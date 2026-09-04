"""Tests for pod remediation: strategy planning, approval gates, and owner resolution."""

from __future__ import annotations

import pytest

from tools import remediate_pods
from tools.remediate_pods import (
    aks_remediate_pods,
    _find_owner_reference,
    _plan_delete_pod,
    _plan_rollout_restart,
    _resolve_workload_owner,
)

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_remediate_pods_rejects_unsafe_namespace(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject unsafe namespace before any query")

    monkeypatch.setattr(remediate_pods, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError, match="namespace"):
        aks_remediate_pods(*CLUSTER_ARGS, "$(id)", "pod-name")


def test_remediate_pods_rejects_unsafe_pod_name(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject unsafe pod_name before any query")

    monkeypatch.setattr(remediate_pods, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError, match="pod"):
        aks_remediate_pods(*CLUSTER_ARGS, "default", "pod; rm -rf /")


def test_remediate_pods_rejects_protected_namespace(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject protected namespace before any query")

    monkeypatch.setattr(remediate_pods, "run_kubectl_json", _should_not_run)

    with pytest.raises(PermissionError, match="protected"):
        aks_remediate_pods(*CLUSTER_ARGS, "kube-system", "pod-name")


def test_remediate_pods_invalid_strategy(monkeypatch):
    pod = {"kind": "Pod", "metadata": {"name": "test-pod"}, "spec": {}}
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: pod)

    with pytest.raises(ValueError, match="Unknown strategy"):
        aks_remediate_pods(*CLUSTER_ARGS, "phonebook", "test-pod", strategy="unknown_strategy")


def test_remediate_pods_not_found(monkeypatch):
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: {})

    with pytest.raises(ValueError, match="not found"):
        aks_remediate_pods(*CLUSTER_ARGS, "phonebook", "missing-pod")


def test_find_owner_reference_returns_deployment():
    pod = {"metadata": {"name": "web-pod", "ownerReferences": [{"kind": "Deployment", "name": "web", "apiVersion": "apps/v1"}]}}
    owner = _find_owner_reference(pod)
    assert owner is not None
    assert owner["kind"] == "Deployment"
    assert owner["name"] == "web"


def test_find_owner_reference_returns_statefulset():
    pod = {"metadata": {"name": "db-pod-0", "ownerReferences": [{"kind": "StatefulSet", "name": "db", "apiVersion": "apps/v1"}]}}
    owner = _find_owner_reference(pod)
    assert owner is not None
    assert owner["kind"] == "StatefulSet"
    assert owner["name"] == "db"


def test_find_owner_reference_skips_non_workload_owners():
    pod = {"metadata": {"name": "job-pod", "ownerReferences": [{"kind": "Job", "name": "backup", "apiVersion": "batch/v1"}]}}
    assert _find_owner_reference(pod) is None


def test_find_owner_reference_none_when_no_owners():
    assert _find_owner_reference({"metadata": {"name": "standalone-pod"}}) is None


def test_resolve_workload_owner_follows_replicaset_to_deployment(monkeypatch):
    pod = {
        "metadata": {
            "name": "web-pod-abc123",
            "ownerReferences": [{"kind": "ReplicaSet", "name": "web-abc123", "apiVersion": "apps/v1"}],
        }
    }
    replicaset = {
        "kind": "ReplicaSet",
        "metadata": {
            "name": "web-abc123",
            "ownerReferences": [{"kind": "Deployment", "name": "web", "apiVersion": "apps/v1"}],
        },
    }
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: replicaset)

    owner = _resolve_workload_owner(*CLUSTER_ARGS, "phonebook", pod)

    assert owner == replicaset["metadata"]["ownerReferences"][0]


def test_resolve_workload_owner_does_not_query_for_direct_statefulset(monkeypatch):
    pod = {"metadata": {"ownerReferences": [{"kind": "StatefulSet", "name": "db", "apiVersion": "apps/v1"}]}}
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: pytest.fail("unexpected query"))
    assert _resolve_workload_owner(*CLUSTER_ARGS, "phonebook", pod)["name"] == "db"


def test_resolve_workload_owner_rejects_invalid_replicaset_name(monkeypatch):
    pod = {"metadata": {"ownerReferences": [{"kind": "ReplicaSet", "name": "bad;name"}]}}
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: pytest.fail("unexpected query"))
    with pytest.raises(ValueError, match="ReplicaSet"):
        _resolve_workload_owner(*CLUSTER_ARGS, "phonebook", pod)


def test_plan_rollout_restart_generates_restart_command():
    pod = {"metadata": {"name": "web-pod-abc123", "ownerReferences": [{"kind": "Deployment", "name": "web", "apiVersion": "apps/v1"}]}}
    plan = _plan_rollout_restart("phonebook", pod)
    assert plan["strategy"] == "rollout_restart"
    assert plan["owner"]["kind"] == "Deployment"
    assert plan["owner"]["name"] == "web"
    assert len(plan["steps"]) == 1
    assert "kubectl rollout restart deployment web" in plan["steps"][0]["kubectl_command"]
    assert "kubectl rollout status" in plan["steps"][0]["wait_command"]


def test_plan_rollout_restart_statefulset():
    pod = {"metadata": {"name": "db-pod-0", "ownerReferences": [{"kind": "StatefulSet", "name": "db", "apiVersion": "apps/v1"}]}}
    plan = _plan_rollout_restart("phonebook", pod)
    assert plan["owner"]["kind"] == "StatefulSet"
    assert "kubectl rollout restart statefulset db" in plan["steps"][0]["kubectl_command"]


def test_plan_rollout_restart_resolved_replicaset_owner():
    pod = {"metadata": {"name": "web-pod", "ownerReferences": [{"kind": "ReplicaSet", "name": "web-rs"}]}}
    owner = {"kind": "Deployment", "name": "web"}
    plan = _plan_rollout_restart("phonebook", pod, owner_ref=owner)
    assert plan["owner"] == {"kind": "Deployment", "name": "web", "namespace": "phonebook"}


def test_plan_rollout_restart_no_owner_returns_error():
    plan = _plan_rollout_restart("phonebook", {"metadata": {"name": "standalone-pod"}})
    assert "error" in plan
    assert plan["fallback_strategy"] == "delete_pod"


def test_plan_rollout_restart_non_workload_owner_returns_error():
    pod = {"metadata": {"name": "job-pod", "ownerReferences": [{"kind": "Job", "name": "backup", "apiVersion": "batch/v1"}]}}
    plan = _plan_rollout_restart("phonebook", pod)
    assert "error" in plan
    assert "Job" in plan["error"]


def test_plan_delete_pod_generates_delete_command():
    plan = _plan_delete_pod("phonebook", {"metadata": {"name": "stuck-pod"}})
    assert plan["strategy"] == "delete_pod"
    assert plan["grace_period_seconds"] == 30
    assert len(plan["steps"]) == 1
    assert "kubectl delete pod stuck-pod" in plan["steps"][0]["kubectl_command"]
    assert "--grace-period=30" in plan["steps"][0]["kubectl_command"]


def test_plan_delete_pod_includes_force_delete_command():
    plan = _plan_delete_pod("phonebook", {"metadata": {"name": "stuck-pod"}})
    assert "force_delete_command" in plan["steps"][0]
    assert "--grace-period=0 --force" in plan["steps"][0]["force_delete_command"]


def test_dry_run_returns_plan_without_execution(monkeypatch):
    pod = {"kind": "Pod", "metadata": {"name": "test-pod", "ownerReferences": [{"kind": "Deployment", "name": "web", "apiVersion": "apps/v1"}]}}
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: pod)
    monkeypatch.setattr(remediate_pods, "run_kubectl_raw", lambda *_a, **_k: "should not run")
    result = aks_remediate_pods(*CLUSTER_ARGS, "phonebook", "test-pod", strategy="rollout_restart", dry_run=True)
    assert result["status"] == "dry_run"
    assert "plan" in result
    assert result["message"] == "Plan only; no cluster changes. Pass dry_run=False to apply."


def test_approval_gates_required_for_write(monkeypatch):
    pod = {"kind": "Pod", "metadata": {"name": "test-pod", "ownerReferences": [{"kind": "Deployment", "name": "web", "apiVersion": "apps/v1"}]}}
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: pod)
    with pytest.raises(PermissionError, match="check_mode"):
        aks_remediate_pods(*CLUSTER_ARGS, "phonebook", "test-pod", strategy="rollout_restart", dry_run=False, check_mode="quick")
