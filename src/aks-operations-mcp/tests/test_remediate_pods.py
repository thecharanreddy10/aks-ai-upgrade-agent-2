"""Tests for pod remediation: strategy planning, validation, and owner detection."""

from __future__ import annotations

import pytest

from tools import remediate_pods
from tools.remediate_pods import aks_remediate_pods, _find_owner_reference, _plan_delete_pod, _plan_rollout_restart

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_remediate_pods_rejects_unsafe_namespace(monkeypatch):
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("validation must reject unsafe namespace before any query")))
    with pytest.raises(ValueError, match="namespace"):
        aks_remediate_pods(*CLUSTER_ARGS, "$(id)", "pod-name")


def test_remediate_pods_rejects_unsafe_pod_name(monkeypatch):
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("validation must reject unsafe pod_name before any query")))
    with pytest.raises(ValueError, match="pod"):
        aks_remediate_pods(*CLUSTER_ARGS, "default", "pod; rm -rf /")


def test_remediate_pods_rejects_protected_namespace(monkeypatch):
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("validation must reject protected namespace before any query")))
    with pytest.raises(PermissionError, match="protected"):
        aks_remediate_pods(*CLUSTER_ARGS, "kube-system", "pod-name")


def test_remediate_pods_invalid_strategy(monkeypatch):
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: {"kind": "Pod", "metadata": {"name": "test-pod"}, "spec": {}})
    with pytest.raises(ValueError, match="Unknown strategy"):
        aks_remediate_pods(*CLUSTER_ARGS, "phonebook", "test-pod", strategy="unknown_strategy")


def test_remediate_pods_not_found(monkeypatch):
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: {})
    with pytest.raises(ValueError, match="not found"):
        aks_remediate_pods(*CLUSTER_ARGS, "phonebook", "missing-pod")


def test_find_owner_reference_returns_deployment():
    owner = _find_owner_reference({"metadata": {"ownerReferences": [{"kind": "Deployment", "name": "web", "apiVersion": "apps/v1"}]}})
    assert owner and owner["kind"] == "Deployment" and owner["name"] == "web"


def test_find_owner_reference_returns_statefulset():
    owner = _find_owner_reference({"metadata": {"ownerReferences": [{"kind": "StatefulSet", "name": "db", "apiVersion": "apps/v1"}]}})
    assert owner and owner["kind"] == "StatefulSet" and owner["name"] == "db"


def test_find_owner_reference_skips_non_workload_owners():
    assert _find_owner_reference({"metadata": {"ownerReferences": [{"kind": "Job", "name": "backup", "apiVersion": "batch/v1"}]}}) is None


def test_find_owner_reference_none_when_no_owners():
    assert _find_owner_reference({"metadata": {}}) is None


def test_plan_rollout_restart_generates_restart_command():
    pod = {"metadata": {"name": "web-pod-abc123", "ownerReferences": [{"kind": "Deployment", "name": "web", "apiVersion": "apps/v1"}]}}
    plan = _plan_rollout_restart("phonebook", pod)
    assert plan["owner"]["kind"] == "Deployment"
    assert "kubectl rollout restart deployment web" in plan["steps"][0]["kubectl_command"]
    assert "kubectl rollout status" in plan["steps"][0]["wait_command"]


def test_plan_rollout_restart_statefulset():
    pod = {"metadata": {"ownerReferences": [{"kind": "StatefulSet", "name": "db", "apiVersion": "apps/v1"}]}}
    assert "kubectl rollout restart statefulset db" in _plan_rollout_restart("phonebook", pod)["steps"][0]["kubectl_command"]


def test_plan_rollout_restart_no_owner_returns_error():
    plan = _plan_rollout_restart("phonebook", {"metadata": {}})
    assert "error" in plan and plan["fallback_strategy"] == "delete_pod"


def test_plan_rollout_restart_non_workload_owner_returns_error():
    plan = _plan_rollout_restart("phonebook", {"metadata": {"ownerReferences": [{"kind": "Job", "name": "backup", "apiVersion": "batch/v1"}]}})
    assert "error" in plan and "Job" in plan["error"]


def test_plan_delete_pod_generates_delete_command():
    plan = _plan_delete_pod("phonebook", {"metadata": {"name": "stuck-pod"}})
    assert plan["grace_period_seconds"] == 30
    assert "kubectl delete pod stuck-pod" in plan["steps"][0]["kubectl_command"]
    assert "--grace-period=30" in plan["steps"][0]["kubectl_command"]


def test_plan_delete_pod_includes_force_delete_command():
    plan = _plan_delete_pod("phonebook", {"metadata": {"name": "stuck-pod"}})
    assert "--grace-period=0 --force" in plan["steps"][0]["force_delete_command"]


def test_dry_run_returns_plan_without_execution(monkeypatch):
    pod = {"kind": "Pod", "metadata": {"name": "test-pod", "ownerReferences": [{"kind": "Deployment", "name": "web", "apiVersion": "apps/v1"}]}}
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: pod)
    monkeypatch.setattr(remediate_pods, "run_kubectl_raw", lambda *_a, **_k: "should not run")
    result = aks_remediate_pods(*CLUSTER_ARGS, "phonebook", "test-pod", strategy="rollout_restart", dry_run=True)
    assert result["status"] == "dry_run"
    assert "approval_token" not in result["message"]


def test_write_still_requires_full_check_mode(monkeypatch):
    pod = {"kind": "Pod", "metadata": {"name": "test-pod", "ownerReferences": [{"kind": "Deployment", "name": "web", "apiVersion": "apps/v1"}]}}
    monkeypatch.setattr(remediate_pods, "run_kubectl_json", lambda *_a, **_k: pod)
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    with pytest.raises(PermissionError, match="check_mode"):
        aks_remediate_pods(*CLUSTER_ARGS, "phonebook", "test-pod", strategy="rollout_restart", dry_run=False, check_mode="quick")
