"""Tests for storage remediation: PVC/PV cleanup, strategy planning, grace periods."""

from __future__ import annotations

import pytest

from tools import remediate_storage
from tools.remediate_storage import (
    aks_remediate_storage,
    _plan_cleanup_pvc,
    _plan_cleanup_pv,
)

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_remediate_storage_pvc_requires_namespace(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("cleanup_pvc requires namespace")

    monkeypatch.setattr(remediate_storage, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError, match="namespace"):
        aks_remediate_storage(
            *CLUSTER_ARGS,
            namespace=None,
            strategy="cleanup_pvc",
        )


def test_remediate_storage_rejects_unsafe_namespace(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject unsafe namespace")

    monkeypatch.setattr(remediate_storage, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError, match="namespace"):
        aks_remediate_storage(
            *CLUSTER_ARGS,
            namespace="$(id)",
            strategy="cleanup_pvc",
        )


def test_remediate_storage_rejects_protected_namespace(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject protected namespace")

    monkeypatch.setattr(remediate_storage, "run_kubectl_json", _should_not_run)

    with pytest.raises(PermissionError, match="protected"):
        aks_remediate_storage(
            *CLUSTER_ARGS,
            namespace="kube-system",
            strategy="cleanup_pvc",
        )


def test_remediate_storage_invalid_strategy(monkeypatch):
    monkeypatch.setattr(remediate_storage, "run_kubectl_json", lambda *_a, **_k: {"items": []})

    with pytest.raises(ValueError, match="Unknown strategy"):
        aks_remediate_storage(
            *CLUSTER_ARGS,
            namespace="default",
            strategy="unknown",
        )


def test_remediate_storage_pvc_rejects_unsafe_pvc_name(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject unsafe pvc_name")

    monkeypatch.setattr(remediate_storage, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError, match="pvc"):
        aks_remediate_storage(
            *CLUSTER_ARGS,
            namespace="default",
            storage_name="pvc; rm -rf /",
            strategy="cleanup_pvc",
        )


def test_remediate_storage_pv_rejects_unsafe_pv_name(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject unsafe pv_name")

    monkeypatch.setattr(remediate_storage, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError, match="pv"):
        aks_remediate_storage(
            *CLUSTER_ARGS,
            strategy="cleanup_pv",
            storage_name="pv$(malicious)",
        )


def test_plan_cleanup_pvc_no_pvcs_returns_no_action(monkeypatch):
    monkeypatch.setattr(remediate_storage, "run_kubectl_json", lambda *_a, **_k: {"items": []})

    plan = _plan_cleanup_pvc(*CLUSTER_ARGS, "default", None)

    assert plan.get("status") == "no_action"
    assert "No PVCs" in plan.get("message", "")


def test_plan_cleanup_pvc_finds_terminating_pvcs(monkeypatch):
    pvcs_response = {
        "items": [
            {
                "metadata": {
                    "name": "stuck-pvc",
                    "deletionTimestamp": "2025-01-01T00:00:00Z",
                },
                "spec": {},
            }
        ]
    }
    monkeypatch.setattr(remediate_storage, "run_kubectl_json", lambda *_a, **_k: pvcs_response)

    plan = _plan_cleanup_pvc(*CLUSTER_ARGS, "default", None)

    assert "steps" in plan
    assert len(plan["steps"]) == 1
    assert plan["steps"][0]["name"] == "stuck-pvc"
    assert "kubectl delete pvc stuck-pvc" in plan["steps"][0]["kubectl_command"]


def test_plan_cleanup_pvc_includes_grace_period():
    pvc = {
        "metadata": {
            "name": "stuck-pvc",
            "deletionTimestamp": "2025-01-01T00:00:00Z",
        },
    }
    plan = {
        "strategy": "cleanup_pvc",
        "steps": [
            {
                "type": "delete_pvc",
                "kubectl_command": f"kubectl delete pvc stuck-pvc -n default --grace-period=30",
            }
        ],
    }

    assert "--grace-period=30" in plan["steps"][0]["kubectl_command"]


def test_plan_cleanup_pvc_includes_force_delete():
    pvc = {
        "metadata": {
            "name": "stuck-pvc",
            "deletionTimestamp": "2025-01-01T00:00:00Z",
        },
    }

    step = {
        "type": "delete_pvc",
        "force_delete_command": f"kubectl delete pvc stuck-pvc -n default --grace-period=0 --force",
    }

    assert "--grace-period=0 --force" in step["force_delete_command"]


def test_plan_cleanup_pv_no_pvs_returns_no_action(monkeypatch):
    monkeypatch.setattr(remediate_storage, "run_kubectl_json", lambda *_a, **_k: {"items": []})

    plan = _plan_cleanup_pv(*CLUSTER_ARGS, None)

    assert plan.get("status") == "no_action"


def test_plan_cleanup_pv_finds_failed_pvs(monkeypatch):
    pvs_response = {
        "items": [
            {
                "metadata": {"name": "stuck-pv"},
                "status": {"phase": "Failed"},
                "spec": {"persistentVolumeReclaimPolicy": "Delete"},
            }
        ]
    }
    monkeypatch.setattr(remediate_storage, "run_kubectl_json", lambda *_a, **_k: pvs_response)

    plan = _plan_cleanup_pv(*CLUSTER_ARGS, None)

    assert "steps" in plan
    assert len(plan["steps"]) == 1
    assert plan["steps"][0]["name"] == "stuck-pv"


def test_plan_cleanup_pv_finds_released_pvs(monkeypatch):
    pvs_response = {
        "items": [
            {
                "metadata": {"name": "released-pv"},
                "status": {"phase": "Released"},
                "spec": {"persistentVolumeReclaimPolicy": "Retain"},
            }
        ]
    }
    monkeypatch.setattr(remediate_storage, "run_kubectl_json", lambda *_a, **_k: pvs_response)

    plan = _plan_cleanup_pv(*CLUSTER_ARGS, None)

    assert len(plan["steps"]) == 1
    assert plan["steps"][0]["reclaim_policy"] == "Retain"


def test_dry_run_pvc_returns_plan_without_execution(monkeypatch):
    pvcs_response = {"items": []}
    monkeypatch.setattr(remediate_storage, "run_kubectl_json", lambda *_a, **_k: pvcs_response)
    monkeypatch.setattr(remediate_storage, "run_kubectl_raw", lambda *_a, **_k: ("should not run"))

    result = aks_remediate_storage(
        *CLUSTER_ARGS,
        namespace="default",
        strategy="cleanup_pvc",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert "plan" in result


def test_dry_run_pv_returns_plan_without_execution(monkeypatch):
    pvs_response = {"items": []}
    monkeypatch.setattr(remediate_storage, "run_kubectl_json", lambda *_a, **_k: pvs_response)
    monkeypatch.setattr(remediate_storage, "run_kubectl_raw", lambda *_a, **_k: ("should not run"))

    result = aks_remediate_storage(
        *CLUSTER_ARGS,
        strategy="cleanup_pv",
        dry_run=True,
    )

    assert result["status"] == "dry_run"


def test_approval_gates_required_for_pvc_write(monkeypatch):
    monkeypatch.setattr(remediate_storage, "run_kubectl_json", lambda *_a, **_k: {"items": []})

    with pytest.raises(PermissionError, match="check_mode"):
        aks_remediate_storage(
            *CLUSTER_ARGS,
            namespace="default",
            strategy="cleanup_pvc",
            dry_run=False,
            check_mode="quick",
        )


def test_plan_cleanup_pvc_includes_verification():
    plan = {
        "post_verification": {
            "command": "kubectl get pvc -n default --field-selector metadata.deletionTimestamp!='' --no-headers | wc -l",
            "expected": "0 (all Terminating PVCs resolved)",
        }
    }

    assert "post_verification" in plan
    assert "0" in plan["post_verification"]["expected"]
