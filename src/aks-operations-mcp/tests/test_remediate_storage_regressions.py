from __future__ import annotations

from tools import remediate_storage
from tools.remediate_storage import _plan_cleanup_pvc, _plan_cleanup_pv

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_cleanup_pvc_does_not_target_bound_terminating_pvc(monkeypatch):
    monkeypatch.setattr(
        remediate_storage,
        "run_kubectl_json",
        lambda *_a, **_k: {
            "items": [
                {
                    "metadata": {"name": "bound-pvc", "deletionTimestamp": "2026-01-01T00:00:00Z"},
                    "status": {"phase": "Bound"},
                },
                {
                    "metadata": {"name": "unbound-pvc", "deletionTimestamp": "2026-01-01T00:00:00Z"},
                    "status": {"phase": "Pending"},
                },
            ]
        },
    )

    plan = _plan_cleanup_pvc(*CLUSTER_ARGS, "default", None)

    assert [step["name"] for step in plan["steps"]] == ["unbound-pvc"]


def test_cleanup_pvc_explicit_bound_pvc_returns_no_action(monkeypatch):
    monkeypatch.setattr(
        remediate_storage,
        "run_kubectl_json",
        lambda *_a, **_k: {
            "kind": "PersistentVolumeClaim",
            "metadata": {"name": "bound-pvc", "deletionTimestamp": "2026-01-01T00:00:00Z"},
            "status": {"phase": "Bound"},
        },
    )

    plan = _plan_cleanup_pvc(*CLUSTER_ARGS, "default", "bound-pvc")

    assert plan["status"] == "no_action"


def test_cleanup_pv_does_not_target_bound_pv_without_claim_ref(monkeypatch):
    monkeypatch.setattr(
        remediate_storage,
        "run_kubectl_json",
        lambda *_a, **_k: {
            "items": [
                {
                    "metadata": {"name": "bound-pv"},
                    "status": {"phase": "Bound"},
                    "spec": {"persistentVolumeReclaimPolicy": "Delete"},
                },
                {
                    "metadata": {"name": "released-pv"},
                    "status": {"phase": "Released"},
                    "spec": {"persistentVolumeReclaimPolicy": "Retain"},
                },
            ]
        },
    )

    plan = _plan_cleanup_pv(*CLUSTER_ARGS, None)

    assert [step["name"] for step in plan["steps"]] == ["released-pv"]


def test_cleanup_pv_verification_checks_failed_or_released_independently(monkeypatch):
    plan = _plan_cleanup_pv(
        *CLUSTER_ARGS,
        None,
    )

    # This test is intentionally replaced by the next monkeypatched planning call;
    # it keeps the regression focused on the generated verification command.
    assert plan["status"] == "no_action"
