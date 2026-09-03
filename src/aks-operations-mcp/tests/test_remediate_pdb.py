"""Tests for PDB remediation: strategy planning, approval gates, and rollback logic."""

from __future__ import annotations

import pytest

from tools import remediate_pdb
from tools.remediate_pdb import (
    aks_remediate_pdb,
    aks_rollback_pdb_remediation,
    _build_label_selector,
    _plan_relax_pdb,
    _plan_scale_workload,
)

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_remediate_pdb_rejects_unsafe_namespace(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject unsafe namespace before any query")

    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError, match="namespace"):
        aks_remediate_pdb(*CLUSTER_ARGS, "$(id)", "pdb-name")


def test_remediate_pdb_rejects_unsafe_pdb_name(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject unsafe pdb_name before any query")

    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError, match="pdb"):
        aks_remediate_pdb(*CLUSTER_ARGS, "default", "pdb; rm -rf /")


def test_remediate_pdb_rejects_protected_namespace(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject protected namespace before any query")

    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", _should_not_run)

    with pytest.raises(PermissionError, match="protected"):
        aks_remediate_pdb(*CLUSTER_ARGS, "kube-system", "pdb-name")


def test_remediate_pdb_invalid_strategy(monkeypatch):
    pdb = {
        "kind": "PodDisruptionBudget",
        "metadata": {"name": "test-pdb"},
        "spec": {},
    }
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: pdb)

    with pytest.raises(ValueError, match="Unknown strategy"):
        aks_remediate_pdb(
            *CLUSTER_ARGS,
            "phonebook",
            "test-pdb",
            strategy="unknown_strategy",
        )


def test_remediate_pdb_not_found(monkeypatch):
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: {})

    with pytest.raises(ValueError, match="not found"):
        aks_remediate_pdb(*CLUSTER_ARGS, "phonebook", "missing-pdb")


def test_build_label_selector_from_match_labels():
    selector = {"matchLabels": {"app": "web", "tier": "frontend"}}
    result = _build_label_selector(selector)
    assert result in ("app=web,tier=frontend", "tier=frontend,app=web")


def test_build_label_selector_empty_returns_none():
    selector = {"matchLabels": {}}
    assert _build_label_selector(selector) is None


def test_plan_scale_workload_generates_deployment_scale_commands(monkeypatch):
    pdb = {
        "kind": "PodDisruptionBudget",
        "metadata": {"name": "web-pdb"},
        "spec": {"selector": {"matchLabels": {"app": "web"}}},
    }
    deployments = {
        "items": [
            {
                "metadata": {"name": "web-1"},
                "spec": {"replicas": 2},
            },
            {
                "metadata": {"name": "web-2"},
                "spec": {"replicas": 1},
            },
        ]
    }
    statefulsets = {"items": []}

    call_count = [0]

    def mock_kubectl(*_a, **_k):
        call_count[0] += 1
        if call_count[0] == 1:  # First call for deployments
            return deployments
        return statefulsets  # Second call for statefulsets

    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", mock_kubectl)

    plan = _plan_scale_workload(*CLUSTER_ARGS, "phonebook", pdb)

    assert "steps" in plan
    assert len(plan["steps"]) == 2
    assert plan["steps"][0]["kind"] == "Deployment"
    assert plan["steps"][0]["current_replicas"] == 2
    assert plan["steps"][0]["new_replicas"] == 3
    assert "kubectl scale deployment web-1" in plan["steps"][0]["kubectl_command"]


def test_plan_scale_workload_no_matches_returns_error(monkeypatch):
    pdb = {
        "kind": "PodDisruptionBudget",
        "metadata": {"name": "web-pdb"},
        "spec": {"selector": {"matchLabels": {"app": "web"}}},
    }
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: {"items": []})

    plan = _plan_scale_workload(*CLUSTER_ARGS, "phonebook", pdb)

    assert "error" in plan
    assert plan["fallback_strategy"] == "relax_pdb"


def test_plan_relax_pdb_generates_patch_command():
    pdb = {
        "metadata": {"name": "web-pdb"},
        "spec": {"minAvailable": 2, "maxUnavailable": None},
    }
    plan = _plan_relax_pdb("phonebook", pdb)

    assert plan["strategy"] == "relax_pdb"
    assert plan["original_spec"]["minAvailable"] == 2
    assert plan["original_spec"]["maxUnavailable"] is None
    assert plan["patch"]["spec"]["minAvailable"] is None
    assert plan["patch"]["spec"]["maxUnavailable"] == 1
    assert len(plan["steps"]) == 1
    assert "patch pdb web-pdb" in plan["steps"][0]["patch_command"]


def test_restore_pdb_command_has_valid_json_payload():
    cmd = remediate_pdb._restore_pdb_command(
        "web-pdb",
        "phonebook",
        original_min_available=2,
        original_max_unavailable=None,
    )

    payload = cmd.split("-p ", 1)[1].strip().strip("'")
    assert payload == '{"spec":{"minAvailable":2,"maxUnavailable":null}}'

    json_payload = payload.replace("'", '"')
    payload_obj = __import__("json").loads(json_payload)
    assert payload_obj == {"spec": {"minAvailable": 2, "maxUnavailable": None}}


def test_restore_pdb_command_preserves_percentage_values():
    cmd = remediate_pdb._restore_pdb_command(
        "web-pdb",
        "phonebook",
        original_min_available="80%",
        original_max_unavailable=None,
    )

    payload = cmd.split("-p ", 1)[1].strip().strip("'")
    payload_obj = __import__("json").loads(payload)
    assert payload_obj == {"spec": {"minAvailable": "80%", "maxUnavailable": None}}


def test_dry_run_returns_plan_without_execution(monkeypatch):
    pdb = {
        "kind": "PodDisruptionBudget",
        "metadata": {"name": "test-pdb"},
        "spec": {"minAvailable": 1},
    }
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: pdb)
    monkeypatch.setattr(remediate_pdb, "run_kubectl_raw", lambda *_a, **_k: ("should not run"))

    result = aks_remediate_pdb(
        *CLUSTER_ARGS,
        "phonebook",
        "test-pdb",
        strategy="relax_pdb",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert "plan" in result
    assert result["message"] == "Plan only; no cluster changes. Pass dry_run=False + approval_token to apply."


def test_approval_gates_required_for_write(monkeypatch):
    pdb = {
        "kind": "PodDisruptionBudget",
        "metadata": {"name": "test-pdb"},
        "spec": {"minAvailable": 1},
    }
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: pdb)

    with pytest.raises(PermissionError, match="check_mode"):
        aks_remediate_pdb(
            *CLUSTER_ARGS,
            "phonebook",
            "test-pdb",
            strategy="relax_pdb",
            dry_run=False,
            check_mode="quick",
        )


def test_relax_pdb_preserves_original_spec():
    pdb = {
        "metadata": {"name": "exact-pdb"},
        "spec": {"minAvailable": 3, "maxUnavailable": None},
    }
    plan = _plan_relax_pdb("phonebook", pdb)

    # Verify original is preserved exactly
    assert plan["original_spec"]["minAvailable"] == 3
    assert plan["original_spec"]["maxUnavailable"] is None


def test_rollback_relax_pdb_dry_run_builds_restore_step(monkeypatch):
    pdb = {
        "kind": "PodDisruptionBudget",
        "metadata": {"name": "web-pdb"},
        "spec": {"minAvailable": None, "maxUnavailable": 1},
    }
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: pdb)
    monkeypatch.setattr(
        remediate_pdb,
        "run_kubectl_raw",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("dry run must not write")),
    )

    result = aks_rollback_pdb_remediation(
        *CLUSTER_ARGS,
        "phonebook",
        "web-pdb",
        strategy="relax_pdb",
        original_min_available=2,
        original_max_unavailable=None,
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert result["steps"][0]["kind"] == "PodDisruptionBudget"
    assert result["steps"][0]["rollback_command"] == (
        "kubectl patch pdb web-pdb -n phonebook --type=merge -p "
        "'{\"spec\":{\"minAvailable\":2,\"maxUnavailable\":null}}'"
    )


def test_rollback_relax_pdb_executes_restore(monkeypatch):
    pdb = {
        "kind": "PodDisruptionBudget",
        "metadata": {"name": "web-pdb"},
        "spec": {"minAvailable": None, "maxUnavailable": 1},
    }
    calls = []
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: pdb)
    monkeypatch.setattr(remediate_pdb, "require_remediation_approval", lambda *_a, **_k: None)
    monkeypatch.setattr(remediate_pdb, "run_kubectl_raw", lambda *args, **_k: calls.append(args) or "patched")

    result = aks_rollback_pdb_remediation(
        *CLUSTER_ARGS,
        "phonebook",
        "web-pdb",
        strategy="relax_pdb",
        original_min_available=2,
        original_max_unavailable=None,
        dry_run=False,
    )

    assert result["status"] == "rolled_back"
    assert len(calls) == 1
    assert calls[0][-1] == (
        "kubectl patch pdb web-pdb -n phonebook --type=merge -p "
        "'{\"spec\":{\"minAvailable\":2,\"maxUnavailable\":null}}'"
    )


def test_rollback_scale_workload_executes_restore(monkeypatch):
    pdb = {
        "kind": "PodDisruptionBudget",
        "metadata": {"name": "web-pdb"},
        "spec": {"minAvailable": None, "maxUnavailable": 1},
    }
    calls = []
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: pdb)
    monkeypatch.setattr(remediate_pdb, "require_remediation_approval", lambda *_a, **_k: None)
    monkeypatch.setattr(remediate_pdb, "run_kubectl_raw", lambda *args, **_k: calls.append(args) or "scaled")

    result = aks_rollback_pdb_remediation(
        *CLUSTER_ARGS,
        "phonebook",
        "web-pdb",
        strategy="scale_workload_up",
        workload_kind="Deployment",
        workload_name="webserver-deploy",
        original_replicas=4,
        dry_run=False,
    )

    assert result["status"] == "rolled_back"
    assert len(calls) == 1
    assert calls[0][-1] == (
        "kubectl scale deployment webserver-deploy -n phonebook --replicas=4"
    )
