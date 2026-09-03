"""Tests for PDB remediation: strategy planning, write gates, and rollback logic."""

from __future__ import annotations

import pytest

from tools import remediate_pdb
from tools.remediate_pdb import aks_remediate_pdb, _build_label_selector, _plan_relax_pdb, _plan_scale_workload

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_remediate_pdb_rejects_unsafe_namespace(monkeypatch):
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("validation must reject unsafe namespace before any query")))
    with pytest.raises(ValueError, match="namespace"):
        aks_remediate_pdb(*CLUSTER_ARGS, "$(id)", "pdb-name")


def test_remediate_pdb_rejects_unsafe_pdb_name(monkeypatch):
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("validation must reject unsafe pdb_name before any query")))
    with pytest.raises(ValueError, match="pdb"):
        aks_remediate_pdb(*CLUSTER_ARGS, "default", "pdb; rm -rf /")


def test_remediate_pdb_rejects_protected_namespace(monkeypatch):
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("validation must reject protected namespace before any query")))
    with pytest.raises(PermissionError, match="protected"):
        aks_remediate_pdb(*CLUSTER_ARGS, "kube-system", "pdb-name")


def test_remediate_pdb_invalid_strategy(monkeypatch):
    pdb = {"kind": "PodDisruptionBudget", "metadata": {"name": "test-pdb"}, "spec": {}}
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: pdb)
    with pytest.raises(ValueError, match="Unknown strategy"):
        aks_remediate_pdb(*CLUSTER_ARGS, "phonebook", "test-pdb", strategy="unknown_strategy")


def test_remediate_pdb_not_found(monkeypatch):
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: {})
    with pytest.raises(ValueError, match="not found"):
        aks_remediate_pdb(*CLUSTER_ARGS, "phonebook", "missing-pdb")


def test_build_label_selector_from_match_labels():
    result = _build_label_selector({"matchLabels": {"app": "web", "tier": "frontend"}})
    assert result in ("app=web,tier=frontend", "tier=frontend,app=web")


def test_build_label_selector_empty_returns_none():
    assert _build_label_selector({"matchLabels": {}}) is None


def test_plan_scale_workload_generates_deployment_scale_commands(monkeypatch):
    pdb = {"kind": "PodDisruptionBudget", "metadata": {"name": "web-pdb"}, "spec": {"selector": {"matchLabels": {"app": "web"}}}}
    deployments = {"items": [{"metadata": {"name": "web-1"}, "spec": {"replicas": 2}}, {"metadata": {"name": "web-2"}, "spec": {"replicas": 1}}]}
    statefulsets = {"items": []}
    call_count = [0]

    def mock_kubectl(*_a, **_k):
        call_count[0] += 1
        return deployments if call_count[0] == 1 else statefulsets

    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", mock_kubectl)
    plan = _plan_scale_workload(*CLUSTER_ARGS, "phonebook", pdb)
    assert len(plan["steps"]) == 2
    assert plan["steps"][0]["kind"] == "Deployment"
    assert plan["steps"][0]["current_replicas"] == 2
    assert plan["steps"][0]["new_replicas"] == 3


def test_plan_scale_workload_no_matches_returns_error(monkeypatch):
    pdb = {"kind": "PodDisruptionBudget", "metadata": {"name": "web-pdb"}, "spec": {"selector": {"matchLabels": {"app": "web"}}}}
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: {"items": []})
    plan = _plan_scale_workload(*CLUSTER_ARGS, "phonebook", pdb)
    assert "error" in plan
    assert plan["fallback_strategy"] == "relax_pdb"


def test_plan_relax_pdb_generates_patch_command():
    pdb = {"metadata": {"name": "web-pdb"}, "spec": {"minAvailable": 2, "maxUnavailable": None}}
    plan = _plan_relax_pdb("phonebook", pdb)
    assert plan["original_spec"] == {"minAvailable": 2, "maxUnavailable": None}
    assert plan["patch"]["spec"] == {"minAvailable": None, "maxUnavailable": 1}
    assert "patch pdb web-pdb" in plan["steps"][0]["patch_command"]


def test_restore_pdb_command_has_valid_json_payload():
    cmd = remediate_pdb._restore_pdb_command("web-pdb", "phonebook", 2, None)
    payload = cmd.split("-p ", 1)[1].strip().strip("'")
    assert payload == '{"spec":{"minAvailable":2,"maxUnavailable":null}}'
    assert __import__("json").loads(payload) == {"spec": {"minAvailable": 2, "maxUnavailable": None}}


def test_dry_run_returns_plan_without_execution(monkeypatch):
    pdb = {"kind": "PodDisruptionBudget", "metadata": {"name": "test-pdb"}, "spec": {"minAvailable": 1}}
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: pdb)
    monkeypatch.setattr(remediate_pdb, "run_kubectl_raw", lambda *_a, **_k: "should not run")
    result = aks_remediate_pdb(*CLUSTER_ARGS, "phonebook", "test-pdb", strategy="relax_pdb", dry_run=True)
    assert result["status"] == "dry_run"
    assert "approval_token" not in result["message"]


def test_write_still_requires_full_check_mode(monkeypatch):
    pdb = {"kind": "PodDisruptionBudget", "metadata": {"name": "test-pdb"}, "spec": {"minAvailable": 1}}
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: pdb)
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    with pytest.raises(PermissionError, match="check_mode"):
        aks_remediate_pdb(*CLUSTER_ARGS, "phonebook", "test-pdb", strategy="relax_pdb", dry_run=False, check_mode="quick")


def test_write_does_not_accept_approval_token_parameter(monkeypatch):
    pdb = {"kind": "PodDisruptionBudget", "metadata": {"name": "test-pdb"}, "spec": {"minAvailable": 1}}
    monkeypatch.setattr(remediate_pdb, "run_kubectl_json", lambda *_a, **_k: pdb)
    with pytest.raises(TypeError, match="approval_token"):
        aks_remediate_pdb(*CLUSTER_ARGS, "phonebook", "test-pdb", approval_token="anything")


def test_relax_pdb_preserves_original_spec():
    plan = _plan_relax_pdb("phonebook", {"metadata": {"name": "exact-pdb"}, "spec": {"minAvailable": 3, "maxUnavailable": None}})
    assert plan["original_spec"] == {"minAvailable": 3, "maxUnavailable": None}
