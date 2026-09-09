"""Focused tests for the read-only Phase 1 upgrade-preparation planner."""

from __future__ import annotations

import inspect
from types import SimpleNamespace

from tools import discovery, upgrade
from tools.registry import ALL_TOOLS, build_input_schema


CLUSTER_ARGS = ("sub-id", "rg", "cluster")
TARGET = "1.30.1"


def _upgrades(control_plane="1.29.3", pools=None, control_upgrades=None, pool_upgrades=None, pool_evidence=None, errors=None):
    pools = pools or [{"name": "systempool", "orchestrator_version": "1.29.3"}]
    return {
        "lookup_mode": "upgrade-profile",
        "current_control_plane_version": control_plane,
        "current_node_pools": pools,
        "control_plane_upgrades": control_upgrades if control_upgrades is not None else [{"kubernetes_version": TARGET}],
        "node_pool_upgrades": pool_upgrades if pool_upgrades is not None else {pool["name"]: [{"kubernetes_version": TARGET}] for pool in pools},
        "node_pool_upgrade_profile_evidence": pool_evidence if pool_evidence is not None else {
            pool["name"]: {"profile_available": True, "upgrades_field_present": True, "upgrade_versions": [TARGET], "error": None}
            for pool in pools
        },
        "upgrade_profile_errors": errors or [],
    }


def _ready():
    return {"readiness": {"is_ready": True, "blockers": [], "warnings": []}}


def _plan(monkeypatch, upgrades_payload=None, readiness=None, **kwargs):
    monkeypatch.setattr(upgrade, "aks_get_available_upgrades", lambda *_a, **_k: upgrades_payload or _upgrades())
    monkeypatch.setattr(upgrade, "aks_validate_upgrade_readiness", lambda *_a, **_k: readiness or _ready())
    return upgrade.aks_plan_upgrade_preparation(*CLUSTER_ARGS, TARGET, **kwargs)


def test_valid_target_is_ready_for_confirmation(monkeypatch):
    result = _plan(monkeypatch)
    assert result["status"] == "ready_for_confirmation"
    assert result["confirmation"]["status"] == "awaiting_explicit_user_confirmation"


def test_discovery_surfaces_control_plane_versions_and_missing_pool_upgrades(monkeypatch):
    cluster = SimpleNamespace(kubernetes_version="1.29.3")
    pool = SimpleNamespace(name="systempool", orchestrator_version="1.29.3", node_image_version="image")
    control_profile = SimpleNamespace(
        control_plane_profile=SimpleNamespace(upgrades=[SimpleNamespace(kubernetes_version=TARGET, is_preview=False)])
    )
    pool_profile = SimpleNamespace(upgrades=None)
    client = SimpleNamespace(
        managed_clusters=SimpleNamespace(
            get=lambda *_args: cluster,
            get_upgrade_profile=lambda *_args: control_profile,
        ),
        agent_pools=SimpleNamespace(
            list=lambda *_args: [pool],
            get_upgrade_profile=lambda *_args: pool_profile,
        ),
    )
    monkeypatch.setattr(discovery, "get_container_service_client", lambda *_args: client)

    result = discovery.aks_get_available_upgrades(*CLUSTER_ARGS, include_upgrade_profiles=True)

    assert result["control_plane_upgrades"] == [{"kubernetes_version": TARGET, "is_preview": False}]
    assert result["node_pool_upgrade_profile_evidence"]["systempool"] == {
        "profile_available": True,
        "upgrades_field_present": False,
        "upgrade_versions": [],
        "error": None,
    }


def test_invalid_target_is_blocked_without_reads(monkeypatch):
    monkeypatch.setattr(upgrade, "aks_get_available_upgrades", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError()))
    result = upgrade.aks_plan_upgrade_preparation(*CLUSTER_ARGS, "not-a-version")
    assert result["status"] == "blocked"
    assert result["target_validation"]["is_syntactically_valid"] is False


def test_target_unavailable_from_control_plane_profile(monkeypatch):
    result = _plan(monkeypatch, _upgrades(control_upgrades=[]))
    assert result["status"] == "blocked"
    assert "control-plane" in result["blockers"][0]


def test_node_pool_profile_without_upgrades_is_insufficient_evidence(monkeypatch):
    evidence = {"systempool": {"profile_available": True, "upgrades_field_present": False, "upgrade_versions": [], "error": None}}
    result = _plan(monkeypatch, _upgrades(pool_upgrades={"systempool": []}, pool_evidence=evidence))
    assert result["status"] == "ready_for_control_plane_only"
    assert result["upgrade_scope"]["node_pools"][0]["path_status"] == "INSUFFICIENT_EVIDENCE"
    assert "node_pool_upgrade_profile_insufficient" in result["blocker_categories"]
    assert all(step["operation"] != "upgrade_node_pool" for step in result["sequence"])


def test_control_plane_only_state_requires_explicit_confirmation(monkeypatch):
    evidence = {"systempool": {"profile_available": True, "upgrades_field_present": False, "upgrade_versions": [], "error": None}}
    result = _plan(monkeypatch, _upgrades(pool_upgrades={"systempool": []}, pool_evidence=evidence))

    assert result["confirmation"]["required"] is True
    assert result["confirmation"]["status"] == "awaiting_explicit_user_confirmation"
    assert result["confirmation"]["scope"] == "control_plane_only"
    assert "re-check node-pool upgrade profiles" in result["confirmation"]["next_action"]
    assert any("only a control-plane-first step" in warning for warning in result["warnings"])


def test_missing_node_pool_profile_operation_is_insufficient_evidence(monkeypatch):
    evidence = {"systempool": {"profile_available": False, "upgrades_field_present": False, "upgrade_versions": [], "error": "profile API unavailable"}}
    result = _plan(monkeypatch, _upgrades(pool_upgrades={"systempool": []}, pool_evidence=evidence))
    assert result["upgrade_scope"]["node_pools"][0]["path_status"] == "INSUFFICIENT_EVIDENCE"


def test_node_pool_target_explicitly_supported(monkeypatch):
    result = _plan(monkeypatch)
    assert result["upgrade_scope"]["node_pools"][0]["path_status"] == "SUPPORTED"


def test_node_pool_target_explicitly_unsupported(monkeypatch):
    evidence = {"systempool": {"profile_available": True, "upgrades_field_present": True, "upgrade_versions": ["1.30.0"], "error": None}}
    result = _plan(monkeypatch, _upgrades(pool_upgrades={"systempool": [{"kubernetes_version": "1.30.0"}]}, pool_evidence=evidence))
    assert result["status"] == "blocked"
    assert result["upgrade_scope"]["node_pools"][0]["path_status"] == "UNSUPPORTED"
    assert "node_pool_upgrade_path_unsupported" in result["blocker_categories"]


def test_insufficient_evidence_with_readiness_blocker_remains_blocked(monkeypatch):
    evidence = {"systempool": {"profile_available": True, "upgrades_field_present": False, "upgrade_versions": [], "error": None}}
    readiness = {"readiness": {"is_ready": False, "blockers": ["PDB blocked"], "warnings": []}}
    result = _plan(
        monkeypatch,
        _upgrades(pool_upgrades={"systempool": []}, pool_evidence=evidence),
        readiness=readiness,
    )

    assert result["status"] == "blocked"
    assert result["confirmation"]["required"] is False


def test_current_control_plane_at_target_is_excluded(monkeypatch):
    result = _plan(monkeypatch, _upgrades(control_plane=TARGET))
    assert result["upgrade_scope"]["control_plane"]["included"] is False
    assert result["sequence"][0]["operation"] == "upgrade_node_pool"


def test_mixed_pool_versions_scope_and_exclusion(monkeypatch):
    pools = [
        {"name": "systempool", "orchestrator_version": "1.29.3"},
        {"name": "userpool", "orchestrator_version": TARGET},
    ]
    result = _plan(monkeypatch, _upgrades(pools=pools))
    assert [pool["name"] for pool in result["upgrade_scope"]["node_pools"]] == ["systempool"]
    assert result["upgrade_scope"]["excluded_node_pools"] == ["userpool"]


def test_sequence_is_control_plane_first(monkeypatch):
    result = _plan(monkeypatch)
    assert [step["operation"] for step in result["sequence"]] == ["upgrade_control_plane", "upgrade_node_pool"]


def test_readiness_blocker_blocks_plan(monkeypatch):
    result = _plan(monkeypatch, readiness={"readiness": {"is_ready": False, "blockers": ["PDB blocked"], "warnings": []}})
    assert result["status"] == "blocked"
    assert result["blockers"] == ["PDB blocked"]


def test_maintenance_window_failure_blocks_plan(monkeypatch):
    readiness = {"readiness": {"is_ready": False, "blockers": ["Current UTC time is outside the configured maintenance window."], "warnings": []}}
    result = _plan(monkeypatch, readiness=readiness, maintenance_window_start_utc="00:00", maintenance_window_end_utc="00:01")
    assert result["status"] == "blocked"


def test_already_at_target(monkeypatch):
    result = _plan(monkeypatch, _upgrades(control_plane=TARGET, pools=[{"name": "pool", "orchestrator_version": TARGET}]))
    assert result["status"] == "already_at_target"
    assert result["sequence"] == []


def test_planner_does_not_invoke_optional_validations(monkeypatch):
    for name in ("aks_check_single_replica_services", "aks_check_operator_health", "aks_check_node_pool_surge", "aks_check_priority_class"):
        monkeypatch.setattr(upgrade, name, lambda *_a, **_k: (_ for _ in ()).throw(AssertionError()), raising=False)
    assert _plan(monkeypatch)["status"] == "ready_for_confirmation"


def test_planner_has_no_approval_or_confirmation_parameter():
    parameters = inspect.signature(upgrade.aks_plan_upgrade_preparation).parameters
    schema = build_input_schema(upgrade.aks_plan_upgrade_preparation)
    assert "approval_token" not in parameters and "confirm_upgrade" not in parameters
    assert "approval_token" not in schema["properties"] and "confirm_upgrade" not in schema["properties"]


# Regression tests for is_available semantics (issue: inconsistency with authoritative ARM data)
# See: https://github.com/microsoft/aks-ai-upgrade-agent/issues/xxx
# The planner's is_available must reflect whether the authoritative ARM profile contains the target,
# not whether the FULL cluster can be upgraded.


def test_is_available_true_when_arm_profile_contains_target_despite_insufficient_pool_evidence(monkeypatch):
    """Regression: ARM profile contains target + node-pool evidence insufficient → is_available=true."""
    # Current: 1.29.3, Target: 1.30.1
    # Control plane can upgrade (target in ARM profile)
    # Node pool has insufficient evidence (missing upgrades field)
    evidence = {"systempool": {"profile_available": True, "upgrades_field_present": False, "upgrade_versions": [], "error": None}}
    result = _plan(
        monkeypatch,
        _upgrades(
            control_upgrades=[{"kubernetes_version": TARGET}],
            pool_upgrades={"systempool": []},
            pool_evidence=evidence,
        ),
    )
    assert result["status"] == "ready_for_control_plane_only"
    assert result["target_validation"]["is_available"] is True  # ← KEY: ARM profile contains target
    assert result["target_validation"]["control_plane_path_supported"] is True
    assert result["target_validation"]["node_pool_paths_supported"] is False
    assert result["target_validation"]["node_pool_path_evidence_sufficient"] is False


def test_is_available_false_when_arm_profile_does_not_contain_target(monkeypatch):
    """Regression: ARM profile does not contain target → is_available=false."""
    # Control plane upgrade NOT available in ARM profile, AND node pool not available
    result = _plan(
        monkeypatch,
        _upgrades(
            control_upgrades=[],  # Empty: target not available
            pool_upgrades={"systempool": []},  # Node pool also doesn't have target
            pool_evidence={"systempool": {"profile_available": True, "upgrades_field_present": True, "upgrade_versions": [], "error": None}},
        ),
    )
    assert result["status"] == "blocked"
    assert result["target_validation"]["is_available"] is False
    assert result["target_validation"]["control_plane_path_supported"] is False
    assert result["target_validation"]["node_pool_paths_supported"] is False


def test_is_available_true_when_node_pool_can_upgrade_despite_control_plane_at_target(monkeypatch):
    """Regression: Control plane at target + node pool can upgrade → is_available=true."""
    # Current: 1.30.1 (at target), node pool also at target
    # But one pool needs upgrade to 1.30.1 (hypothetically different version)
    result = _plan(
        monkeypatch,
        _upgrades(
            control_plane="1.30.1",  # Already at target
            pools=[{"name": "systempool", "orchestrator_version": "1.30.0"}],  # Needs upgrade
            control_upgrades=[{"kubernetes_version": "1.30.1"}],  # Even though CP at target
            pool_upgrades={"systempool": [{"kubernetes_version": "1.30.1"}]},  # Pool can upgrade
            pool_evidence={"systempool": {"profile_available": True, "upgrades_field_present": True, "upgrade_versions": ["1.30.1"], "error": None}},
        ),
    )
    # Should be ready because node pool can upgrade even though control plane is at target
    assert result["target_validation"]["is_available"] is True
    assert result["target_validation"]["control_plane_path_supported"] is True


def test_is_available_true_when_either_control_plane_or_node_pool_can_upgrade(monkeypatch):
    """Regression: Either control plane OR node pool can upgrade → is_available=true."""
    # Both paths available: control plane can upgrade, pool can upgrade
    result = _plan(monkeypatch)
    assert result["status"] == "ready_for_confirmation"
    assert result["target_validation"]["is_available"] is True
    assert result["target_validation"]["control_plane_path_supported"] is True
    assert result["target_validation"]["node_pool_paths_supported"] is True


def test_registry_exposes_planner():
    assert any(tool.__name__ == "aks_plan_upgrade_preparation" for tool in ALL_TOOLS)
