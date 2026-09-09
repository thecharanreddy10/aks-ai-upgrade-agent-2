"""Mock-only tests for Phase 2 execution and verification tools."""

from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import upgrade
from tools.registry import ALL_TOOLS, build_input_schema


ARGS = ("sub", "rg", "cluster")
TARGET = "1.30.1"


class Poller:
    def __init__(self, callback=None, error=None):
        self.callback, self.error = callback, error

    def status(self):
        return "InProgress"

    def result(self):
        if self.error:
            raise self.error
        if self.callback:
            self.callback()


class Operations:
    def __init__(self, resources):
        self.resources = resources
        self.writes = []
        self.fail_next = None

    def get(self, *_args):
        return self.resources[_args[-1]] if len(_args) == 3 else self.resources["cluster"]

    def list(self, *_args):
        return list(self.resources.values())

    def begin_create_or_update(self, *args, **kwargs):
        resource = kwargs.get("parameters") or args[-1]
        self.writes.append((args, kwargs, resource))
        error, self.fail_next = self.fail_next, None

        def complete():
            if hasattr(resource, "orchestrator_version"):
                resource.current_orchestrator_version = resource.orchestrator_version
            else:
                resource.current_kubernetes_version = resource.kubernetes_version
            resource.provisioning_state = "Succeeded"

        return Poller(complete, error)


def _cluster(version="1.29.3"):
    return SimpleNamespace(
        kubernetes_version=version,
        current_kubernetes_version=version,
        provisioning_state="Succeeded",
        e_tag="cluster-etag",
    )


def _pool(name="pool1", version="1.29.3"):
    return SimpleNamespace(
        name=name,
        orchestrator_version=version,
        current_orchestrator_version=version,
        provisioning_state="Succeeded",
        node_image_version="image",
        e_tag=f"{name}-etag",
    )


def _upgrades(pools, supported=True, evidence=True, control_supported=True):
    pool_profiles = {}
    pool_evidence = {}
    for pool in pools:
        name = pool.name
        pool_profiles[name] = [{"kubernetes_version": TARGET}] if supported else [{"kubernetes_version": "1.30.0"}]
        pool_evidence[name] = {
            "profile_available": evidence,
            "upgrades_field_present": evidence,
            "upgrade_versions": [TARGET] if supported and evidence else [],
            "error": None if evidence else "profile unavailable",
        }
        if not evidence:
            pool_profiles[name] = []
    return {
        "lookup_mode": "upgrade-profile",
        "current_control_plane_version": pools[0]._cluster.kubernetes_version,
        "current_node_pools": [
            {"name": p.name, "orchestrator_version": p.orchestrator_version, "node_image_version": p.node_image_version}
            for p in pools
        ],
        "control_plane_upgrades": [{"kubernetes_version": TARGET}] if control_supported else [],
        "node_pool_upgrades": pool_profiles,
        "node_pool_upgrade_profile_evidence": pool_evidence,
        "upgrade_profile_errors": [],
    }


def _wire(monkeypatch, pools=None, supported=True, evidence=True, control_supported=True, readiness=None):
    cluster = _cluster()
    pools = pools or [_pool()]
    for pool in pools:
        pool._cluster = cluster
    client = SimpleNamespace(
        managed_clusters=Operations({"cluster": cluster}),
        agent_pools=Operations({pool.name: pool for pool in pools}),
    )
    profile_calls = []

    def available(*_args, **_kwargs):
        profile_calls.append(1)
        return _upgrades(pools, supported, evidence, control_supported)

    ready = readiness or {"readiness": {"is_ready": True, "blockers": [], "warnings": []}}
    monkeypatch.setattr(upgrade, "get_container_service_client", lambda *_a: client)
    monkeypatch.setattr(upgrade, "aks_get_available_upgrades", available)
    monkeypatch.setattr(upgrade, "aks_validate_upgrade_readiness", lambda *_a, **_k: ready)
    monkeypatch.setattr(upgrade, "aks_get_cluster_details", lambda *_a: {
        "kubernetes_version": cluster.kubernetes_version, "provisioning_state": cluster.provisioning_state
    })
    monkeypatch.setattr(upgrade, "aks_get_node_pools", lambda *_a: {"node_pools": [
        {"name": p.name, "orchestrator_version": p.orchestrator_version, "provisioning_state": p.provisioning_state}
        for p in pools
    ]})
    return client, cluster, pools, profile_calls


def _execute(monkeypatch, **kwargs):
    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    # Existing tests assume confirmation is provided; new tests override this explicitly
    if "is_user_confirmed" not in kwargs:
        kwargs["is_user_confirmed"] = True
    return upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, **kwargs)


def test_write_gate_requires_full_check_mode(monkeypatch):
    monkeypatch.delenv("AKS_UPGRADE_ENABLE_WRITE", raising=False)
    result = upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, check_mode="quick", is_user_confirmed=True)
    assert result["status"] == "blocked"
    assert result["blocked_stage"] == "execution_gate"
    assert result["reason_code"] == "CHECK_MODE_NOT_FULL"
    assert result["writes_performed"] is False
    assert result["pollers_created"] is False
    assert result["cluster_modified"] is False


def test_write_gate_requires_environment_enablement(monkeypatch):
    monkeypatch.delenv("AKS_UPGRADE_ENABLE_WRITE", raising=False)
    monkeypatch.setattr(
        upgrade, "get_container_service_client",
        lambda *_args: pytest.fail("Azure client must not be created when the write gate is disabled"),
    )
    result = upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, is_user_confirmed=True)
    assert result == {
        "status": "blocked",
        "blocked_stage": "execution_gate",
        "reason_code": "UPGRADE_WRITE_DISABLED",
        "message": "Upgrade execution is disabled because AKS_UPGRADE_ENABLE_WRITE is not enabled.",
        "writes_performed": False,
        "write_submission_attempted": False,
        "write_accepted": False,
        "pollers_created": False,
        "cluster_modified": False,
        "target_kubernetes_version": TARGET,
        "execution_scope": "complete_cluster",
        "pre_execution_readiness": None,
        "control_plane": {"status": "not_required", "poller_status": None, "before": None, "after": None, "error": None},
        "node_pool_profile_after_control_plane": None,
        "node_pools": [],
        "post_upgrade_verification": None,
        "blockers": ["Upgrade execution is disabled because AKS_UPGRADE_ENABLE_WRITE is not enabled."],
        "warnings": [],
    }


def test_readiness_blocker_prevents_every_write(monkeypatch):
    client, *_ = _wire(monkeypatch, readiness={"readiness": {"is_ready": False, "blockers": ["PDB"], "warnings": ["warn"]}})
    result = _execute(monkeypatch)
    assert result["status"] == "blocked" and result["blockers"] == ["PDB"]
    assert result["reason_code"] == "MANDATORY_READINESS_FAILED"
    assert result["blocked_stage"] == "mandatory_readiness"
    assert not client.managed_clusters.writes and not client.agent_pools.writes


def test_unsupported_control_plane_target_prevents_write(monkeypatch):
    client, *_ = _wire(monkeypatch, control_supported=False)
    result = _execute(monkeypatch)
    assert result["status"] == "blocked"
    assert result["reason_code"] == "CONTROL_PLANE_TARGET_UNSUPPORTED"
    assert result["blocked_stage"] == "control_plane_path"
    assert not client.managed_clusters.writes


def test_maintenance_window_blocker_is_structured(monkeypatch):
    client, *_ = _wire(monkeypatch, readiness={"readiness": {
        "is_ready": False,
        "blockers": ["Current time is outside the configured maintenance window."],
        "warnings": [],
    }})
    result = _execute(monkeypatch)
    assert result["status"] == "blocked"
    assert result["blocked_stage"] == "maintenance_window"
    assert result["reason_code"] == "MAINTENANCE_WINDOW_UNAVAILABLE"
    assert not client.managed_clusters.writes and not client.agent_pools.writes


# Authorization Tests
# ===================
# These tests validate the explicit confirmation authorization model.
# is_user_confirmed=True is required before any Azure write.
# AKS_UPGRADE_ENABLE_WRITE=true is a deployment-level capability switch.


def test_authorization_a_confirmed_with_write_enabled_proceeds_to_write(monkeypatch):
    """Authorization A: AKS_UPGRADE_ENABLE_WRITE=true + is_user_confirmed=true → write allowed."""
    client, _cluster_obj, _pools, profiles = _wire(monkeypatch)
    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    result = upgrade.aks_execute_confirmed_upgrade(
        *ARGS, TARGET, is_user_confirmed=True, confirmed_scope="control_plane_only"
    )
    assert result["status"] == "completed"
    assert result["write_accepted"] is True
    assert len(client.managed_clusters.writes) == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"is_user_confirmed": False},
        {"target_kubernetes_version": "1.35.1"},
        {"target_kubernetes_version": "1.35.1", "is_user_confirmed": False},
    ],
)
def test_authorization_contract_non_confirmation_cases_block(monkeypatch, kwargs):
    """Agent/MCP contract: target-only requests never count as confirmation."""
    _wire(monkeypatch)
    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    call_kwargs = dict(kwargs)
    call_kwargs.setdefault("is_user_confirmed", False)
    target_value = call_kwargs.pop("target_kubernetes_version", TARGET)
    # The target may be present, but it must never satisfy the authorization gate by itself.
    result = upgrade.aks_execute_confirmed_upgrade(*ARGS, target_value, **call_kwargs)
    assert result["status"] == "blocked"
    assert result["blocked_stage"] == "authorization"
    assert result["reason_code"] == "EXECUTION_CONFIRMATION_REQUIRED"
    assert result["write_submission_attempted"] is False
    assert result["pollers_created"] is False
    assert result["cluster_modified"] is False


def test_agent_instructions_require_explicit_confirmation(monkeypatch):
    """Agent instructions must require explicit approval and classify non-approval cases."""
    del monkeypatch
    main_py = Path(__file__).resolve().parents[2] / "agent-framework-agent-with-foundry-toolbox-responses" / "main.py"
    text = main_py.read_text(encoding="utf-8")
    # New policy: AKS UPGRADE HUMAN APPROVAL POLICY
    assert "explicitly approved" in text
    assert "explicit approval" in text
    assert "Never execute an AKS control-plane" in text
    assert "explicit approval of the displayed upgrade plan" in text
    assert "Do not execute the upgrade immediately" in text
    assert "Stop and ask the user" in text
    assert "`control_plane_only`" in text


def test_agent_instructions_accept_concise_confirmations_for_current_pending_plan(monkeypatch):
    """Agent must require specific approval examples referring to the upgrade plan."""
    del monkeypatch
    main_py = Path(__file__).resolve().parents[2] / "agent-framework-agent-with-foundry-toolbox-responses" / "main.py"
    text = main_py.read_text(encoding="utf-8")
    # New policy includes examples of valid approval
    assert "Yes, proceed with the upgrade to 1.35.1" in text
    assert "I approve the control-plane upgrade to 1.35.1" in text
    assert "Yes, proceed with the complete cluster upgrade to 1.35.1" in text


def test_agent_instructions_reject_confirmation_for_different_target_or_scope(monkeypatch):
    """Different target/scope than the upgrade plan must block execution."""
    del monkeypatch
    main_py = Path(__file__).resolve().parents[2] / "agent-framework-agent-with-foundry-toolbox-responses" / "main.py"
    text = main_py.read_text(encoding="utf-8")
    # New policy: execute scope policy and no automatic expansion
    assert "Never convert" in text
    assert "never infer" in text.lower()
    assert "do not expand" in text.lower()


def test_agent_instructions_require_pending_plan_for_generic_confirmation(monkeypatch):
    """Generic statements must not be treated as approval without clear upgrade plan reference."""
    del monkeypatch
    main_py = Path(__file__).resolve().parents[2] / "agent-framework-agent-with-foundry-toolbox-responses" / "main.py"
    text = main_py.read_text(encoding="utf-8")
    # New policy: ambiguous approval cases that must NOT authorize execution
    assert "Do NOT treat any of the following as approval" in text
    assert "Ambiguous statements such as" in text
    assert "When approval is ambiguous" in text


def test_authorization_b_not_confirmed_blocks_before_write(monkeypatch):
    """Authorization B: AKS_UPGRADE_ENABLE_WRITE=true + is_user_confirmed=false → blocked."""
    _wire(monkeypatch)
    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    result = upgrade.aks_execute_confirmed_upgrade(
        *ARGS, TARGET, is_user_confirmed=False
    )
    assert result["status"] == "blocked"
    assert result["blocked_stage"] == "authorization"
    assert result["reason_code"] == "EXECUTION_CONFIRMATION_REQUIRED"
    # No Azure calls should be made
    assert result["write_submission_attempted"] is False
    assert result["pollers_created"] is False
    assert result["cluster_modified"] is False


def test_authorization_c_confirmed_with_write_disabled_blocks(monkeypatch):
    """Authorization C: AKS_UPGRADE_ENABLE_WRITE=false + is_user_confirmed=true → blocked."""
    _wire(monkeypatch)
    monkeypatch.delenv("AKS_UPGRADE_ENABLE_WRITE", raising=False)
    result = upgrade.aks_execute_confirmed_upgrade(
        *ARGS, TARGET, is_user_confirmed=True
    )
    assert result["status"] == "blocked"
    assert result["blocked_stage"] == "execution_gate"
    assert result["reason_code"] == "UPGRADE_WRITE_DISABLED"
    # Confirmation present but write capability disabled
    assert result["write_submission_attempted"] is False
    assert result["pollers_created"] is False


def test_authorization_d_confirmed_control_plane_only_prevents_node_pool_writes(monkeypatch):
    """Authorization D: control_plane_only scope forbids node-pool writes even if SUPPORTED."""
    client, _cluster_obj, pools, _profiles = _wire(monkeypatch)
    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    result = upgrade.aks_execute_confirmed_upgrade(
        *ARGS, TARGET, is_user_confirmed=True, confirmed_scope="control_plane_only"
    )
    assert result["status"] == "completed"
    assert result["reason_code"] == "CONTROL_PLANE_ONLY_SCOPE"
    # Control plane can write
    assert len(client.managed_clusters.writes) == 1
    # But node pools MUST NOT write
    assert len(client.agent_pools.writes) == 0
    assert pools[0].orchestrator_version != TARGET


def test_authorization_e_complete_cluster_allows_supported_node_pool_writes(monkeypatch):
    """Authorization E: complete_cluster scope + SUPPORTED node pools → pool writes allowed."""
    client, _cluster_obj, pools, _profiles = _wire(monkeypatch)
    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    result = upgrade.aks_execute_confirmed_upgrade(
        *ARGS, TARGET, is_user_confirmed=True, confirmed_scope="complete_cluster"
    )
    assert result["status"] == "completed"
    assert result["execution_scope"] == "complete_cluster"
    # Both control plane and node pools should write
    assert len(client.managed_clusters.writes) == 1
    assert len(client.agent_pools.writes) == 1
    assert pools[0].orchestrator_version == TARGET


def test_authorization_f_target_version_alone_does_not_count_as_confirmation(monkeypatch):
    """Authorization F: Supplying only target_kubernetes_version is not confirmation."""
    _wire(monkeypatch)
    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    # Call with only target_kubernetes_version, no is_user_confirmed
    result = upgrade.aks_execute_confirmed_upgrade(
        *ARGS, TARGET
        # is_user_confirmed defaults to False
    )
    assert result["status"] == "blocked"
    assert result["reason_code"] == "EXECUTION_CONFIRMATION_REQUIRED"
    # No Azure operations
    assert result["write_submission_attempted"] is False


def test_successful_control_plane_lro_and_post_upgrade_verification(monkeypatch):
    client, _cluster_obj, _pools, profiles = _wire(monkeypatch)
    result = _execute(monkeypatch)
    assert result["status"] == "completed"
    assert result["control_plane"]["status"] == "succeeded"
    assert result["control_plane"]["poller_status"] == "InProgress"
    assert result["writes_performed"] is True
    assert result["write_submission_attempted"] is True
    assert result["write_accepted"] is True
    assert result["pollers_created"] is True
    assert result["cluster_modified"] is True
    assert result["post_upgrade_verification"]["is_successful"] is True
    assert len(profiles) == 2
    args, kwargs, submitted = client.managed_clusters.writes[0]
    assert args[:2] == ("rg", "cluster")
    assert kwargs["parameters"] is submitted
    assert submitted.kubernetes_version == TARGET


def test_control_plane_submission_failure_stops_pools_without_poller(monkeypatch):
    client, *_ = _wire(monkeypatch)

    def reject_submission(*_args, **_kwargs):
        raise RuntimeError("ManagedCluster update submission failed")

    client.managed_clusters.begin_create_or_update = reject_submission
    result = _execute(monkeypatch)
    assert result["status"] == "failed"
    assert result["control_plane"]["status"] == "failed"
    assert result["blocked_stage"] == "control_plane_submission"
    assert result["reason_code"] == "CONTROL_PLANE_UPGRADE_FAILED"
    assert result["writes_performed"] is True
    assert result["write_submission_attempted"] is True
    assert result["write_accepted"] is False
    assert result["pollers_created"] is False
    assert result["cluster_modified"] is False
    assert not client.agent_pools.writes


def test_control_plane_submission_uses_standard_sdk_create_or_update(monkeypatch):
    client, *_ = _wire(monkeypatch)
    result = _execute(monkeypatch)
    assert result["status"] == "completed"
    args, kwargs, submitted = client.managed_clusters.writes[0]
    assert args[:2] == ("rg", "cluster")
    assert kwargs["parameters"] is submitted
    assert submitted.kubernetes_version == TARGET
    assert "etag" not in kwargs
    assert "match_condition" not in kwargs


def test_supported_pool_is_upgraded_after_fresh_profile(monkeypatch):
    client, _cluster_obj, pools, profiles = _wire(monkeypatch)
    result = _execute(monkeypatch)
    assert len(profiles) == 2
    assert result["node_pools"][0]["path_status"] == "SUPPORTED"
    assert result["node_pools"][0]["status"] == "succeeded"
    assert len(client.agent_pools.writes) == 1
    assert pools[0].orchestrator_version == TARGET


# Scope Enforcement Tests
# =====================
# These tests validate that confirmed_scope parameter is enforced.
# Node-pool execution requires explicit scope authorization.


def test_control_plane_only_scope_with_supported_pool_prevents_pool_write(monkeypatch):
    """Scope enforcement: control_plane_only + SUPPORTED pool → no nodepool write."""
    client, _cluster_obj, pools, profiles = _wire(monkeypatch)
    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    result = upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="control_plane_only", is_user_confirmed=True)

    # Control plane should succeed
    assert result["status"] == "completed"
    assert result["control_plane"]["status"] == "succeeded"
    assert result["execution_scope"] == "control_plane_only"

    # Node-pool execution must NOT occur, even though pool is SUPPORTED
    assert result["reason_code"] == "CONTROL_PLANE_ONLY_SCOPE"
    assert len(client.agent_pools.writes) == 0
    assert result["node_pools"] == []
    assert pools[0].orchestrator_version != TARGET  # Pool should NOT be upgraded


def test_control_plane_only_scope_with_insufficient_pool_prevents_pool_write(monkeypatch):
    """Scope enforcement: control_plane_only + INSUFFICIENT_EVIDENCE pool → no nodepool write."""
    client, *_ = _wire(monkeypatch, supported=True, evidence=False)
    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    result = upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="control_plane_only", is_user_confirmed=True)

    assert result["status"] == "completed"
    assert result["control_plane"]["status"] == "succeeded"
    assert result["execution_scope"] == "control_plane_only"
    assert result["reason_code"] == "CONTROL_PLANE_ONLY_SCOPE"
    assert len(client.agent_pools.writes) == 0
    assert result["node_pools"] == []


def test_control_plane_only_scope_with_unsupported_pool_prevents_pool_write(monkeypatch):
    """Scope enforcement: control_plane_only + UNSUPPORTED pool → no nodepool write."""
    client, *_ = _wire(monkeypatch, supported=False, evidence=True)
    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    result = upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="control_plane_only", is_user_confirmed=True)

    assert result["status"] == "completed"
    assert result["control_plane"]["status"] == "succeeded"
    assert result["execution_scope"] == "control_plane_only"
    assert result["reason_code"] == "CONTROL_PLANE_ONLY_SCOPE"
    assert len(client.agent_pools.writes) == 0
    assert result["node_pools"] == []


def test_complete_cluster_scope_with_supported_pool_allows_pool_write(monkeypatch):
    """Scope enforcement: complete_cluster + SUPPORTED pool → nodepool write allowed."""
    client, _cluster_obj, pools, profiles = _wire(monkeypatch)
    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    result = upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="complete_cluster", is_user_confirmed=True)

    # Both control plane and node pool should succeed
    assert result["status"] == "completed"
    assert result["control_plane"]["status"] == "succeeded"
    assert result["execution_scope"] == "complete_cluster"

    # Node-pool write MUST occur when scope is complete_cluster
    assert result["node_pools"][0]["path_status"] == "SUPPORTED"
    assert result["node_pools"][0]["status"] == "succeeded"
    assert len(client.agent_pools.writes) == 1
    assert pools[0].orchestrator_version == TARGET


def test_default_scope_is_complete_cluster(monkeypatch):
    """Default confirmed_scope should be complete_cluster."""
    client, _cluster_obj, pools, profiles = _wire(monkeypatch)
    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    result = upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, is_user_confirmed=True)

    # Default behavior (complete_cluster) should allow node-pool execution
    assert result["status"] == "completed"
    assert result["control_plane"]["status"] == "succeeded"
    assert result["execution_scope"] == "complete_cluster"
    assert result["node_pools"][0]["path_status"] == "SUPPORTED"
    assert len(client.agent_pools.writes) == 1



@pytest.mark.parametrize("supported,evidence,status", [(False, True, "UNSUPPORTED"), (True, False, "INSUFFICIENT_EVIDENCE")])
def test_unsupported_or_insufficient_pool_is_not_upgraded(monkeypatch, supported, evidence, status):
    client, *_ = _wire(monkeypatch, supported=supported, evidence=evidence)
    result = _execute(monkeypatch)
    assert result["status"] == "partial"
    assert result["node_pools"][0]["path_status"] == status
    assert result["reason_code"] == (
        "NODE_POOL_TARGET_UNSUPPORTED" if status == "UNSUPPORTED" else "NODE_POOL_PROFILE_INSUFFICIENT"
    )
    assert result["blocked_stage"] == "node_pool_path"
    assert not client.agent_pools.writes


def test_first_failed_pool_stops_later_pools(monkeypatch):
    pools = [_pool("first"), _pool("second")]
    client, *_ = _wire(monkeypatch, pools=pools)
    client.agent_pools.fail_next = RuntimeError("pool failed")
    result = _execute(monkeypatch)
    assert result["status"] == "partial"
    assert [entry["name"] for entry in result["node_pools"]] == ["first"]
    assert len(client.agent_pools.writes) == 1


def test_multiple_pools_are_processed_sequentially(monkeypatch):
    client, *_ = _wire(monkeypatch, pools=[_pool("first"), _pool("second")])
    result = _execute(monkeypatch)
    assert result["status"] == "completed"
    assert [entry["name"] for entry in result["node_pools"]] == ["first", "second"]
    assert len(client.agent_pools.writes) == 2


def test_already_target_pool_is_not_upgraded(monkeypatch):
    pool = _pool(version=TARGET)
    client, *_ = _wire(monkeypatch, pools=[pool])
    result = _execute(monkeypatch)
    assert result["node_pools"][0]["status"] == "not_required"
    assert not client.agent_pools.writes


def test_status_tool_is_read_only(monkeypatch):
    client, *_ = _wire(monkeypatch)
    result = upgrade.aks_get_upgrade_execution_status(*ARGS)
    assert result["cluster"]["current_kubernetes_version"] == "1.29.3"
    assert result["node_pools"][0]["current_orchestrator_version"] == "1.29.3"
    assert not client.managed_clusters.writes and not client.agent_pools.writes


def test_no_approval_or_confirmation_parameters_and_registry_registration():
    names = {tool.__name__ for tool in ALL_TOOLS}
    assert {"aks_execute_confirmed_upgrade", "aks_get_upgrade_execution_status"} <= names
    for func in (upgrade.aks_execute_confirmed_upgrade, upgrade.aks_get_upgrade_execution_status):
        properties = build_input_schema(func)["properties"]
        assert "approval_token" not in properties and "confirm_upgrade" not in properties
        assert "approval_token" not in inspect.signature(func).parameters


def test_optional_validations_are_never_called(monkeypatch):
    _wire(monkeypatch)
    for name in ("aks_check_single_replica_services", "aks_check_operator_health", "aks_check_node_pool_surge", "aks_check_priority_class"):
        monkeypatch.setattr(upgrade, name, lambda *_a, **_k: pytest.fail("optional validation invoked"), raising=False)
    result = _execute(monkeypatch)
    assert result["status"] == "completed"


# Regression test for discovered authorization flaw
# ===================================================
# Live test on 2026-09-09 revealed that the agent could set is_user_confirmed=true
# itself, without a human approval mechanism, causing an unauthorized AKS write.
# The Foundry Toolbox is configured with require_approval="never", so there is no
# trusted channel for passing human approval state from the UI to the MCP tool.
# The root cause: is_user_confirmed is just a parameter, not a cryptographically or
# independently trusted signal of human approval.


def test_regression_is_user_confirmed_cannot_be_trusted_as_sole_authorization():
    """
    REGRESSION: is_user_confirmed=true cannot be trusted as proof of human approval
    when agent can supply it directly in tool arguments.

    Root cause: Foundry Toolbox + Agent Framework + MCP architecture provides no
    trusted channel for passing human approval from a UI layer to the MCP tool.
    The Toolbox is configured with require_approval="never", so the only
    authorization boundary must be the deployment-level AKS_UPGRADE_ENABLE_WRITE gate.

    Safest fallback: AKS_UPGRADE_ENABLE_WRITE stays disabled by default.
    Operator must explicitly enable it at deployment time.
    Agent-level is_user_confirmed check remains as a UX contract, but cannot be
    relied upon as the sole security boundary.

    This test documents the architectural constraint discovered in live validation.
    """
    # This is a documentation test; the actual security boundary is the deployment
    # environment variable, not a parameter that the agent can fabricate.
    # See: toolbox.yaml require_approval="never"
    pass
