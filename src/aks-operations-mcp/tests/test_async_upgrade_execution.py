"""Tests for the non-blocking AKS upgrade coordinator."""

from __future__ import annotations

from types import SimpleNamespace

from tools import async_upgrade


TARGET = "1.35.2"
ARGS = ("sub", "rg", "cluster")


class Poller:
    def __init__(self, status="InProgress"):
        self._status = status

    def status(self):
        return self._status


class Operations:
    def __init__(self, resources):
        self.resources = resources
        self.writes = []

    def get(self, *args):
        return self.resources[args[-1]]

    def list(self, *_args):
        return list(self.resources.values())

    def begin_create_or_update(self, *args, **kwargs):
        resource = kwargs.get("parameters") or args[-1]
        self.writes.append(resource)
        return Poller()


def _cluster(version="1.35.1", state="Succeeded"):
    return SimpleNamespace(
        kubernetes_version=version,
        current_kubernetes_version=version,
        provisioning_state=state,
    )


def _pool(name="nodepool1", version="1.35.1", state="Succeeded"):
    return SimpleNamespace(
        name=name,
        orchestrator_version=version,
        current_orchestrator_version=version,
        provisioning_state=state,
        node_image_version="image",
    )


def _wire(monkeypatch, cluster, pool, readiness=None, pool_supported=True):
    client = SimpleNamespace(
        managed_clusters=Operations({"cluster": cluster}),
        agent_pools=Operations({pool.name: pool}),
    )
    profile = [{"kubernetes_version": TARGET}] if pool_supported else [{"kubernetes_version": "1.35.1"}]

    def available(*_args, **_kwargs):
        return {
            "lookup_mode": "upgrade-profile",
            "current_control_plane_version": cluster.kubernetes_version,
            "current_node_pools": [{
                "name": pool.name,
                "orchestrator_version": pool.orchestrator_version,
                "provisioning_state": pool.provisioning_state,
            }],
            "control_plane_upgrades": [{"kubernetes_version": TARGET}],
            "node_pool_upgrades": {pool.name: profile},
            "node_pool_upgrade_profile_evidence": {pool.name: {
                "profile_available": True,
                "upgrades_field_present": True,
                "upgrade_versions": [TARGET] if pool_supported else ["1.35.1"],
                "error": None,
            }},
            "upgrade_profile_errors": [],
        }

    monkeypatch.setenv("AKS_UPGRADE_ENABLE_WRITE", "true")
    monkeypatch.setattr(async_upgrade, "aks_get_available_upgrades", available)
    monkeypatch.setattr(async_upgrade.sync_upgrade, "get_container_service_client", lambda *_: client)
    monkeypatch.setattr(
        async_upgrade.sync_upgrade,
        "aks_validate_upgrade_readiness",
        lambda *a, **k: readiness or {"readiness": {"is_ready": True, "blockers": [], "warnings": []}},
    )
    monkeypatch.setattr(
        async_upgrade,
        "aks_get_cluster_details",
        lambda *a: {"kubernetes_version": cluster.kubernetes_version, "provisioning_state": cluster.provisioning_state},
    )
    monkeypatch.setattr(
        async_upgrade,
        "aks_get_node_pools",
        lambda *a: {"node_pools": [{"name": pool.name, "orchestrator_version": pool.orchestrator_version, "provisioning_state": pool.provisioning_state}]},
    )
    return client, available


def test_control_plane_submission_returns_without_waiting(monkeypatch):
    cluster = _cluster("1.35.1", "Succeeded")
    pool = _pool()
    client, _ = _wire(monkeypatch, cluster, pool)

    result = async_upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="control_plane_only")

    assert result["status"] == "in_progress"
    assert result["reason_code"] == "CONTROL_PLANE_UPGRADE_STARTED"
    assert result["next_action"] == "poll_status"
    assert result["write_accepted"] is True
    assert len(client.managed_clusters.writes) == 1
    assert result["control_plane"]["status"] == "started"


def test_existing_control_plane_operation_is_not_duplicated(monkeypatch):
    cluster = _cluster("1.35.1", "Updating")
    pool = _pool()
    client, _ = _wire(monkeypatch, cluster, pool)

    result = async_upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="control_plane_only")

    assert result["status"] == "in_progress"
    assert result["reason_code"] == "CONTROL_PLANE_ALREADY_IN_PROGRESS"
    assert result["write_submission_attempted"] is False
    assert client.managed_clusters.writes == []


def test_failed_control_plane_operation_is_not_retried(monkeypatch):
    cluster = _cluster("1.35.1", "Failed")
    pool = _pool()
    client, _ = _wire(monkeypatch, cluster, pool)

    result = async_upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="control_plane_only")

    assert result["status"] == "failed"
    assert result["reason_code"] == "CONTROL_PLANE_OPERATION_TERMINAL_FAILURE"
    assert result["write_submission_attempted"] is False
    assert client.managed_clusters.writes == []


def test_control_plane_only_does_not_require_node_pool_target(monkeypatch):
    cluster = _cluster(TARGET, "Succeeded")
    pool = _pool("nodepool1", "1.35.1", "Succeeded")
    _wire(monkeypatch, cluster, pool)

    result = async_upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="control_plane_only")

    assert result["status"] == "completed"
    assert result["reason_code"] == "CONTROL_PLANE_ONLY_SCOPE"
    assert result["post_upgrade_verification"]["is_successful"] is True


def test_node_pool_submission_returns_without_waiting(monkeypatch):
    cluster = _cluster(TARGET, "Succeeded")
    pool = _pool("nodepool1", "1.35.1", "Succeeded")
    client, _ = _wire(monkeypatch, cluster, pool, pool_supported=True)

    result = async_upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="complete_cluster")

    assert result["status"] == "in_progress"
    assert result["reason_code"] == "NODE_POOL_UPGRADE_STARTED"
    assert result["next_action"] == "poll_status"
    assert len(client.agent_pools.writes) == 1


def test_node_pool_in_progress_is_not_duplicated(monkeypatch):
    cluster = _cluster(TARGET, "Succeeded")
    pool = _pool("nodepool1", "1.35.1", "Updating")
    client, _ = _wire(monkeypatch, cluster, pool, pool_supported=True)

    result = async_upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="complete_cluster")

    assert result["status"] == "in_progress"
    assert result["reason_code"] == "NODE_POOL_ALREADY_IN_PROGRESS"
    assert client.agent_pools.writes == []


def test_failed_node_pool_operation_is_not_retried(monkeypatch):
    cluster = _cluster(TARGET, "Succeeded")
    pool = _pool("nodepool1", "1.35.1", "Failed")
    client, _ = _wire(monkeypatch, cluster, pool, pool_supported=True)

    result = async_upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="complete_cluster")

    assert result["status"] == "partial"
    assert result["reason_code"] == "NODE_POOL_OPERATION_TERMINAL_FAILURE"
    assert client.agent_pools.writes == []


def test_insufficient_node_pool_evidence_returns_partial_without_write(monkeypatch):
    cluster = _cluster(TARGET, "Succeeded")
    pool = _pool("nodepool1", "1.35.1", "Succeeded")
    client, _ = _wire(monkeypatch, cluster, pool, pool_supported=False)

    result = async_upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="complete_cluster")

    assert result["status"] == "partial"
    assert result["reason_code"] == "NODE_POOL_PROFILE_INSUFFICIENT"
    assert client.agent_pools.writes == []


def test_live_node_pool_target_prevents_redundant_write_when_discovery_is_stale(monkeypatch):
    cluster = _cluster(TARGET, "Succeeded")
    pool = _pool("nodepool1", TARGET, "Succeeded")
    client, available = _wire(monkeypatch, cluster, pool, pool_supported=True)
    original = available

    # Simulate stale discovery that still reports the old version while the live pool is already at target.
    monkeypatch.setattr(
        async_upgrade,
        "aks_get_available_upgrades",
        lambda *a, **k: {
            **original(),
            "current_node_pools": [{"name": pool.name, "orchestrator_version": "1.35.1", "provisioning_state": "Succeeded"}],
        },
    )

    result = async_upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="complete_cluster")

    assert result["status"] == "completed"
    assert result["reason_code"] == "UPGRADE_COMPLETED"
    assert client.agent_pools.writes == []


def test_complete_cluster_advances_and_finishes_after_node_pool_reaches_target(monkeypatch):
    cluster = _cluster(TARGET, "Succeeded")
    pool = _pool("nodepool1", "1.35.1", "Succeeded")
    client, _ = _wire(monkeypatch, cluster, pool, pool_supported=True)

    first = async_upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="complete_cluster")
    assert first["status"] == "in_progress"
    assert first["reason_code"] == "NODE_POOL_UPGRADE_STARTED"
    assert len(client.agent_pools.writes) == 1

    pool.orchestrator_version = TARGET
    pool.current_orchestrator_version = TARGET
    pool.provisioning_state = "Succeeded"

    final = async_upgrade.aks_execute_confirmed_upgrade(*ARGS, TARGET, confirmed_scope="complete_cluster")
    assert final["status"] == "completed"
    assert final["reason_code"] == "UPGRADE_COMPLETED"
    assert len(client.agent_pools.writes) == 1
