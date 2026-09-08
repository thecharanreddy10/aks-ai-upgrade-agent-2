"""Tests for the additional upgrade-readiness validation tools."""

from __future__ import annotations

from types import SimpleNamespace

from tools import upgrade, validation
from tools.validation import (
    aks_check_node_pool_surge,
    aks_check_operator_health,
    aks_check_priority_class,
    aks_check_single_replica_services,
)

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_single_replica_services_warn_for_one_replica(monkeypatch):
    batch = {
        "deployments": (
            0,
            '{"items":[{"metadata":{"namespace":"cerebral","name":"cp-api"},'
            '"spec":{"replicas":1,"selector":{"matchLabels":{"app":"cp-api"}}},'
            '"status":{"availableReplicas":1}}]}',
        ),
        "statefulsets": (0, '{"items":[]}'),
    }
    monkeypatch.setattr(validation, "run_kubectl_batch", lambda *_a, **_k: batch)

    result = aks_check_single_replica_services(*CLUSTER_ARGS, namespace="cerebral", label_selector="app=cp-api")

    assert result["status"] == "WARNING"
    assert len(result["single_replica_workloads"]) == 1
    assert result["single_replica_workloads"][0]["name"] == "cp-api"


def test_single_replica_services_pass_for_two_replicas(monkeypatch):
    batch = {
        "deployments": (
            0,
            '{"items":[{"metadata":{"namespace":"cerebral","name":"cp-api"},'
            '"spec":{"replicas":2,"selector":{"matchLabels":{"app":"cp-api"}}},'
            '"status":{"availableReplicas":2}}]}',
        ),
        "statefulsets": (0, '{"items":[]}'),
    }
    monkeypatch.setattr(validation, "run_kubectl_batch", lambda *_a, **_k: batch)

    result = aks_check_single_replica_services(*CLUSTER_ARGS, namespace="cerebral", label_selector="app=cp-api")

    assert result["status"] == "PASS"
    assert result["single_replica_workloads"] == []


def test_single_replica_services_is_not_configured_without_selector():
    result = aks_check_single_replica_services(*CLUSTER_ARGS)

    assert result["status"] == "NOT_CONFIGURED"


def test_operator_health_skips_non_sit():
    result = aks_check_operator_health(*CLUSTER_ARGS, environment="PROD", operator_selector="app=operator")

    assert result["status"] == "SKIPPED"


def test_operator_health_not_configured_without_selector():
    result = aks_check_operator_health(*CLUSTER_ARGS, environment="SIT")

    assert result["status"] == "NOT_CONFIGURED"


def test_operator_health_blocks_unhealthy_operator(monkeypatch):
    batch = {
        "deployments": (
            0,
            '{"items":[{"metadata":{"namespace":"sit-ops","name":"sample-operator",'
            '"labels":{"app.kubernetes.io/version":"1.2.3"}},'
            '"spec":{"replicas":2},"status":{"availableReplicas":1},'
            '"template":{"spec":{"containers":[{"image":"example/operator:1.2.3"}]}}}]}',
        ),
        "statefulsets": (0, '{"items":[]}'),
    }
    monkeypatch.setattr(validation, "run_kubectl_batch", lambda *_a, **_k: batch)

    result = aks_check_operator_health(
        *CLUSTER_ARGS,
        environment="SIT",
        namespace="sit-ops",
        operator_selector="app=sample-operator",
    )

    assert result["status"] == "BLOCKED"
    assert result["unhealthy_operators"][0]["available_replicas"] == 1
    assert result["operators"][0]["current_version"] == "1.2.3"


def test_operator_health_passes_healthy_operator_and_matches_target(monkeypatch):
    batch = {
        "deployments": (
            0,
            '{"items":[{"metadata":{"namespace":"sit-ops","name":"sample-operator",'
            '"labels":{"app.kubernetes.io/version":"1.2.3"}},'
            '"spec":{"replicas":1},"status":{"availableReplicas":1},'
            '"template":{"spec":{"containers":[{"image":"example/operator:1.2.3"}]}}}]}',
        ),
        "statefulsets": (0, '{"items":[]}'),
    }
    monkeypatch.setattr(validation, "run_kubectl_batch", lambda *_a, **_k: batch)

    result = aks_check_operator_health(
        *CLUSTER_ARGS,
        environment="SIT",
        namespace="sit-ops",
        operator_selector="app=sample-operator",
        target_version="1.2.3",
    )

    assert result["status"] == "PASS"
    assert result["version_mismatches"] == []


def test_node_pool_surge_warns_for_ten_node_pool_below_recommendation(monkeypatch):
    pool = SimpleNamespace(
        name="userpool",
        mode="User",
        count=10,
        upgrade_settings=SimpleNamespace(max_surge="10%"),
    )
    fake_client = SimpleNamespace(agent_pools=SimpleNamespace(list=lambda *_a, **_k: [pool]))
    monkeypatch.setattr(validation, "get_container_service_client", lambda *_a, **_k: fake_client)

    result = aks_check_node_pool_surge(*CLUSTER_ARGS)

    assert result["status"] == "WARNING"
    assert result["recommendations"][0]["recommended_max_surge"] == "33%"
    assert result["node_pools"][0]["parsed_max_surge"]["surge_nodes"] == 1


def test_node_pool_surge_passes_for_33_percent(monkeypatch):
    pool = SimpleNamespace(
        name="userpool",
        mode="User",
        count=10,
        upgrade_settings=SimpleNamespace(max_surge="33%"),
    )
    fake_client = SimpleNamespace(agent_pools=SimpleNamespace(list=lambda *_a, **_k: [pool]))
    monkeypatch.setattr(validation, "get_container_service_client", lambda *_a, **_k: fake_client)

    result = aks_check_node_pool_surge(*CLUSTER_ARGS)

    assert result["status"] == "PASS"
    assert result["recommendations"] == []


def test_node_pool_surge_accepts_numeric_four_as_equivalent_capacity(monkeypatch):
    pool = SimpleNamespace(
        name="userpool",
        mode="User",
        count=10,
        upgrade_settings=SimpleNamespace(max_surge="4"),
    )
    fake_client = SimpleNamespace(agent_pools=SimpleNamespace(list=lambda *_a, **_k: [pool]))
    monkeypatch.setattr(validation, "get_container_service_client", lambda *_a, **_k: fake_client)

    result = aks_check_node_pool_surge(*CLUSTER_ARGS)

    assert result["status"] == "PASS"


def test_priority_class_warns_for_non_compliant_critical_pod(monkeypatch):
    payload = {
        "items": [
            {
                "metadata": {"namespace": "kube-system", "name": "critical-agent"},
                "spec": {"priorityClassName": "system-node-critical"},
            }
        ]
    }
    monkeypatch.setattr(validation, "run_kubectl_json", lambda *_a, **_k: payload)

    result = aks_check_priority_class(
        *CLUSTER_ARGS,
        namespace="kube-system",
        critical_selector="app=critical-agent",
    )

    assert result["status"] == "WARNING"
    assert result["violations"][0]["priority_class"] == "system-node-critical"


def test_priority_class_passes_for_system_cluster_critical(monkeypatch):
    payload = {
        "items": [
            {
                "metadata": {"namespace": "kube-system", "name": "critical-agent"},
                "spec": {"priorityClassName": "system-cluster-critical"},
            }
        ]
    }
    monkeypatch.setattr(validation, "run_kubectl_json", lambda *_a, **_k: payload)

    result = aks_check_priority_class(
        *CLUSTER_ARGS,
        namespace="kube-system",
        critical_selector="app=critical-agent",
    )

    assert result["status"] == "PASS"
    assert result["violations"] == []


def test_validate_upgrade_readiness_integrates_new_checks(monkeypatch):
    healthy = {"unhealthy_nodes": []}
    pod_health = {"unhealthy_pods": [], "query_errors": []}
    pdb_health = {"is_upgrade_safe": True}
    storage_health = {"blockers": [], "warnings": []}
    deprecated_health = {"blockers": [], "warnings": []}
    single = {"status": "WARNING", "single_replica_workloads": [{"name": "cp-api"}]}
    operator = {"status": "BLOCKED", "unhealthy_operators": [{"name": "operator"}]}
    surge = {"recommendations": [{"pool_name": "userpool", "current_max_surge": "10%"}]}
    priority = {"status": "WARNING", "violations": [{"name": "critical-agent"}]}

    monkeypatch.setattr(upgrade, "aks_check_node_health", lambda *_a, **_k: healthy)
    monkeypatch.setattr(upgrade, "aks_check_pod_health", lambda *_a, **_k: pod_health)
    monkeypatch.setattr(upgrade, "aks_check_pdb", lambda *_a, **_k: pdb_health)
    monkeypatch.setattr(upgrade, "aks_check_storage", lambda *_a, **_k: storage_health)
    monkeypatch.setattr(upgrade, "aks_check_deprecated_apis", lambda *_a, **_k: deprecated_health)
    monkeypatch.setattr(upgrade, "aks_check_single_replica_services", lambda *_a, **_k: single)
    monkeypatch.setattr(upgrade, "aks_check_operator_health", lambda *_a, **_k: operator)
    monkeypatch.setattr(upgrade, "aks_check_node_pool_surge", lambda *_a, **_k: surge)
    monkeypatch.setattr(upgrade, "aks_check_priority_class", lambda *_a, **_k: priority)

    result = upgrade.aks_validate_upgrade_readiness(*CLUSTER_ARGS, check_mode="full")

    assert result["single_replica_health"] == single
    assert result["operator_health"] == operator
    assert result["node_pool_surge_health"] == surge
    assert result["priority_class_health"] == priority
    assert result["readiness"]["is_ready"] is False
    assert any("single-replica" in item for item in result["readiness"]["blockers"])
    assert any("operator" in item.lower() for item in result["readiness"]["blockers"])
    assert any("maxsurge" in item.lower() for item in result["readiness"]["warnings"])
    assert any("priorityclass" in item.lower() for item in result["readiness"]["warnings"])
