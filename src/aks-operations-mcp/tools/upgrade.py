"""Upgrade tools for AKS operations with built-in safety guardrails."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any, Callable

from tools.common import get_container_service_client
from tools.deprecated_apis import aks_check_deprecated_apis
from tools.storage import aks_check_storage
from tools.validation import aks_check_node_health, aks_check_pdb, aks_check_pod_health


def aks_validate_upgrade_readiness(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str | None = None,
    maintenance_window_start_utc: str | None = None,
    maintenance_window_end_utc: str | None = None,
    check_mode: str = "quick",
    target_kubernetes_version: str | None = None,
) -> dict[str, Any]:
    """Run pre-upgrade health and safety checks."""
    if check_mode not in {"quick", "full"}:
        raise ValueError("check_mode must be 'quick' or 'full'.")

    node_health: dict[str, Any] = {}
    pod_health: dict[str, Any] = {}
    pdb_health: dict[str, Any] = {}
    storage_health: dict[str, Any] = {}
    deprecated_api_health: dict[str, Any] = {}
    deep_check_errors: list[str] = []
    blockers: list[str] = []
    warnings: list[str] = []

    if check_mode == "full":
        checks: list[tuple[str, str, Callable[[], dict[str, Any]]]] = [
            ("node_health", "node_health_check_failed", lambda: aks_check_node_health(subscription_id, resource_group, cluster_name)),
            ("pod_health", "pod_health_check_failed", lambda: aks_check_pod_health(subscription_id, resource_group, cluster_name, namespace)),
            ("pdb_health", "pdb_check_failed", lambda: aks_check_pdb(subscription_id, resource_group, cluster_name, namespace)),
            ("storage_health", "storage_health_check_failed", lambda: aks_check_storage(subscription_id, resource_group, cluster_name, namespace)),
            ("deprecated_api_health", "deprecated_api_check_failed", lambda: aks_check_deprecated_apis(subscription_id, resource_group, cluster_name, target_version=target_kubernetes_version, namespace=namespace)),
        ]
        results: dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=len(checks)) as executor:
            futures = {name: executor.submit(func) for name, _error_label, func in checks}
            error_labels = {name: error_label for name, error_label, _func in checks}
            for name, future in futures.items():
                try:
                    results[name] = future.result()
                except Exception as exc:  # noqa: BLE001
                    deep_check_errors.append(f"{error_labels[name]}: {exc}")

        if "node_health" in results:
            node_health = results["node_health"]
            if node_health.get("unhealthy_nodes"):
                blockers.append("Unhealthy nodes detected.")
        if "pod_health" in results:
            pod_health = results["pod_health"]
            if pod_health.get("unhealthy_pods"):
                blockers.append("Unhealthy pods detected.")
            elif pod_health.get("query_errors"):
                blockers.append("Pod health could not be fully checked; query_errors present.")
        if "pdb_health" in results:
            pdb_health = results["pdb_health"]
            if not pdb_health.get("is_upgrade_safe", False):
                blockers.append("PodDisruptionBudget constraints currently block disruption.")
        if "storage_health" in results:
            storage_health = results["storage_health"]
            blockers.extend(storage_health.get("blockers", []))
            warnings.extend(storage_health.get("warnings", []))
        if "deprecated_api_health" in results:
            deprecated_api_health = results["deprecated_api_health"]
            blockers.extend(deprecated_api_health.get("blockers", []))
            warnings.extend(deprecated_api_health.get("warnings", []))
        if deep_check_errors:
            blockers.append("One or more deep checks failed to execute.")
    else:
        warnings.append("Deep health checks were skipped in quick mode.")

    in_window = True
    if maintenance_window_start_utc and maintenance_window_end_utc:
        in_window = _is_within_maintenance_window(maintenance_window_start_utc, maintenance_window_end_utc)
        if not in_window:
            blockers.append("Current UTC time is outside the configured maintenance window.")

    return {
        "subscription_id": subscription_id,
        "resource_group": resource_group,
        "cluster_name": cluster_name,
        "namespace": namespace or "all-namespaces",
        "check_mode": check_mode,
        "maintenance_window": {"start_utc": maintenance_window_start_utc, "end_utc": maintenance_window_end_utc, "in_window": in_window},
        "readiness": {"is_ready": len(blockers) == 0, "blockers": blockers, "warnings": warnings},
        "deep_check_errors": deep_check_errors,
        "node_health": node_health,
        "pod_health": pod_health,
        "pdb_health": pdb_health,
        "storage_health": storage_health,
        "deprecated_api_health": deprecated_api_health,
    }


def aks_upgrade_node_pool(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    node_pool_name: str,
    kubernetes_version: str,
    namespace: str | None = None,
    dry_run: bool = True,
    maintenance_window_start_utc: str | None = None,
    maintenance_window_end_utc: str | None = None,
    check_mode: str = "quick",
) -> dict[str, Any]:
    """Execute a controlled node pool upgrade with safety gates.

    Real writes require dry_run=False, check_mode='full', the server write-enable gate,
    and sufficient Azure permissions. No application-level approval token is used.
    """
    readiness = aks_validate_upgrade_readiness(
        subscription_id=subscription_id,
        resource_group=resource_group,
        cluster_name=cluster_name,
        namespace=namespace,
        maintenance_window_start_utc=maintenance_window_start_utc,
        maintenance_window_end_utc=maintenance_window_end_utc,
        check_mode=check_mode,
        target_kubernetes_version=kubernetes_version,
    )
    if not readiness["readiness"]["is_ready"]:
        return {"status": "blocked", "reason": "precheck_failed", "requested_upgrade": {"cluster_name": cluster_name, "node_pool_name": node_pool_name, "kubernetes_version": kubernetes_version, "dry_run": dry_run}, "readiness": readiness}
    if dry_run:
        return {"status": "dry_run", "message": "Prechecks passed. No write operation executed.", "requested_upgrade": {"cluster_name": cluster_name, "node_pool_name": node_pool_name, "kubernetes_version": kubernetes_version, "dry_run": True, "check_mode": check_mode}, "readiness": readiness}
    if check_mode != "full":
        raise PermissionError("Write operations require check_mode='full'.")
    if os.getenv("AKS_UPGRADE_ENABLE_WRITE", "false").lower() != "true":
        raise PermissionError("Upgrade write operations are disabled. Set AKS_UPGRADE_ENABLE_WRITE=true to enable.")

    client = get_container_service_client(subscription_id)
    pool = client.agent_pools.get(resource_group, cluster_name, node_pool_name)
    pool.orchestrator_version = kubernetes_version
    try:
        poller = client.agent_pools.begin_create_or_update(resource_group_name=resource_group, resource_name=cluster_name, agent_pool_name=node_pool_name, parameters=pool)
    except TypeError:
        poller = client.agent_pools.begin_create_or_update(resource_group, cluster_name, node_pool_name, pool)
    return {"status": "started", "message": "Node pool upgrade request accepted.", "requested_upgrade": {"cluster_name": cluster_name, "node_pool_name": node_pool_name, "kubernetes_version": kubernetes_version, "dry_run": False}, "poller_status": poller.status(), "readiness": readiness}


def _is_within_maintenance_window(start_utc: str, end_utc: str) -> bool:
    """Return whether current UTC time falls within [start_utc, end_utc]."""
    now = datetime.now(UTC).time()
    start = datetime.strptime(start_utc, "%H:%M").time()
    end = datetime.strptime(end_utc, "%H:%M").time()
    if start <= end:
        return start <= now <= end
    return now >= start or now <= end
