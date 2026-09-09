"""Non-blocking AKS upgrade coordinator for long-running Azure operations."""

from __future__ import annotations

from threading import Lock
from typing import Any

from tools import upgrade as sync_upgrade
from tools.discovery import aks_get_available_upgrades, aks_get_cluster_details, aks_get_node_pools


_IN_PROGRESS_STATES = {"Updating", "Upgrading", "Creating", "Deleting", "Accepted", "InProgress", "In Progress"}
_TERMINAL_FAILURE_STATES = {"Failed", "Canceled", "Cancelled"}
_VALID_SCOPES = {"control_plane_only", "complete_cluster"}
_ACTIVE_EXECUTIONS: set[tuple[str, str, str, str, str]] = set()
_ACTIVE_EXECUTIONS_LOCK = Lock()


def aks_execute_confirmed_upgrade(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    target_kubernetes_version: str,
    namespace: str | None = None,
    maintenance_window_start_utc: str | None = None,
    maintenance_window_end_utc: str | None = None,
    check_mode: str = "full",
    confirmed_scope: str = "complete_cluster",
) -> dict[str, Any]:
    """Validate scope and coordinate one active execution for this target and scope."""
    result = _result(target_kubernetes_version, confirmed_scope)
    if confirmed_scope not in _VALID_SCOPES:
        return _finish(
            result,
            "blocked",
            "confirmed_scope must be 'control_plane_only' or 'complete_cluster'.",
            "INVALID_EXECUTION_SCOPE",
            "scope_validation",
        )

    execution_key = (
        subscription_id,
        resource_group,
        cluster_name,
        target_kubernetes_version,
        confirmed_scope,
    )
    with _ACTIVE_EXECUTIONS_LOCK:
        already_active = execution_key in _ACTIVE_EXECUTIONS
        if not already_active:
            _ACTIVE_EXECUTIONS.add(execution_key)

    if already_active:
        state = _active_execution_state(
            subscription_id,
            resource_group,
            cluster_name,
            target_kubernetes_version,
            confirmed_scope,
        )
        if state == "terminal_failure":
            with _ACTIVE_EXECUTIONS_LOCK:
                _ACTIVE_EXECUTIONS.discard(execution_key)
            return _finish(
                result,
                "failed",
                "The active Azure operation is in a terminal failure state; no automatic retry was submitted.",
                "UPGRADE_OPERATION_TERMINAL_FAILURE",
                "execution_state",
            )
        if state != "ready_to_advance":
            return _finish(
                result,
                "in_progress",
                "An upgrade operation for this target and scope is already active; no duplicate write was submitted.",
                "UPGRADE_ALREADY_IN_PROGRESS",
                "execution_state",
            )
        with _ACTIVE_EXECUTIONS_LOCK:
            _ACTIVE_EXECUTIONS.discard(execution_key)

    try:
        result = _execute_confirmed_upgrade(
            subscription_id,
            resource_group,
            cluster_name,
            target_kubernetes_version,
            namespace,
            maintenance_window_start_utc,
            maintenance_window_end_utc,
            check_mode,
            confirmed_scope,
        )
    except Exception:
        with _ACTIVE_EXECUTIONS_LOCK:
            _ACTIVE_EXECUTIONS.discard(execution_key)
        raise

    if result["status"] != "in_progress":
        with _ACTIVE_EXECUTIONS_LOCK:
            _ACTIVE_EXECUTIONS.discard(execution_key)
    return result


def _execute_confirmed_upgrade(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    target_kubernetes_version: str,
    namespace: str | None = None,
    maintenance_window_start_utc: str | None = None,
    maintenance_window_end_utc: str | None = None,
    check_mode: str = "full",
    confirmed_scope: str = "complete_cluster",
) -> dict[str, Any]:
    """Start or advance a previously user-confirmed AKS upgrade without waiting for Azure LRO completion.

    The calling agent must obtain explicit user approval before invoking this tool. This tool enforces
    the existing MCP write gate and readiness checks, submits at most one long-running Azure operation
    per call, and returns quickly so the agent can poll `aks_get_upgrade_execution_status` and call this
    coordinator again to advance the workflow.

    The workflow is deliberately idempotent against live Azure state: if a control-plane or node-pool
    operation is already in progress, the tool reports that state and performs no duplicate write.
    """
    result = _result(target_kubernetes_version, confirmed_scope)

    gate_blocker = sync_upgrade._upgrade_write_gate_blocker(check_mode)
    if gate_blocker:
        return _finish(result, "blocked", gate_blocker["message"], gate_blocker["reason_code"], gate_blocker["blocked_stage"])

    if not sync_upgrade._is_valid_kubernetes_version(target_kubernetes_version):
        message = "target_kubernetes_version must be major.minor or major.minor.patch."
        return _finish(result, "blocked", message, "INVALID_TARGET_VERSION", "target_validation")

    upgrades = aks_get_available_upgrades(
        subscription_id,
        resource_group,
        cluster_name,
        include_upgrade_profiles=True,
    )
    result["current_state"] = {
        "control_plane_version": upgrades.get("current_control_plane_version"),
        "node_pools": upgrades.get("current_node_pools", []),
    }

    if upgrades.get("lookup_mode") != "upgrade-profile":
        return _finish(
            result,
            "blocked",
            "Authoritative upgrade-profile lookup was not available.",
            "CONTROL_PLANE_PROFILE_INSUFFICIENT",
            "control_plane_path",
        )

    client = sync_upgrade.get_container_service_client(subscription_id)
    live_cluster = client.managed_clusters.get(resource_group, cluster_name)
    result["control_plane"]["before"] = sync_upgrade._cluster_execution_state(live_cluster)
    live_cluster_state = getattr(live_cluster, "provisioning_state", None)

    if live_cluster_state in _IN_PROGRESS_STATES:
        result["control_plane"]["status"] = "in_progress"
        result["control_plane"]["poller_status"] = live_cluster_state
        return _finish(
            result,
            "in_progress",
            "A control-plane Azure operation is already in progress; no duplicate write was submitted.",
            "CONTROL_PLANE_ALREADY_IN_PROGRESS",
            "control_plane_execution",
        )

    if live_cluster_state in _TERMINAL_FAILURE_STATES:
        return _finish(
            result,
            "failed",
            f"The control-plane Azure operation is in terminal state '{live_cluster_state}'; no automatic retry was submitted.",
            "CONTROL_PLANE_OPERATION_TERMINAL_FAILURE",
            "control_plane_execution",
        )

    live_current_control_plane = (
        getattr(live_cluster, "current_kubernetes_version", None)
        or getattr(live_cluster, "kubernetes_version", None)
    )
    live_control_plane_at_target = (
        live_current_control_plane == target_kubernetes_version
        and live_cluster_state == "Succeeded"
    )

    control_upgrades = upgrades.get("control_plane_upgrades")
    if not live_control_plane_at_target:
        if not isinstance(control_upgrades, list) or not sync_upgrade._profile_offers_target(
            control_upgrades, target_kubernetes_version
        ):
            message = "Target version is not available in the control-plane upgrade profile."
            return _finish(result, "blocked", message, "CONTROL_PLANE_TARGET_UNSUPPORTED", "control_plane_path")

        readiness = sync_upgrade.aks_validate_upgrade_readiness(
            subscription_id=subscription_id,
            resource_group=resource_group,
            cluster_name=cluster_name,
            namespace=namespace,
            maintenance_window_start_utc=maintenance_window_start_utc,
            maintenance_window_end_utc=maintenance_window_end_utc,
            check_mode="full",
            target_kubernetes_version=target_kubernetes_version,
        )
        result["pre_execution_readiness"] = readiness
        if not readiness["readiness"]["is_ready"]:
            blockers = list(readiness["readiness"].get("blockers", []))
            maintenance_blocked = any("maintenance" in blocker.lower() for blocker in blockers)
            return _finish(
                result,
                "blocked",
                blockers[0] if blockers else "Mandatory upgrade readiness checks did not pass.",
                "MAINTENANCE_WINDOW_UNAVAILABLE" if maintenance_blocked else "MANDATORY_READINESS_FAILED",
                "maintenance_window" if maintenance_blocked else "mandatory_readiness",
                blockers=blockers,
            )

        live_cluster.kubernetes_version = target_kubernetes_version
        try:
            poller = sync_upgrade._begin_create_or_update(
                client.managed_clusters.begin_create_or_update,
                (resource_group, cluster_name),
                live_cluster,
            )
        except Exception as exc:  # noqa: BLE001
            return _finish(
                result,
                "failed",
                str(exc),
                "CONTROL_PLANE_UPGRADE_SUBMISSION_FAILED",
                "control_plane_submission",
            )

        result["writes_performed"] = True
        result["write_submission_attempted"] = True
        result["write_accepted"] = True
        result["pollers_created"] = True
        result["control_plane"]["status"] = "started"
        result["control_plane"]["poller_status"] = _safe_poller_status(poller)
        result["next_action"] = "poll_status"
        return _finish(
            result,
            "in_progress",
            "Control-plane upgrade submitted successfully. Poll aks_get_upgrade_execution_status before advancing.",
            "CONTROL_PLANE_UPGRADE_STARTED",
            "control_plane_execution",
        )

    # Control plane is already at target. For control-plane-only approval, verify only the control plane.
    if confirmed_scope == "control_plane_only":
        verification = _safe_post_execution_snapshot(
            subscription_id, resource_group, cluster_name, target_kubernetes_version, include_node_pools=False
        )
        result["post_upgrade_verification"] = verification
        if not verification["is_successful"]:
            return _finish(
                result,
                "failed",
                verification["message"],
                "POST_UPGRADE_VERIFICATION_FAILED",
                "post_upgrade_verification",
            )
        result["next_action"] = None
        return _finish(
            result,
            "completed",
            "Control-plane upgrade is at the target and the confirmed scope excludes node pools.",
            "CONTROL_PLANE_ONLY_SCOPE",
            None,
        )

    # Complete-cluster flow: refresh node-pool evidence only after control-plane target is observed.
    refreshed = aks_get_available_upgrades(
        subscription_id,
        resource_group,
        cluster_name,
        include_upgrade_profiles=True,
    )
    result["node_pool_profile_after_control_plane"] = sync_upgrade._pool_profile_snapshot(refreshed)
    pools = refreshed.get("current_node_pools", [])
    profiles = refreshed.get("node_pool_upgrades", {})
    evidence_map = refreshed.get("node_pool_upgrade_profile_evidence", {})

    # Re-run the mandatory checks before beginning the second phase.
    readiness = sync_upgrade.aks_validate_upgrade_readiness(
        subscription_id=subscription_id,
        resource_group=resource_group,
        cluster_name=cluster_name,
        namespace=namespace,
        maintenance_window_start_utc=maintenance_window_start_utc,
        maintenance_window_end_utc=maintenance_window_end_utc,
        check_mode="full",
        target_kubernetes_version=target_kubernetes_version,
    )
    result["pre_node_pool_readiness"] = readiness
    if not readiness["readiness"]["is_ready"]:
        blockers = list(readiness["readiness"].get("blockers", []))
        return _finish(
            result,
            "blocked",
            blockers[0] if blockers else "Mandatory readiness checks did not pass before node-pool execution.",
            "MANDATORY_READINESS_FAILED",
            "mandatory_readiness",
            blockers=blockers,
        )

    for pool_summary in pools:
        pool_name = pool_summary.get("name")
        evidence = evidence_map.get(pool_name, {})
        profile = profiles.get(pool_name) if isinstance(profiles, dict) else None
        path_status = sync_upgrade._node_pool_path_status(evidence, profile, target_kubernetes_version)
        pool = client.agent_pools.get(resource_group, cluster_name, pool_name)
        pool_result = {
            "name": pool_name,
            "path_status": path_status,
            "status": "skipped",
            "before": sync_upgrade._pool_execution_state(pool),
            "after": None,
            "error": None,
            "evidence": evidence,
        }

        live_pool_state = getattr(pool, "provisioning_state", None)
        live_pool_version = (
            getattr(pool, "current_orchestrator_version", None)
            or getattr(pool, "orchestrator_version", None)
        )
        if live_pool_state in _IN_PROGRESS_STATES:
            pool_result["status"] = "in_progress"
            pool_result["poller_status"] = live_pool_state
            result["node_pools"].append(pool_result)
            result["next_action"] = "poll_status"
            return _finish(
                result,
                "in_progress",
                f"Node-pool '{pool_name}' upgrade is already in progress; no duplicate write was submitted.",
                "NODE_POOL_ALREADY_IN_PROGRESS",
                "node_pool_execution",
            )

        if live_pool_state in _TERMINAL_FAILURE_STATES:
            pool_result["status"] = "failed"
            pool_result["error"] = f"Azure reports terminal provisioning state '{live_pool_state}'."
            result["node_pools"].append(pool_result)
            return _finish(
                result,
                "partial",
                f"Node-pool '{pool_name}' is in terminal Azure state '{live_pool_state}'; no automatic retry was submitted.",
                "NODE_POOL_OPERATION_TERMINAL_FAILURE",
                "node_pool_execution",
            )

        if live_pool_version == target_kubernetes_version and live_pool_state == "Succeeded":
            pool_result["status"] = "completed"
            pool_result["path_status"] = "NOT_REQUIRED"
            pool_result["after"] = sync_upgrade._pool_execution_state(pool)
            result["node_pools"].append(pool_result)
            continue

        result["node_pools"].append(pool_result)

        if path_status != "SUPPORTED":
            message = (
                f"Node-pool upgrade evidence is insufficient for '{pool_name}'; Azure has not provided enough evidence to prove the path."
                if path_status == "INSUFFICIENT_EVIDENCE"
                else f"Target version is not available in the upgrade profile for node pool '{pool_name}'."
            )
            result["next_action"] = None
            return _finish(
                result,
                "partial",
                message,
                "NODE_POOL_PROFILE_INSUFFICIENT" if path_status == "INSUFFICIENT_EVIDENCE" else "NODE_POOL_TARGET_UNSUPPORTED",
                "node_pool_path",
            )

        pool.orchestrator_version = target_kubernetes_version
        try:
            poller = sync_upgrade._begin_create_or_update(
                client.agent_pools.begin_create_or_update,
                (resource_group, cluster_name, pool_name),
                pool,
            )
        except Exception as exc:  # noqa: BLE001
            pool_result["status"] = "failed"
            pool_result["error"] = str(exc)
            return _finish(
                result,
                "failed",
                str(exc),
                "NODE_POOL_UPGRADE_SUBMISSION_FAILED",
                "node_pool_submission",
            )

        result["writes_performed"] = True
        result["write_submission_attempted"] = True
        result["write_accepted"] = True
        result["pollers_created"] = True
        pool_result["status"] = "started"
        pool_result["poller_status"] = _safe_poller_status(poller)
        result["next_action"] = "poll_status"
        return _finish(
            result,
            "in_progress",
            f"Node-pool '{pool_name}' upgrade submitted successfully. Poll aks_get_upgrade_execution_status before advancing.",
            "NODE_POOL_UPGRADE_STARTED",
            "node_pool_execution",
        )

    verification = _safe_post_execution_snapshot(
        subscription_id, resource_group, cluster_name, target_kubernetes_version, include_node_pools=True
    )
    result["post_upgrade_verification"] = verification
    if not verification["is_successful"]:
        return _finish(
            result,
            "failed",
            verification["message"],
            "POST_UPGRADE_VERIFICATION_FAILED",
            "post_upgrade_verification",
        )
    result["next_action"] = None
    return _finish(result, "completed", "Complete-cluster upgrade verification succeeded.", "UPGRADE_COMPLETED", None)


def _active_execution_state(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    target: str,
    scope: str,
) -> str:
    """Classify an active key conservatively from fresh Azure resource state."""
    client = sync_upgrade.get_container_service_client(subscription_id)
    cluster = client.managed_clusters.get(resource_group, cluster_name)
    cluster_state = getattr(cluster, "provisioning_state", None)
    cluster_version = (
        getattr(cluster, "current_kubernetes_version", None)
        or getattr(cluster, "kubernetes_version", None)
    )
    if cluster_state in _TERMINAL_FAILURE_STATES:
        return "terminal_failure"
    if cluster_state in _IN_PROGRESS_STATES:
        return "running"
    if cluster_state != "Succeeded" or cluster_version != target:
        return "running"
    if scope == "control_plane_only":
        return "ready_to_advance"

    pools = list(client.agent_pools.list(resource_group, cluster_name))
    for pool in pools:
        pool_state = getattr(pool, "provisioning_state", None)
        if pool_state in _TERMINAL_FAILURE_STATES:
            return "terminal_failure"
        if pool_state in _IN_PROGRESS_STATES:
            return "running"
        pool_version = (
            getattr(pool, "current_orchestrator_version", None)
            or getattr(pool, "orchestrator_version", None)
        )
        if pool_state != "Succeeded" or pool_version != target:
            return "ready_to_advance"
    return "ready_to_advance"


def _safe_poller_status(poller: Any) -> str | None:
    try:
        return str(poller.status())
    except Exception:  # pragma: no cover - defensive only
        return None


def _safe_post_execution_snapshot(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    target: str,
    *,
    include_node_pools: bool,
) -> dict[str, Any]:
    try:
        cluster = aks_get_cluster_details(subscription_id, resource_group, cluster_name)
        pools = aks_get_node_pools(subscription_id, resource_group, cluster_name) if include_node_pools else {"node_pools": []}
        if cluster.get("kubernetes_version") != target or cluster.get("provisioning_state") != "Succeeded":
            return {"is_successful": False, "message": "Control plane is not yet at the target version with Succeeded provisioning state."}
        if include_node_pools:
            for pool in pools.get("node_pools", []):
                if pool.get("orchestrator_version") != target or pool.get("provisioning_state") != "Succeeded":
                    return {"is_successful": False, "message": f"Node pool '{pool.get('name')}' is not yet at the target version with Succeeded provisioning state."}
        return {"is_successful": True, "message": "Final version and provisioning-state verification succeeded.", "cluster": cluster, "node_pools": pools.get("node_pools", [])}
    except Exception as exc:  # noqa: BLE001
        return {"is_successful": False, "message": str(exc)}


def _result(target: str, scope: str) -> dict[str, Any]:
    return {
        "status": "blocked",
        "blocked_stage": None,
        "reason_code": None,
        "message": None,
        "writes_performed": False,
        "write_submission_attempted": False,
        "write_accepted": False,
        "pollers_created": False,
        "cluster_modified": False,
        "target_kubernetes_version": target,
        "execution_scope": scope,
        "current_state": None,
        "pre_execution_readiness": None,
        "pre_node_pool_readiness": None,
        "control_plane": {"status": "not_required", "poller_status": None, "before": None, "after": None, "error": None},
        "node_pool_profile_after_control_plane": None,
        "node_pools": [],
        "post_upgrade_verification": None,
        "next_action": None,
        "blockers": [],
        "warnings": [],
    }


def _finish(
    result: dict[str, Any],
    status: str,
    message: str,
    reason_code: str,
    blocked_stage: str | None,
    *,
    blockers: list[str] | None = None,
) -> dict[str, Any]:
    result["status"] = status
    result["message"] = message
    result["reason_code"] = reason_code
    if blocked_stage is not None:
        result["blocked_stage"] = blocked_stage
    if blockers is not None:
        result["blockers"] = blockers
    elif status in {"blocked", "partial", "failed"}:
        result["blockers"] = [message]
    return result
