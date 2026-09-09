"""Non-blocking AKS upgrade coordinator for long-running Azure operations."""

from __future__ import annotations

from typing import Any

from tools import upgrade as sync_upgrade
from tools.discovery import aks_get_available_upgrades, aks_get_cluster_details, aks_get_node_pools


_IN_PROGRESS_STATES = {"Updating", "Creating", "Deleting", "Accepted", "InProgress", "In Progress"}


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
    """Start or advance a previously user-confirmed AKS upgrade without waiting for Azure LRO completion.

    The calling agent must obtain explicit user approval before invoking this tool. This tool enforces
    the existing MCP write gate and readiness checks, submits at most one long-running Azure operation
    per call, and returns quickly so the agent can poll `aks_get_upgrade_execution_status` and call this
    coordinator again to advance the workflow.

    The workflow is deliberately idempotent against the live Azure state: if a control-plane or node-pool
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

    control_upgrades = upgrades.get("control_plane_upgrades")
    current_control_plane = upgrades.get("current_control_plane_version")
    if current_control_plane != target_kubernetes_version:
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

        client = sync_upgrade.get_container_service_client(subscription_id)
        cluster = client.managed_clusters.get(resource_group, cluster_name)
        result["control_plane"]["before"] = sync_upgrade._cluster_execution_state(cluster)
        provisioning_state = getattr(cluster, "provisioning_state", None)
        if provisioning_state in _IN_PROGRESS_STATES:
            result["control_plane"]["status"] = "in_progress"
            result["control_plane"]["poller_status"] = provisioning_state
            return _finish(
                result,
                "in_progress",
                "Control-plane upgrade is already in progress; no duplicate write was submitted.",
                "CONTROL_PLANE_ALREADY_IN_PROGRESS",
                "control_plane_execution",
            )

        cluster.kubernetes_version = target_kubernetes_version
        try:
            poller = sync_upgrade._begin_create_or_update(
                client.managed_clusters.begin_create_or_update,
                (resource_group, cluster_name),
                cluster,
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

    client = sync_upgrade.get_container_service_client(subscription_id)
    for pool_summary in pools:
        pool_name = pool_summary.get("name")
        observed_version = pool_summary.get("orchestrator_version")
        if observed_version == target_kubernetes_version:
            result["node_pools"].append(
                {"name": pool_name, "status": "completed", "path_status": "NOT_REQUIRED", "before": dict(pool_summary), "after": dict(pool_summary)}
            )
            continue

        evidence = evidence_map.get(pool_name, {})
        profile = profiles.get(pool_name) if isinstance(profiles, dict) else None
        path_status = sync_upgrade._node_pool_path_status(evidence, profile, target_kubernetes_version)
        pool_result = {
            "name": pool_name,
            "path_status": path_status,
            "status": "skipped",
            "before": dict(pool_summary),
            "after": None,
            "error": None,
            "evidence": evidence,
        }
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

        pool = client.agent_pools.get(resource_group, cluster_name, pool_name)
        pool_result["before"] = sync_upgrade._pool_execution_state(pool)
        provisioning_state = getattr(pool, "provisioning_state", None)
        if provisioning_state in _IN_PROGRESS_STATES:
            pool_result["status"] = "in_progress"
            pool_result["poller_status"] = provisioning_state
            result["next_action"] = "poll_status"
            return _finish(
                result,
                "in_progress",
                f"Node-pool '{pool_name}' upgrade is already in progress; no duplicate write was submitted.",
                "NODE_POOL_ALREADY_IN_PROGRESS",
                "node_pool_execution",
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
