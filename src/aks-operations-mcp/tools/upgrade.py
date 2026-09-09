"""Upgrade tools for AKS operations with built-in safety guardrails."""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any, Callable

from tools.common import get_container_service_client
from tools.deprecated_apis import aks_check_deprecated_apis
from tools.discovery import aks_get_available_upgrades, aks_get_cluster_details, aks_get_node_pools
from tools.storage import aks_check_storage
from tools.validation import (
    aks_check_node_health,
    aks_check_pdb,
    aks_check_pod_health,
)


_KUBERNETES_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?$")


def aks_get_upgrade_execution_status(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
) -> dict[str, Any]:
    """Return a read-only snapshot of AKS upgrade execution state."""
    client = get_container_service_client(subscription_id)
    cluster = client.managed_clusters.get(resource_group, cluster_name)
    pools = list(client.agent_pools.list(resource_group, cluster_name))
    return {
        "subscription_id": subscription_id,
        "resource_group": resource_group,
        "cluster_name": cluster_name,
        "cluster": _cluster_execution_state(cluster),
        "node_pools": [_pool_execution_state(pool) for pool in pools],
    }


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
    is_user_confirmed: bool = False,
) -> dict[str, Any]:
    """Execute a previously user-confirmed AKS upgrade and verify its outcome.

    This tool enforces explicit user confirmation as a required authorization gate.
    The calling agent must:
    1. Obtain explicit user confirmation before invoking this tool
    2. Pass is_user_confirmed=True to signal that confirmation has been received
    3. Supply the confirmed_scope (control_plane_only or complete_cluster)

    The server enforces multiple safety gates:
    - Explicit user confirmation (is_user_confirmed=True)
    - Environment-level write capability (AKS_UPGRADE_ENABLE_WRITE=true)
    - Full mode checks (check_mode='full')
    - Valid target version
    - Supported control-plane upgrade path
    - Mandatory readiness checks
    - Scope-based node-pool execution control

    Args:
        is_user_confirmed: Must be True to proceed with execution. False blocks all writes.
            Represents explicit user confirmation obtained in the Agent Interface.
        confirmed_scope: The user-confirmed execution scope. Either "complete_cluster" (control plane
            and node pools if SUPPORTED) or "control_plane_only" (control plane only, no node-pool
            writes regardless of profile state). Node-pool execution requires explicit scope authorization.
    """
    result = _execution_result(target_kubernetes_version)

    # Explicit confirmation is required before any write operation.
    if not is_user_confirmed:
        message = "Upgrade execution requires explicit user confirmation (is_user_confirmed=True)."
        return _finish_execution(
            result, "blocked", [message],
            blocked_stage="authorization",
            reason_code="EXECUTION_CONFIRMATION_REQUIRED",
            message=message,
        )

    gate_blocker = _upgrade_write_gate_blocker(check_mode)
    if gate_blocker:
        return _finish_execution(result, "blocked", [gate_blocker["message"]], **gate_blocker)
    if not _is_valid_kubernetes_version(target_kubernetes_version):
        message = "target_kubernetes_version must be major.minor or major.minor.patch."
        return _finish_execution(
            result, "blocked", [message], blocked_stage="target_validation",
            reason_code="INVALID_TARGET_VERSION", message=message,
        )

    # Fresh discovery is deliberately performed before readiness and every write.
    upgrades = aks_get_available_upgrades(
        subscription_id, resource_group, cluster_name, include_upgrade_profiles=True
    )
    current_control_plane = upgrades.get("current_control_plane_version")
    pools_before = upgrades.get("current_node_pools", [])
    result["control_plane"]["before"] = {
        "kubernetes_version": current_control_plane,
    }

    profile_errors = list(upgrades.get("upgrade_profile_errors", []))
    control_profile_errors = [error for error in profile_errors if error.startswith("control-plane")]
    control_upgrades = upgrades.get("control_plane_upgrades")
    control_plane_supported = (
        current_control_plane == target_kubernetes_version
        or (isinstance(control_upgrades, list) and _profile_offers_target(control_upgrades, target_kubernetes_version))
    )
    if upgrades.get("lookup_mode") != "upgrade-profile" or control_profile_errors or not control_plane_supported:
        blockers = control_profile_errors or ["Target version is not available in the control-plane upgrade profile."]
        insufficient = upgrades.get("lookup_mode") != "upgrade-profile" or bool(control_profile_errors)
        return _finish_execution(
            result, "blocked", blockers, blocked_stage="control_plane_path",
            reason_code="CONTROL_PLANE_PROFILE_INSUFFICIENT" if insufficient else "CONTROL_PLANE_TARGET_UNSUPPORTED",
            message=blockers[0],
        )

    readiness = aks_validate_upgrade_readiness(
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
        return _finish_execution(
            result,
            "blocked",
            blockers,
            list(readiness["readiness"].get("warnings", [])),
            blocked_stage="maintenance_window" if maintenance_blocked else "mandatory_readiness",
            reason_code="MAINTENANCE_WINDOW_UNAVAILABLE" if maintenance_blocked else "MANDATORY_READINESS_FAILED",
            message=blockers[0] if blockers else "Mandatory upgrade readiness checks did not pass.",
        )

    client = get_container_service_client(subscription_id)
    if current_control_plane != target_kubernetes_version:
        full_cluster = client.managed_clusters.get(resource_group, cluster_name)
        result["control_plane"]["before"] = _cluster_execution_state(full_cluster)
        full_cluster.kubernetes_version = target_kubernetes_version
        try:
            result["writes_performed"] = True
            result["write_submission_attempted"] = True
            poller = _begin_create_or_update(
                client.managed_clusters.begin_create_or_update,
                (resource_group, cluster_name),
                full_cluster,
            )
            result["write_accepted"] = True
            result["pollers_created"] = True
            result["control_plane"]["status"] = "started"
            result["control_plane"]["poller_status"] = poller.status()
            poller.result()
            refreshed_cluster = client.managed_clusters.get(resource_group, cluster_name)
            result["control_plane"]["after"] = _cluster_execution_state(refreshed_cluster)
            if not _cluster_at_target(refreshed_cluster, target_kubernetes_version):
                raise RuntimeError("Control-plane operation completed without the expected succeeded state and target version.")
            result["control_plane"]["status"] = "succeeded"
            result["cluster_modified"] = True
        except Exception as exc:  # noqa: BLE001
            result["control_plane"]["status"] = "failed"
            result["control_plane"]["error"] = str(exc)
            return _finish_execution_with_current_state(
                result, "failed", subscription_id, resource_group, cluster_name, [str(exc)],
                blocked_stage="control_plane_submission", reason_code="CONTROL_PLANE_UPGRADE_FAILED",
                message=str(exc),
            )
    else:
        result["control_plane"]["status"] = "not_required"
        result["control_plane"]["after"] = result["control_plane"]["before"]

    # Enforce execution scope: do not perform node-pool writes if scope is "control_plane_only".
    if confirmed_scope == "control_plane_only":
        result["node_pool_profile_after_control_plane"] = None
        result["node_pools"] = []
        result["execution_scope"] = "control_plane_only"
        return _finish_execution(
            result, "completed", [], [],
            blocked_stage=None,
            reason_code="CONTROL_PLANE_ONLY_SCOPE",
            message="Control-plane upgrade completed. Node-pool execution was outside the confirmed scope.",
        )

    # Azure may expose a pool path only after the control-plane operation. Never reuse Phase 1 data.
    refreshed_upgrades = aks_get_available_upgrades(
        subscription_id, resource_group, cluster_name, include_upgrade_profiles=True
    )
    result["node_pool_profile_after_control_plane"] = _pool_profile_snapshot(refreshed_upgrades)
    refreshed_pools = refreshed_upgrades.get("current_node_pools", [])
    pool_profiles = refreshed_upgrades.get("node_pool_upgrades", {})
    pool_evidence = refreshed_upgrades.get("node_pool_upgrade_profile_evidence", {})

    for pool_summary in refreshed_pools:
        pool_name = pool_summary.get("name")
        before = dict(pool_summary)
        if pool_summary.get("orchestrator_version") == target_kubernetes_version:
            result["node_pools"].append({
                "name": pool_name,
                "path_status": "NOT_REQUIRED",
                "status": "not_required",
                "before": before,
                "after": before,
                "error": None,
            })
            continue

        evidence = pool_evidence.get(pool_name)
        profile = pool_profiles.get(pool_name) if isinstance(pool_profiles, dict) else None
        if not isinstance(evidence, dict):
            evidence = {
                "profile_available": isinstance(profile, list),
                "upgrades_field_present": isinstance(profile, list),
                "upgrade_versions": [item.get("kubernetes_version") for item in profile] if isinstance(profile, list) else [],
                "error": None,
            }
        path_status = _node_pool_path_status(evidence, profile, target_kubernetes_version)
        pool_result = {
            "name": pool_name,
            "path_status": path_status,
            "status": "skipped",
            "before": before,
            "after": None,
            "error": None,
            "evidence": evidence,
        }
        result["node_pools"].append(pool_result)
        if path_status != "SUPPORTED":
            explanation = (
                f"Node-pool upgrade profile evidence is insufficient for '{pool_name}'; Azure has not provided enough evidence to prove the path."
                if path_status == "INSUFFICIENT_EVIDENCE"
                else f"Target version is not available in the upgrade profile for node pool '{pool_name}'."
            )
            return _finish_execution_with_current_state(
                result,
                "partial" if _has_completed_write(result) else "blocked",
                subscription_id,
                resource_group,
                cluster_name,
                [explanation],
                blocked_stage="node_pool_path",
                reason_code=("NODE_POOL_PROFILE_INSUFFICIENT" if path_status == "INSUFFICIENT_EVIDENCE"
                             else "NODE_POOL_TARGET_UNSUPPORTED"),
                message=explanation,
            )

        full_pool = client.agent_pools.get(resource_group, cluster_name, pool_name)
        pool_result["before"] = _pool_execution_state(full_pool)
        full_pool.orchestrator_version = target_kubernetes_version
        pool_result["status"] = "started"
        try:
            result["writes_performed"] = True
            result["write_submission_attempted"] = True
            poller = _begin_create_or_update(
                client.agent_pools.begin_create_or_update,
                (resource_group, cluster_name, pool_name),
                full_pool,
            )
            result["write_accepted"] = True
            result["pollers_created"] = True
            pool_result["poller_status"] = poller.status()
            poller.result()
            refreshed_pool = client.agent_pools.get(resource_group, cluster_name, pool_name)
            pool_result["after"] = _pool_execution_state(refreshed_pool)
            if not _pool_at_target(refreshed_pool, target_kubernetes_version):
                raise RuntimeError("Node-pool operation completed without the expected succeeded state and target version.")
            pool_result["status"] = "succeeded"
        except Exception as exc:  # noqa: BLE001
            pool_result["status"] = "failed"
            pool_result["error"] = str(exc)
            return _finish_execution_with_current_state(
                result, "partial" if _has_completed_write(result) else "failed",
                subscription_id, resource_group, cluster_name, [str(exc)],
                blocked_stage="node_pool_execution", reason_code="NODE_POOL_UPGRADE_FAILED", message=str(exc),
            )

    verification = _post_upgrade_verification(
        subscription_id, resource_group, cluster_name, target_kubernetes_version,
        namespace, maintenance_window_start_utc, maintenance_window_end_utc,
    )
    result["post_upgrade_verification"] = verification
    if not verification["is_successful"]:
        return _finish_execution(
            result, "failed", verification["blockers"], verification["warnings"],
            blocked_stage="post_upgrade_verification", reason_code="POST_UPGRADE_VERIFICATION_FAILED",
            message=verification["blockers"][0] if verification["blockers"] else "Post-upgrade verification failed.",
        )
    return _finish_execution(result, "completed", [], verification["warnings"])


def _upgrade_write_gate_blocker(check_mode: str) -> dict[str, str] | None:
    """Return an expected pre-write gate refusal without creating an Azure client."""
    if check_mode != "full":
        return {
            "blocked_stage": "execution_gate",
            "reason_code": "CHECK_MODE_NOT_FULL",
            "message": "Upgrade write operations require check_mode='full'.",
        }
    if os.getenv("AKS_UPGRADE_ENABLE_WRITE", "false").lower() != "true":
        return {
            "blocked_stage": "execution_gate",
            "reason_code": "UPGRADE_WRITE_DISABLED",
            "message": "Upgrade execution is disabled because AKS_UPGRADE_ENABLE_WRITE is not enabled.",
        }
    return None


def _begin_create_or_update(
    operation: Callable[..., Any], identifiers: tuple[str, ...], resource: Any,
) -> Any:
    """Submit a standard SDK create-or-update call without an explicit optimistic-concurrency condition."""
    try:
        return operation(*identifiers, parameters=resource)
    except TypeError:
        return operation(*identifiers, resource)


def _cluster_execution_state(cluster: Any) -> dict[str, Any]:
    return {
        "kubernetes_version": getattr(cluster, "kubernetes_version", None),
        "current_kubernetes_version": getattr(cluster, "current_kubernetes_version", None),
        "provisioning_state": getattr(cluster, "provisioning_state", None),
    }


def _pool_execution_state(pool: Any) -> dict[str, Any]:
    return {
        "name": getattr(pool, "name", None),
        "orchestrator_version": getattr(pool, "orchestrator_version", None),
        "current_orchestrator_version": getattr(pool, "current_orchestrator_version", None),
        "provisioning_state": getattr(pool, "provisioning_state", None),
        "node_image_version": getattr(pool, "node_image_version", None),
    }


def _cluster_at_target(cluster: Any, target: str) -> bool:
    state = _cluster_execution_state(cluster)
    observed = state["current_kubernetes_version"] or state["kubernetes_version"]
    return state["provisioning_state"] == "Succeeded" and observed == target


def _pool_at_target(pool: Any, target: str) -> bool:
    state = _pool_execution_state(pool)
    observed = state["current_orchestrator_version"] or state["orchestrator_version"]
    return state["provisioning_state"] == "Succeeded" and observed == target


def _pool_profile_snapshot(upgrades: dict[str, Any]) -> dict[str, Any]:
    return {
        "node_pool_upgrades": upgrades.get("node_pool_upgrades", {}),
        "node_pool_upgrade_profile_evidence": upgrades.get("node_pool_upgrade_profile_evidence", {}),
        "upgrade_profile_errors": upgrades.get("upgrade_profile_errors", []),
    }


def _execution_result(target: str) -> dict[str, Any]:
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
        "execution_scope": "complete_cluster",
        "pre_execution_readiness": None,
        "control_plane": {"status": "not_required", "poller_status": None, "before": None, "after": None, "error": None},
        "node_pool_profile_after_control_plane": None,
        "node_pools": [],
        "post_upgrade_verification": None,
        "blockers": [],
        "warnings": [],
    }


def _finish_execution(
    result: dict[str, Any], status: str, blockers: list[str], warnings: list[str] | None = None,
    *, blocked_stage: str | None = None, reason_code: str | None = None, message: str | None = None,
) -> dict[str, Any]:
    result["status"] = status
    result["blockers"] = blockers
    if warnings is not None:
        result["warnings"] = warnings
    if blocked_stage is not None:
        result["blocked_stage"] = blocked_stage
    if reason_code is not None:
        result["reason_code"] = reason_code
    if message is not None:
        result["message"] = message
    return result


def _finish_execution_with_current_state(
    result: dict[str, Any], status: str, subscription_id: str, resource_group: str,
    cluster_name: str, blockers: list[str],
    *, blocked_stage: str | None = None, reason_code: str | None = None, message: str | None = None,
) -> dict[str, Any]:
    try:
        result["current_execution_status"] = aks_get_upgrade_execution_status(
            subscription_id, resource_group, cluster_name
        )
    except Exception as exc:  # noqa: BLE001
        result["current_execution_status_error"] = str(exc)
    return _finish_execution(
        result, status, blockers, blocked_stage=blocked_stage, reason_code=reason_code, message=message,
    )


def _has_completed_write(result: dict[str, Any]) -> bool:
    return result["control_plane"]["status"] == "succeeded" or any(
        pool.get("status") == "succeeded" for pool in result["node_pools"]
    )


def _post_upgrade_verification(
    subscription_id: str, resource_group: str, cluster_name: str, target: str,
    namespace: str | None, maintenance_window_start_utc: str | None,
    maintenance_window_end_utc: str | None,
) -> dict[str, Any]:
    cluster = aks_get_cluster_details(subscription_id, resource_group, cluster_name)
    pools = aks_get_node_pools(subscription_id, resource_group, cluster_name)
    readiness = aks_validate_upgrade_readiness(
        subscription_id, resource_group, cluster_name, namespace=namespace,
        maintenance_window_start_utc=maintenance_window_start_utc,
        maintenance_window_end_utc=maintenance_window_end_utc, check_mode="full",
        target_kubernetes_version=target,
    )
    blockers = list(readiness["readiness"].get("blockers", []))
    if cluster.get("kubernetes_version") != target or cluster.get("provisioning_state") != "Succeeded":
        blockers.append("Control plane did not report the expected target version and Succeeded provisioning state.")
    for pool in pools.get("node_pools", []):
        if pool.get("orchestrator_version") != target or pool.get("provisioning_state") != "Succeeded":
            blockers.append(f"Node pool '{pool.get('name')}' did not report the expected target version and Succeeded provisioning state.")
    return {
        "cluster": cluster,
        "node_pools": pools,
        "readiness": readiness,
        "blockers": blockers,
        "warnings": list(readiness["readiness"].get("warnings", [])),
        "is_successful": not blockers,
    }


def aks_plan_upgrade_preparation(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    target_kubernetes_version: str,
    namespace: str | None = None,
    maintenance_window_start_utc: str | None = None,
    maintenance_window_end_utc: str | None = None,
) -> dict[str, Any]:
    """Create a read-only, mandatory-check-only AKS upgrade preparation plan.

    The tool does not perform an upgrade, invoke remediation, or run optional
    smooth-upgrade validations. A later Phase 2 operation must obtain explicit
    user confirmation and enforce its own write gates.
    """
    target_validation: dict[str, Any] = {
        "requested_version": target_kubernetes_version,
        "is_syntactically_valid": _is_valid_kubernetes_version(target_kubernetes_version),
        "is_available": False,
        "control_plane_path_supported": False,
        "node_pool_paths_supported": False,
        "node_pool_path_evidence_sufficient": False,
        "errors": [],
    }
    if not target_validation["is_syntactically_valid"]:
        target_validation["errors"].append(
            "target_kubernetes_version must be major.minor or major.minor.patch."
        )
        return _preparation_result(
            "blocked", target_validation, {}, [], {}, [], target_validation["errors"], [], None
        )

    upgrades = aks_get_available_upgrades(
        subscription_id,
        resource_group,
        cluster_name,
        include_upgrade_profiles=True,
    )
    current_state = {
        "control_plane_version": upgrades.get("current_control_plane_version"),
        "node_pools": upgrades.get("current_node_pools", []),
    }
    profile_errors = list(upgrades.get("upgrade_profile_errors", []))
    control_plane_profile_errors = [error for error in profile_errors if error.startswith("control-plane")]
    if upgrades.get("lookup_mode") != "upgrade-profile" or control_plane_profile_errors:
        target_validation["errors"].append(
            "Authoritative AKS upgrade-profile data is incomplete or unavailable."
        )
        target_validation["errors"].extend(control_plane_profile_errors)
        return _preparation_result(
            "blocked", target_validation, current_state, current_state["node_pools"], {}, [],
            target_validation["errors"], [], None,
        )

    pools = current_state["node_pools"]
    control_plane_current = current_state["control_plane_version"]
    affected_pools = [pool for pool in pools if pool.get("orchestrator_version") != target_kubernetes_version]
    excluded_pools = [pool.get("name") for pool in pools if pool.get("orchestrator_version") == target_kubernetes_version]
    if control_plane_current == target_kubernetes_version and not affected_pools:
        scope = {"control_plane": {"included": False, "reason": "already_at_target"}, "node_pools": [], "excluded_node_pools": excluded_pools}
        return _preparation_result(
            "already_at_target", target_validation, current_state, pools, scope, [], [], [], None
        )

    control_plane_upgrades = upgrades.get("control_plane_upgrades")
    if not isinstance(control_plane_upgrades, list):
        target_validation["errors"].append("Control-plane upgrade profile is missing.")
    elif control_plane_current != target_kubernetes_version:
        target_validation["control_plane_path_supported"] = _profile_offers_target(
            control_plane_upgrades, target_kubernetes_version
        )
        if not target_validation["control_plane_path_supported"]:
            target_validation["errors"].append("Target version is not available in the control-plane upgrade profile.")
    else:
        target_validation["control_plane_path_supported"] = True

    pool_profiles = upgrades.get("node_pool_upgrades")
    pool_profile_evidence = upgrades.get("node_pool_upgrade_profile_evidence", {})
    if not isinstance(pool_profiles, dict):
        target_validation["errors"].append("Node-pool upgrade profiles are missing.")
    else:
        pool_path_evidence = []
        for pool in affected_pools:
            name = pool.get("name")
            profile = pool_profiles.get(name)
            evidence = pool_profile_evidence.get(name)
            if not isinstance(evidence, dict):
                evidence = {
                    "profile_available": isinstance(profile, list),
                    "upgrades_field_present": isinstance(profile, list),
                    "upgrade_versions": [item.get("kubernetes_version") for item in profile] if isinstance(profile, list) else [],
                    "error": None,
                }
            path_status = _node_pool_path_status(evidence, profile, target_kubernetes_version)
            pool_path_evidence.append({
                "name": name,
                "current_version": pool.get("orchestrator_version"),
                "target_version": target_kubernetes_version,
                "path_status": path_status,
                "evidence": evidence,
            })
        insufficient_pools = [item["name"] for item in pool_path_evidence if item["path_status"] == "INSUFFICIENT_EVIDENCE"]
        unsupported_pools = [item["name"] for item in pool_path_evidence if item["path_status"] == "UNSUPPORTED"]
        target_validation["node_pool_path_evidence_sufficient"] = not insufficient_pools
        target_validation["node_pool_paths_supported"] = not insufficient_pools and not unsupported_pools
        if insufficient_pools:
            target_validation["errors"].append(
                "Node-pool upgrade profile evidence is insufficient for node pool(s): "
                + ", ".join(str(name) for name in insufficient_pools)
                + ". Re-check after the control-plane upgrade before proceeding."
            )
        if unsupported_pools:
            target_validation["errors"].append(
                "Target version is not available in the upgrade profile for node pool(s): "
                + ", ".join(str(name) for name in unsupported_pools)
            )

    # is_available reflects whether the authoritative ARM profile contains the target.
    # It's true if either control plane OR node pools can upgrade to the target.
    target_validation["is_available"] = (
        target_validation["control_plane_path_supported"] or target_validation["node_pool_paths_supported"]
    )
    scope = {
        "control_plane": {
            "included": control_plane_current != target_kubernetes_version,
            "current_version": control_plane_current,
            "target_version": target_kubernetes_version,
        },
        "node_pools": pool_path_evidence if isinstance(pool_profiles, dict) else [],
        "excluded_node_pools": excluded_pools,
    }
    sequence = _upgrade_sequence(scope)
    control_plane_only_candidate = (
        scope["control_plane"]["included"]
        and target_validation["control_plane_path_supported"]
        and bool(insufficient_pools)
        and not unsupported_pools
    )
    if target_validation["errors"] and not control_plane_only_candidate:
        return _preparation_result(
            "blocked", target_validation, current_state, pools, scope, sequence,
            target_validation["errors"], [], None,
        )

    readiness = aks_validate_upgrade_readiness(
        subscription_id=subscription_id,
        resource_group=resource_group,
        cluster_name=cluster_name,
        namespace=namespace,
        maintenance_window_start_utc=maintenance_window_start_utc,
        maintenance_window_end_utc=maintenance_window_end_utc,
        check_mode="full",
        target_kubernetes_version=target_kubernetes_version,
    )
    blockers = list(readiness["readiness"].get("blockers", []))
    warnings = list(readiness["readiness"].get("warnings", []))
    if control_plane_only_candidate:
        warnings.append(
            "Node-pool upgrade profile evidence is insufficient. The control-plane target is "
            "supported, so only a control-plane-first step can be proposed. Node-pool eligibility "
            "must be re-evaluated after the control-plane upgrade."
        )
    if blockers:
        status = "blocked"
    elif control_plane_only_candidate:
        status = "ready_for_control_plane_only"
    else:
        status = "ready_for_confirmation"
    return _preparation_result(
        status, target_validation, current_state, pools, scope, sequence, blockers, warnings, readiness
    )


def _is_valid_kubernetes_version(value: str) -> bool:
    return isinstance(value, str) and bool(_KUBERNETES_VERSION_RE.fullmatch(value))


def _profile_offers_target(profile: list[dict[str, Any]], target: str) -> bool:
    return any(item.get("kubernetes_version") == target for item in profile)


def _node_pool_path_status(evidence: dict[str, Any], profile: Any, target: str) -> str:
    """Classify a pool path without treating absent Azure data as a rejection."""
    if not evidence.get("profile_available") or not evidence.get("upgrades_field_present"):
        return "INSUFFICIENT_EVIDENCE"
    if not isinstance(profile, list):
        return "INSUFFICIENT_EVIDENCE"
    return "SUPPORTED" if _profile_offers_target(profile, target) else "UNSUPPORTED"


def _upgrade_sequence(scope: dict[str, Any]) -> list[dict[str, Any]]:
    sequence: list[dict[str, Any]] = []
    if scope["control_plane"]["included"]:
        sequence.append({"order": 1, "operation": "upgrade_control_plane", "phase": "phase_2"})
    for pool in scope["node_pools"]:
        if pool["path_status"] != "SUPPORTED":
            continue
        sequence.append({
            "order": len(sequence) + 1,
            "operation": "upgrade_node_pool",
            "node_pool_name": pool["name"],
            "phase": "phase_2",
        })
    return sequence


def _preparation_result(
    status: str,
    target_validation: dict[str, Any],
    current_state: dict[str, Any],
    node_pools: list[dict[str, Any]],
    scope: dict[str, Any],
    sequence: list[dict[str, Any]],
    blockers: list[str],
    warnings: list[str],
    readiness: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "status": status,
        "target_validation": target_validation,
        "current_cluster_state": current_state,
        "node_pools": node_pools,
        "upgrade_scope": scope,
        "sequence": sequence,
        "readiness": readiness,
        "blockers": blockers,
        "blocker_categories": _blocker_categories(scope),
        "warnings": warnings,
        "confirmation": _confirmation_for_status(status),
        "optional_validations": {
            "run_automatically": False,
            "available_tools": [
                "aks_check_single_replica_services",
                "aks_check_operator_health",
                "aks_check_node_pool_surge",
                "aks_check_priority_class",
            ],
        },
    }


def _confirmation_for_status(status: str) -> dict[str, Any]:
    if status == "ready_for_control_plane_only":
        return {
            "required": True,
            "status": "awaiting_explicit_user_confirmation",
            "scope": "control_plane_only",
            "next_action": (
                "Ask the user whether to proceed with the control-plane upgrade only. After "
                "successful control-plane completion, re-check node-pool upgrade profiles before "
                "any node-pool upgrade."
            ),
        }
    if status == "ready_for_confirmation":
        return {
            "required": True,
            "status": "awaiting_explicit_user_confirmation",
            "scope": "complete_cluster",
        }
    return {"required": False, "status": "not_available"}


def _blocker_categories(scope: dict[str, Any]) -> list[str]:
    statuses = {pool.get("path_status") for pool in scope.get("node_pools", [])}
    categories = []
    if "INSUFFICIENT_EVIDENCE" in statuses:
        categories.append("node_pool_upgrade_profile_insufficient")
    if "UNSUPPORTED" in statuses:
        categories.append("node_pool_upgrade_path_unsupported")
    return categories


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
    """Run pre-upgrade health and safety checks.

    This tool runs only the five mandatory upgrade-readiness checks. Optional upgrade-smoothness
    validations are exposed as separate tools and must be selected explicitly by the agent.

    In "full" mode checks run concurrently to avoid serial AKS Run Command latency.
    """
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
            (
                "node_health",
                "node_health_check_failed",
                lambda: aks_check_node_health(subscription_id, resource_group, cluster_name),
            ),
            (
                "pod_health",
                "pod_health_check_failed",
                lambda: aks_check_pod_health(subscription_id, resource_group, cluster_name, namespace),
            ),
            (
                "pdb_health",
                "pdb_check_failed",
                lambda: aks_check_pdb(subscription_id, resource_group, cluster_name, namespace),
            ),
            (
                "storage_health",
                "storage_health_check_failed",
                lambda: aks_check_storage(subscription_id, resource_group, cluster_name, namespace),
            ),
            (
                "deprecated_api_health",
                "deprecated_api_check_failed",
                lambda: aks_check_deprecated_apis(
                    subscription_id,
                    resource_group,
                    cluster_name,
                    target_version=target_kubernetes_version,
                    namespace=namespace,
                ),
            ),
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
        "maintenance_window": {
            "start_utc": maintenance_window_start_utc,
            "end_utc": maintenance_window_end_utc,
            "in_window": in_window,
        },
        "readiness": {
            "is_ready": len(blockers) == 0,
            "blockers": blockers,
            "warnings": warnings,
        },
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

    Guardrails:
    - Health gates must pass.
    - Defaults to dry-run mode.
    - Non-dry-run requires env gate.
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
        return {
            "status": "blocked",
            "reason": "precheck_failed",
            "requested_upgrade": {
                "cluster_name": cluster_name,
                "node_pool_name": node_pool_name,
                "kubernetes_version": kubernetes_version,
                "dry_run": dry_run,
            },
            "readiness": readiness,
        }

    if dry_run:
        return {
            "status": "dry_run",
            "message": "Prechecks passed. No write operation executed.",
            "requested_upgrade": {
                "cluster_name": cluster_name,
                "node_pool_name": node_pool_name,
                "kubernetes_version": kubernetes_version,
                "dry_run": True,
                "check_mode": check_mode,
            },
            "readiness": readiness,
        }

    if check_mode != "full":
        raise PermissionError("Write operations require check_mode='full'.")

    if os.getenv("AKS_UPGRADE_ENABLE_WRITE", "false").lower() != "true":
        raise PermissionError("Upgrade write operations are disabled. Set AKS_UPGRADE_ENABLE_WRITE=true to enable.")

    client = get_container_service_client(subscription_id)
    pool = client.agent_pools.get(resource_group, cluster_name, node_pool_name)
    pool.orchestrator_version = kubernetes_version

    try:
        poller = client.agent_pools.begin_create_or_update(
            resource_group_name=resource_group,
            resource_name=cluster_name,
            agent_pool_name=node_pool_name,
            parameters=pool,
        )
    except TypeError:
        poller = client.agent_pools.begin_create_or_update(resource_group, cluster_name, node_pool_name, pool)

    return {
        "status": "started",
        "message": "Node pool upgrade request accepted.",
        "requested_upgrade": {
            "cluster_name": cluster_name,
            "node_pool_name": node_pool_name,
            "kubernetes_version": kubernetes_version,
            "dry_run": False,
        },
        "poller_status": poller.status(),
        "readiness": readiness,
    }


def _is_within_maintenance_window(start_utc: str, end_utc: str) -> bool:
    """Return whether current UTC time falls within [start_utc, end_utc].

    Format: HH:MM (24-hour). Supports windows crossing midnight.
    """
    now = datetime.now(UTC).time()
    start = datetime.strptime(start_utc, "%H:%M").time()
    end = datetime.strptime(end_utc, "%H:%M").time()

    if start <= end:
        return start <= now <= end

    return now >= start or now <= end
