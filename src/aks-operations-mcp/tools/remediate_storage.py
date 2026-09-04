"""Remediation tools for storage-related constraints during upgrades.

Strategies:
- cleanup_pvc: Delete unbound PersistentVolumeClaims stuck in Terminating.
  Allows finalizers to complete and reclaim policies to take effect.
- cleanup_pv: Find orphaned/stuck PersistentVolumes (not attached to any node/pod).
  Attempt graceful deletion or mark for cleanup.

Both strategies are storage-specific; namespace scoped where applicable.
"""

from __future__ import annotations

from typing import Any

from tools.common import (
    assert_namespace_not_protected,
    require_remediation_approval,
    run_kubectl_json,
    run_kubectl_raw,
    validate_k8s_name,
    validate_namespace,
)


def aks_remediate_storage(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str | None = None,
    storage_name: str | None = None,
    strategy: str = "cleanup_pvc",
    dry_run: bool = True,
    check_mode: str = "quick",
) -> dict[str, Any]:
    """Execute a storage remediation plan to unblock upgrade-readiness issues."""
    if strategy not in ("cleanup_pvc", "cleanup_pv"):
        raise ValueError(f"Unknown strategy: {strategy!r}")

    if strategy == "cleanup_pvc":
        if not namespace:
            raise ValueError("cleanup_pvc requires namespace parameter.")
        validate_namespace(namespace)
        assert_namespace_not_protected(namespace)
        if storage_name:
            validate_k8s_name(storage_name, "pvc")
        plan = _plan_cleanup_pvc(
            subscription_id, resource_group, cluster_name, namespace, storage_name
        )
    else:
        if storage_name:
            validate_k8s_name(storage_name, "pv")
        plan = _plan_cleanup_pv(
            subscription_id, resource_group, cluster_name, storage_name
        )

    if dry_run:
        return {
            "status": "dry_run",
            "strategy": strategy,
            "scope": {"namespace": namespace} if namespace else {"cluster_wide": True},
            "plan": plan,
            "message": "Plan only; no cluster changes. Pass dry_run=False to apply.",
        }

    require_remediation_approval(check_mode, namespace=namespace)

    return _apply_plan(
        subscription_id,
        resource_group,
        cluster_name,
        namespace,
        storage_name,
        plan,
        strategy,
    )


def _is_terminating_unbound_pvc(pvc: dict[str, Any]) -> bool:
    """Return True only for PVCs that are both terminating and not Bound."""
    metadata = pvc.get("metadata", {})
    phase = pvc.get("status", {}).get("phase")
    return bool(metadata.get("deletionTimestamp")) and phase != "Bound"


def _plan_cleanup_pvc(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str,
    pvc_name: str | None,
) -> dict[str, Any]:
    """Plan cleanup only for terminating, unbound PVCs."""
    if pvc_name:
        pvc_payload = run_kubectl_json(
            subscription_id,
            resource_group,
            cluster_name,
            f"get pvc {pvc_name} -n {namespace}",
        )
        if not pvc_payload or pvc_payload.get("kind") != "PersistentVolumeClaim":
            return {"error": f"PVC {namespace}/{pvc_name} not found."}
        pvcs = [pvc_payload] if _is_terminating_unbound_pvc(pvc_payload) else []
    else:
        all_pvcs = run_kubectl_json(
            subscription_id,
            resource_group,
            cluster_name,
            f"get pvc -n {namespace} -o json",
        )
        pvcs = [
            pvc for pvc in all_pvcs.get("items", []) if _is_terminating_unbound_pvc(pvc)
        ]

    if not pvcs:
        return {
            "status": "no_action",
            "message": f"No terminating, unbound PVCs found in {namespace}.",
        }

    steps = []
    for pvc in pvcs:
        name = pvc.get("metadata", {}).get("name")
        steps.append({
            "type": "delete_pvc",
            "kind": "PersistentVolumeClaim",
            "name": name,
            "namespace": namespace,
            "kubectl_command": f"kubectl delete pvc {name} -n {namespace} --grace-period=30",
            "force_delete_command": f"kubectl delete pvc {name} -n {namespace} --grace-period=0 --force",
            "description": "Delete terminating, unbound PVC; allow reclaim policy to take effect.",
        })

    return {
        "strategy": "cleanup_pvc",
        "namespace": namespace,
        "pvcs_to_delete": len(steps),
        "steps": steps,
        "post_verification": {
            "command": f"kubectl get pvc -n {namespace} -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,DELETING:.metadata.deletionTimestamp --no-headers",
            "expected": "No remaining PVC with a deletion timestamp and non-Bound phase",
        },
    }


def _plan_cleanup_pv(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    pv_name: str | None,
) -> dict[str, Any]:
    """Plan cleanup for PVs in Released or Failed phase only."""
    if pv_name:
        pv_payload = run_kubectl_json(
            subscription_id,
            resource_group,
            cluster_name,
            f"get pv {pv_name}",
        )
        if not pv_payload or pv_payload.get("kind") != "PersistentVolume":
            return {"error": f"PV {pv_name} not found."}
        pvs = [pv_payload]
    else:
        all_pvs = run_kubectl_json(
            subscription_id,
            resource_group,
            cluster_name,
            "get pv -o json",
        )
        pvs = all_pvs.get("items", [])

    stuck_pvs = [
        pv for pv in pvs if pv.get("status", {}).get("phase") in ("Failed", "Released")
    ]

    if not stuck_pvs:
        return {
            "status": "no_action",
            "message": "No orphaned or stuck PersistentVolumes found.",
        }

    steps = []
    for pv in stuck_pvs:
        name = pv.get("metadata", {}).get("name")
        reclaim = pv.get("spec", {}).get("persistentVolumeReclaimPolicy", "Retain")
        steps.append({
            "type": "delete_pv",
            "kind": "PersistentVolume",
            "name": name,
            "reclaim_policy": reclaim,
            "kubectl_command": f"kubectl delete pv {name}",
            "description": f"Delete PV in {pv.get('status', {}).get('phase')} phase; reclaim policy is {reclaim}.",
        })

    return {
        "strategy": "cleanup_pv",
        "scope": "cluster_wide",
        "pvs_to_delete": len(steps),
        "steps": steps,
        "post_verification": {
            "command": "kubectl get pv -o custom-columns=NAME:.metadata.name,PHASE:.status.phase --no-headers | awk '$2==\"Failed\" || $2==\"Released\" {count++} END {print count+0}'",
            "expected": "0",
        },
    }


def _apply_plan(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str | None,
    storage_name: str | None,
    plan: dict[str, Any],
    strategy: str,
) -> dict[str, Any]:
    """Execute the storage remediation plan."""
    if "error" in plan:
        return {"status": "failed", "reason": plan["error"]}

    if plan.get("status") == "no_action":
        return plan

    applied_changes = []
    try:
        for step in plan.get("steps", []):
            command = step.get("kubectl_command")
            raw_logs = run_kubectl_raw(subscription_id, resource_group, cluster_name, command)
            applied_changes.append({
                "type": step.get("type"),
                "kind": step.get("kind"),
                "name": step.get("name"),
                "description": step.get("description"),
                "output": raw_logs[:200],
            })
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "failed",
            "reason": str(exc),
            "applied_changes": applied_changes,
        }

    return {
        "status": "applied",
        "strategy": strategy,
        "scope": {"namespace": namespace} if namespace else {"cluster_wide": True},
        "applied_changes": applied_changes,
        "post_verification": plan.get("post_verification"),
        "message": f"Storage {strategy} applied successfully.",
    }
