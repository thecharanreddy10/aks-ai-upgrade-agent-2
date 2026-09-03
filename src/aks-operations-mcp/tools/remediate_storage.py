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
    approval_token: str | None = None,
    check_mode: str = "quick",
) -> dict[str, Any]:
    """Execute a storage remediation plan to unblock upgrade-readiness issues.

    Strategies:
    - cleanup_pvc: Delete unbound PVCs in Terminating state (namespace-scoped).
                   Allows finalizers to complete and reclaim policies to work.
    - cleanup_pv: Find orphaned PersistentVolumes (cluster-scoped).
                  Gracefully delete or mark for cleanup.

    Returns a plan with exact kubectl commands. No cluster writes unless
    dry_run=False + approval gates pass.
    """
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
    else:  # cleanup_pv
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
            "message": "Plan only; no cluster changes. Pass dry_run=False + approval_token to apply.",
        }

    require_remediation_approval(check_mode, approval_token, namespace=namespace)

    return _apply_plan(
        subscription_id,
        resource_group,
        cluster_name,
        namespace,
        storage_name,
        plan,
        strategy,
    )


def _plan_cleanup_pvc(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str,
    pvc_name: str | None,
) -> dict[str, Any]:
    """Plan cleaning up unbound PersistentVolumeClaims in Terminating state."""
    if pvc_name:
        pvc_payload = run_kubectl_json(
            subscription_id,
            resource_group,
            cluster_name,
            f"get pvc {pvc_name} -n {namespace}",
        )
        if not pvc_payload or pvc_payload.get("kind") != "PersistentVolumeClaim":
            return {"error": f"PVC {namespace}/{pvc_name} not found."}

        pvcs = [pvc_payload]
    else:
        all_pvcs = run_kubectl_json(
            subscription_id,
            resource_group,
            cluster_name,
            f"get pvc -n {namespace} -o json",
        )
        pvcs = [
            pvc
            for pvc in all_pvcs.get("items", [])
            if pvc.get("metadata", {}).get("deletionTimestamp")
        ]

    if not pvcs:
        return {
            "status": "no_action",
            "message": f"No PVCs in Terminating state found in {namespace}.",
        }

    steps = []
    for pvc in pvcs:
        pvc_name = pvc.get("metadata", {}).get("name")
        steps.append({
            "type": "delete_pvc",
            "kind": "PersistentVolumeClaim",
            "name": pvc_name,
            "namespace": namespace,
            "kubectl_command": f"kubectl delete pvc {pvc_name} -n {namespace} --grace-period=30",
            "force_delete_command": f"kubectl delete pvc {pvc_name} -n {namespace} --grace-period=0 --force",
            "description": "Delete unbound PVC; allow reclaim policy (Delete/Retain) to take effect.",
        })

    return {
        "strategy": "cleanup_pvc",
        "namespace": namespace,
        "pvcs_to_delete": len(steps),
        "steps": steps,
        "post_verification": {
            "command": f"kubectl get pvc -n {namespace} --field-selector metadata.deletionTimestamp!='' --no-headers | wc -l",
            "expected": "0 (all Terminating PVCs resolved)",
        },
    }


def _plan_cleanup_pv(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    pv_name: str | None,
) -> dict[str, Any]:
    """Plan cleaning up orphaned/stuck PersistentVolumes."""
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

    stuck_pvs = []
    for pv in pvs:
        status = pv.get("status", {}).get("phase")
        claim_ref = pv.get("spec", {}).get("claimRef")
        if status in ("Failed", "Released") or (
            status == "Bound" and not claim_ref
        ):
            stuck_pvs.append(pv)

    if not stuck_pvs:
        return {
            "status": "no_action",
            "message": "No orphaned or stuck PersistentVolumes found.",
        }

    steps = []
    for pv in stuck_pvs:
        pv_name = pv.get("metadata", {}).get("name")
        reclaim = pv.get("spec", {}).get("persistentVolumeReclaimPolicy", "Retain")
        steps.append({
            "type": "delete_pv",
            "kind": "PersistentVolume",
            "name": pv_name,
            "reclaim_policy": reclaim,
            "kubectl_command": f"kubectl delete pv {pv_name}",
            "description": f"Delete orphaned PV; reclaim policy is {reclaim}.",
        })

    return {
        "strategy": "cleanup_pv",
        "scope": "cluster_wide",
        "pvs_to_delete": len(steps),
        "steps": steps,
        "post_verification": {
            "command": "kubectl get pv --field-selector status.phase=Failed,status.phase=Released --no-headers | wc -l",
            "expected": "0 (all orphaned PVs deleted or recovered)",
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
        return {
            "status": "failed",
            "reason": plan["error"],
        }

    if plan.get("status") == "no_action":
        return plan

    applied_changes = []
    try:
        for step in plan.get("steps", []):
            command = step.get("kubectl_command")
            raw_logs = run_kubectl_raw(subscription_id, resource_group, cluster_name, command)
            applied_changes.append(
                {
                    "type": step.get("type"),
                    "kind": step.get("kind"),
                    "name": step.get("name"),
                    "description": step.get("description"),
                    "output": raw_logs[:200],
                }
            )
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
