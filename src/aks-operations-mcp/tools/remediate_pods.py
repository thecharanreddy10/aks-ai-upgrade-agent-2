"""Remediation tools for unhealthy/stuck pods during upgrades.

Strategies:
- rollout_restart: Restart the Deployment/StatefulSet that owns the pod.
  Triggers a rolling update with new pods. Non-destructive, fully reversible.
- delete_pod: Delete the pod with a configurable grace period so its controller can recreate it.

Neither strategy directly deletes the workload controller.
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


def aks_remediate_pods(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str,
    pod_name: str,
    strategy: str = "rollout_restart",
    dry_run: bool = True,
    check_mode: str = "quick",
) -> dict[str, Any]:
    """Execute a pod remediation plan to unstick unhealthy/pending pods during upgrade.

    Strategies:
    - rollout_restart: Restart the Deployment/StatefulSet that owns the pod.
    - delete_pod: Delete the pod with grace period, triggering pod recreation.

    Returns a plan with exact kubectl commands. No cluster writes unless
    dry_run=False + approval gates pass.
    """
    validate_namespace(namespace)
    validate_k8s_name(pod_name, "pod")
    assert_namespace_not_protected(namespace)

    if strategy not in ("rollout_restart", "delete_pod"):
        raise ValueError(f"Unknown strategy: {strategy!r}")

    pod = _fetch_pod(subscription_id, resource_group, cluster_name, namespace, pod_name)
    if not pod:
        raise ValueError(
            f"Pod {namespace}/{pod_name} not found or could not be queried."
        )

    if strategy == "rollout_restart":
        owner_ref = _resolve_workload_owner(
            subscription_id, resource_group, cluster_name, namespace, pod
        )
        plan = _plan_rollout_restart(namespace, pod, owner_ref=owner_ref)
    else:
        plan = _plan_delete_pod(namespace, pod)

    if dry_run:
        return {
            "status": "dry_run",
            "strategy": strategy,
            "pod": {"namespace": namespace, "name": pod_name},
            "plan": plan,
            "message": "Plan only; no cluster changes. Pass dry_run=False to apply.",
        }

    require_remediation_approval(check_mode, namespace)

    return _apply_plan(
        subscription_id,
        resource_group,
        cluster_name,
        namespace,
        pod_name,
        plan,
        strategy,
    )


def _fetch_pod(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str,
    pod_name: str,
) -> dict[str, Any] | None:
    """Fetch the Pod object from the cluster."""
    payload = run_kubectl_json(
        subscription_id,
        resource_group,
        cluster_name,
        f"get pod {pod_name} -n {namespace}",
    )
    return payload if payload.get("kind") == "Pod" else None


def _resolve_workload_owner(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str,
    pod: dict[str, Any],
) -> dict[str, Any] | None:
    """Resolve a Pod's controller to Deployment/StatefulSet.

    Kubernetes Pods created by a Deployment normally have a ReplicaSet as their
    direct owner, not the Deployment itself. Follow that ReplicaSet's owner
    reference so rollout_restart targets the actual workload controller.
    """
    direct_owner = _find_owner_reference(pod)
    if direct_owner:
        return direct_owner

    owner_refs = pod.get("metadata", {}).get("ownerReferences", [])
    replica_set_ref = next(
        (ref for ref in owner_refs if ref.get("kind") == "ReplicaSet"),
        None,
    )
    if not replica_set_ref:
        return None

    replica_set_name = replica_set_ref.get("name")
    if not replica_set_name:
        return None
    validate_k8s_name(replica_set_name, "ReplicaSet")

    replica_set = run_kubectl_json(
        subscription_id,
        resource_group,
        cluster_name,
        f"get replicaset {replica_set_name} -n {namespace}",
    )
    if replica_set.get("kind") != "ReplicaSet":
        return None

    return _find_owner_reference(replica_set)


def _plan_rollout_restart(
    namespace: str,
    pod: dict[str, Any],
    owner_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Plan restarting the Deployment/StatefulSet that owns this pod."""
    owner_ref = owner_ref or _find_owner_reference(pod)
    all_owners = pod.get("metadata", {}).get("ownerReferences", [])

    if not owner_ref and all_owners:
        other_kind = all_owners[0].get("kind", "Unknown")
        return {
            "error": f"Pod owner is {other_kind}, not Deployment/StatefulSet; cannot rollout restart.",
            "fallback_strategy": "delete_pod",
        }

    if not owner_ref:
        return {
            "error": "Pod has no Deployment or StatefulSet owner; cannot rollout restart.",
            "fallback_strategy": "delete_pod",
        }

    kind = owner_ref.get("kind")
    name = owner_ref.get("name")
    if kind not in ("Deployment", "StatefulSet") or not name:
        return {
            "error": f"Resolved pod owner is {kind or 'Unknown'}, not Deployment/StatefulSet; cannot rollout restart.",
            "fallback_strategy": "delete_pod",
        }

    return {
        "strategy": "rollout_restart",
        "owner": {"kind": kind, "name": name, "namespace": namespace},
        "steps": [
            {
                "type": "rollout_restart",
                "kind": kind,
                "name": name,
                "namespace": namespace,
                "kubectl_command": f"kubectl rollout restart {kind.lower()} {name} -n {namespace}",
                "wait_command": f"kubectl rollout status {kind.lower()} {name} -n {namespace} --timeout=5m",
            }
        ],
        "post_verification": {
            "command": f"kubectl get pod {pod.get('metadata', {}).get('name')} -n {namespace} -o jsonpath='{{.status.phase}}'",
            "expected": "Running",
        },
    }


def _plan_delete_pod(
    namespace: str,
    pod: dict[str, Any],
) -> dict[str, Any]:
    """Plan deleting the pod with grace period for controller recreation."""
    pod_name = pod.get("metadata", {}).get("name")
    grace_period = 30

    return {
        "strategy": "delete_pod",
        "pod": {"namespace": namespace, "name": pod_name},
        "grace_period_seconds": grace_period,
        "steps": [
            {
                "type": "delete",
                "kind": "Pod",
                "name": pod_name,
                "namespace": namespace,
                "kubectl_command": f"kubectl delete pod {pod_name} -n {namespace} --grace-period={grace_period}",
                "force_delete_command": f"kubectl delete pod {pod_name} -n {namespace} --grace-period=0 --force",
            }
        ],
        "post_verification": {
            "command": f"kubectl get pod {pod_name} -n {namespace} -o jsonpath='{{.status.phase}}' 2>&1 || echo 'pod recreated'",
            "expected": "pod either replaced with new Running instance or recreated by controller",
        },
    }


def _find_owner_reference(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Find the first Deployment or StatefulSet owner reference."""
    owner_refs = obj.get("metadata", {}).get("ownerReferences", [])
    for ref in owner_refs:
        if ref.get("kind") in ("Deployment", "StatefulSet"):
            return ref
    return None


def _apply_plan(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str,
    pod_name: str,
    plan: dict[str, Any],
    strategy: str,
) -> dict[str, Any]:
    """Execute the remediation plan and verify success."""
    if "error" in plan:
        return {
            "status": "failed",
            "reason": plan["error"],
            "suggested_fallback": plan.get("fallback_strategy"),
        }

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
                    "output": raw_logs[:200],
                }
            )

            wait_cmd = step.get("wait_command")
            if wait_cmd:
                wait_logs = run_kubectl_raw(
                    subscription_id, resource_group, cluster_name, wait_cmd
                )
                applied_changes[-1]["wait_output"] = wait_logs[:200]
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "failed",
            "reason": str(exc),
            "applied_changes": applied_changes,
        }

    return {
        "status": "applied",
        "strategy": strategy,
        "pod": {"namespace": namespace, "name": pod_name},
        "applied_changes": applied_changes,
        "post_verification": plan.get("post_verification"),
        "message": "Pod remediation applied successfully. Run post_verification to confirm healthy state.",
    }
