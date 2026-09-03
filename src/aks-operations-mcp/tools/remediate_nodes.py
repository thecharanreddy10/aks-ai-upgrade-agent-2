"""Remediation tools for node-level constraints during upgrades.

Strategies:
- drain_node: Evict all pods from node and cordon it. Reversible via uncordon.
- restart_node: Reboot the node via kubectl debug node container.
"""

from __future__ import annotations

from typing import Any

from tools.common import require_remediation_approval, run_kubectl_json, run_kubectl_raw, validate_k8s_name


def aks_remediate_node(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    node_name: str,
    strategy: str = "drain_node",
    dry_run: bool = True,
    check_mode: str = "quick",
) -> dict[str, Any]:
    """Execute a node remediation plan.

    Real writes require dry_run=False, check_mode='full', the server write-enable gate,
    and sufficient Azure/Kubernetes permissions. No application-level approval token is used.
    """
    validate_k8s_name(node_name, "node")
    if strategy not in ("drain_node", "restart_node"):
        raise ValueError(f"Unknown strategy: {strategy!r}")

    node = _fetch_node(subscription_id, resource_group, cluster_name, node_name)
    if not node:
        raise ValueError(f"Node {node_name} not found or could not be queried.")

    plan = _plan_drain_node(node_name) if strategy == "drain_node" else _plan_restart_node(node_name)
    if dry_run:
        return {"status": "dry_run", "strategy": strategy, "node": {"name": node_name}, "plan": plan, "message": "Plan only; no cluster changes. Pass dry_run=False when remediation writes are enabled."}

    require_remediation_approval(check_mode, namespace=None)
    return _apply_plan(subscription_id, resource_group, cluster_name, node_name, plan, strategy)


def _fetch_node(subscription_id: str, resource_group: str, cluster_name: str, node_name: str) -> dict[str, Any] | None:
    payload = run_kubectl_json(subscription_id, resource_group, cluster_name, f"get node {node_name}")
    return payload if payload.get("kind") == "Node" else None


def _plan_drain_node(node_name: str) -> dict[str, Any]:
    return {
        "strategy": "drain_node",
        "node": node_name,
        "steps": [
            {"type": "cordon", "kind": "Node", "name": node_name, "kubectl_command": f"kubectl cordon {node_name}", "description": "Mark node as unschedulable to prevent new pod scheduling."},
            {"type": "drain", "kind": "Node", "name": node_name, "kubectl_command": f"kubectl drain {node_name} --ignore-daemonsets --delete-emptydir-data --timeout=5m", "description": "Evict all pods (except daemonsets); local storage erased."},
        ],
        "post_drain_verification": {"command": f"kubectl get pods -A --field-selector spec.nodeName={node_name} --no-headers | wc -l", "expected": "0 (all pods evicted)"},
        "uncordon_command": f"kubectl uncordon {node_name}",
        "uncordon_description": "Mark node as schedulable again after upgrade/maintenance.",
    }


def _plan_restart_node(node_name: str) -> dict[str, Any]:
    return {
        "strategy": "restart_node",
        "node": node_name,
        "steps": [{"type": "restart", "kind": "Node", "name": node_name, "kubectl_command": f"kubectl debug node/{node_name} -it --image=busybox:1.35 -- chroot /host shutdown -r +1", "description": "Schedule reboot 1 minute from now; allows graceful pod eviction."}],
        "monitoring": {"check_command": f"kubectl get node {node_name} -o jsonpath='{{.status.conditions[?(@.type==\"Ready\")].status}}'", "healthy_status": "True", "warning": "Node will be NotReady for 1-2 minutes during reboot. Monitor upgrade progress separately."},
    }


def _apply_plan(subscription_id: str, resource_group: str, cluster_name: str, node_name: str, plan: dict[str, Any], strategy: str) -> dict[str, Any]:
    if "error" in plan:
        return {"status": "failed", "reason": plan["error"]}
    applied_changes = []
    try:
        for step in plan.get("steps", []):
            command = step.get("kubectl_command")
            raw_logs = run_kubectl_raw(subscription_id, resource_group, cluster_name, command)
            applied_changes.append({"type": step.get("type"), "kind": step.get("kind"), "name": step.get("name"), "description": step.get("description"), "output": raw_logs[:200]})
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "reason": str(exc), "applied_changes": applied_changes}
    post_verify = plan.get("post_drain_verification") or plan.get("monitoring")
    return {"status": "applied", "strategy": strategy, "node": {"name": node_name}, "applied_changes": applied_changes, "post_verification": post_verify, "uncordon_or_monitor": plan.get("uncordon_command") or plan.get("monitoring", {}).get("check_command"), "message": f"Node {strategy} applied successfully. Monitor pod re-scheduling and node readiness."}
