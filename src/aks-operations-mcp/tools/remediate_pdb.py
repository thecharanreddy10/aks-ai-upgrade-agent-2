"""Remediation tools for Pod Disruption Budget (PDB) constraints during upgrades.

Strategies:
- scale_workload_up: Find the Deployment/StatefulSet the PDB protects, scale replicas up
  so disruptionsAllowed increases. Non-destructive, reversible.
- relax_pdb: Patch minAvailable/maxUnavailable to allow more disruptions; original spec
  captured for exact restoration.

Neither strategy deletes a PDB.
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


def aks_remediate_pdb(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str,
    pdb_name: str,
    strategy: str = "scale_workload_up",
    dry_run: bool = True,
    check_mode: str = "full",
) -> dict[str, Any]:
    """Execute a PDB remediation plan to allow disruptions during upgrade.

    Real writes require dry_run=False, check_mode='full', the server write-enable gate,
    and sufficient Azure/Kubernetes permissions. No application-level approval token is used.
    """
    validate_namespace(namespace)
    validate_k8s_name(pdb_name, "pdb")
    assert_namespace_not_protected(namespace)

    if strategy not in ("scale_workload_up", "relax_pdb"):
        raise ValueError(f"Unknown strategy: {strategy!r}")

    pdb = _fetch_pdb(subscription_id, resource_group, cluster_name, namespace, pdb_name)
    if not pdb:
        raise ValueError(f"PDB {namespace}/{pdb_name} not found or could not be queried.")

    if strategy == "scale_workload_up":
        plan = _plan_scale_workload(subscription_id, resource_group, cluster_name, namespace, pdb)
    else:
        plan = _plan_relax_pdb(namespace, pdb)

    if dry_run:
        return {
            "status": "dry_run",
            "strategy": strategy,
            "pdb": {"namespace": namespace, "name": pdb_name},
            "plan": plan,
            "message": "Plan only; no cluster changes. Pass dry_run=False when remediation writes are enabled.",
        }

    require_remediation_approval(check_mode, namespace)
    return _apply_plan(subscription_id, resource_group, cluster_name, namespace, pdb_name, plan, strategy)


def _fetch_pdb(subscription_id: str, resource_group: str, cluster_name: str, namespace: str, pdb_name: str) -> dict[str, Any] | None:
    payload = run_kubectl_json(subscription_id, resource_group, cluster_name, f"get pdb {pdb_name} -n {namespace}")
    return payload if payload.get("kind") == "PodDisruptionBudget" else None


def _plan_scale_workload(subscription_id: str, resource_group: str, cluster_name: str, namespace: str, pdb: dict[str, Any]) -> dict[str, Any]:
    selector = pdb.get("spec", {}).get("selector", {})
    label_selector = _build_label_selector(selector)
    if not label_selector:
        return {"error": "Could not extract label selector from PDB spec.", "fallback_strategy": "relax_pdb"}

    deployments_payload = run_kubectl_json(subscription_id, resource_group, cluster_name, f"get deployments -n {namespace} -l {label_selector} -o json")
    deployments = deployments_payload.get("items", [])
    statefulsets_payload = run_kubectl_json(subscription_id, resource_group, cluster_name, f"get statefulsets -n {namespace} -l {label_selector} -o json")
    statefulsets = statefulsets_payload.get("items", [])

    if not deployments and not statefulsets:
        return {"error": f"No Deployments or StatefulSets found matching selector {label_selector!r}.", "fallback_strategy": "relax_pdb"}

    steps = []
    for dep in deployments:
        name = dep.get("metadata", {}).get("name")
        current_replicas = dep.get("spec", {}).get("replicas", 1)
        new_replicas = current_replicas + 1
        steps.append({"type": "scale", "kind": "Deployment", "name": name, "namespace": namespace, "current_replicas": current_replicas, "new_replicas": new_replicas, "kubectl_command": f"kubectl scale deployment {name} -n {namespace} --replicas={new_replicas}", "rollback_command": f"kubectl scale deployment {name} -n {namespace} --replicas={current_replicas}"})

    for sts in statefulsets:
        name = sts.get("metadata", {}).get("name")
        current_replicas = sts.get("spec", {}).get("replicas", 1)
        new_replicas = current_replicas + 1
        steps.append({"type": "scale", "kind": "StatefulSet", "name": name, "namespace": namespace, "current_replicas": current_replicas, "new_replicas": new_replicas, "kubectl_command": f"kubectl scale statefulset {name} -n {namespace} --replicas={new_replicas}", "rollback_command": f"kubectl scale statefulset {name} -n {namespace} --replicas={current_replicas}"})

    return {"strategy": "scale_workload_up", "selector": label_selector, "steps": steps, "post_verification": {"command": f"kubectl get pdb {pdb.get('metadata', {}).get('name')} -n {namespace} -o jsonpath='{{.status.disruptionsAllowed}}'", "expected": "value > 0"}}


def _plan_relax_pdb(namespace: str, pdb: dict[str, Any]) -> dict[str, Any]:
    spec = pdb.get("spec", {})
    metadata = pdb.get("metadata", {})
    pdb_name = metadata.get("name")
    original_min_available = spec.get("minAvailable")
    original_max_unavailable = spec.get("maxUnavailable")
    new_max_unavailable = 1
    return {
        "strategy": "relax_pdb",
        "original_spec": {"minAvailable": original_min_available, "maxUnavailable": original_max_unavailable},
        "patch": {"spec": {"minAvailable": None, "maxUnavailable": new_max_unavailable}},
        "steps": [{"type": "patch", "kind": "PodDisruptionBudget", "name": pdb_name, "namespace": namespace, "patch_command": f"kubectl patch pdb {pdb_name} -n {namespace} --type=merge -p '{{\"spec\":{{\"minAvailable\":null,\"maxUnavailable\":{new_max_unavailable}}}}}'", "rollback_command": _restore_pdb_command(pdb_name, namespace, original_min_available, original_max_unavailable)}],
        "post_verification": {"command": f"kubectl get pdb {pdb_name} -n {namespace} -o jsonpath='{{.spec.minAvailable}} {{.spec.maxUnavailable}}'", "expected": f"null {new_max_unavailable}"},
    }


def _restore_pdb_command(pdb_name: str, namespace: str, original_min_available: int | None, original_max_unavailable: int | None) -> str:
    spec_parts: list[str] = []
    spec_parts.append(f'"minAvailable":{original_min_available}' if original_min_available is not None else '"minAvailable":null')
    spec_parts.append(f'"maxUnavailable":{original_max_unavailable}' if original_max_unavailable is not None else '"maxUnavailable":null')
    patch_json = "{" + ",".join(spec_parts) + "}"
    return f'kubectl patch pdb {pdb_name} -n {namespace} --type=merge -p \'{{"spec":{patch_json}}}\''


def _build_label_selector(selector: dict[str, Any]) -> str | None:
    match_labels = selector.get("matchLabels", {})
    if not match_labels:
        return None
    return ",".join(f"{k}={v}" for k, v in match_labels.items())


def _apply_plan(subscription_id: str, resource_group: str, cluster_name: str, namespace: str, pdb_name: str, plan: dict[str, Any], strategy: str) -> dict[str, Any]:
    if "error" in plan:
        return {"status": "failed", "reason": plan["error"], "suggested_fallback": plan.get("fallback_strategy")}
    applied_changes = []
    try:
        for step in plan.get("steps", []):
            command = step.get("kubectl_command") or step.get("patch_command")
            raw_logs = run_kubectl_raw(subscription_id, resource_group, cluster_name, command)
            applied_changes.append({"type": step.get("type"), "kind": step.get("kind"), "name": step.get("name"), "output": raw_logs[:200]})
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "reason": str(exc), "applied_changes": applied_changes, "rollback_steps": plan.get("steps", [])}
    return {"status": "applied", "strategy": strategy, "pdb": {"namespace": namespace, "name": pdb_name}, "applied_changes": applied_changes, "rollback_steps": plan.get("steps", []), "post_verification": plan.get("post_verification"), "message": "PDB remediation applied successfully. Run post_verification to confirm."}
