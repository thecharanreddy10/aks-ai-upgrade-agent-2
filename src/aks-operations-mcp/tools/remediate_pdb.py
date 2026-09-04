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
    approval_token: str | None = None,
    check_mode: str = "full",
) -> dict[str, Any]:
    """Execute a PDB remediation plan to allow disruptions during upgrade.

    Strategies:
    - scale_workload_up: Scale up the Deployment/StatefulSet the PDB protects.
    - relax_pdb: Patch the PDB's minAvailable/maxUnavailable.

    Returns a plan with exact kubectl commands, rollback procedure, and post-apply
    verification steps. No cluster writes unless dry_run=False + approval gates pass.

    The server resolves the approval token from its protected environment when the
    caller does not provide one, so the agent never needs to know the secret.
    """
    validate_namespace(namespace)
    validate_k8s_name(pdb_name, "pdb")
    assert_namespace_not_protected(namespace)

    if strategy not in ("scale_workload_up", "relax_pdb"):
        raise ValueError(f"Unknown strategy: {strategy!r}")

    pdb = _fetch_pdb(subscription_id, resource_group, cluster_name, namespace, pdb_name)
    if not pdb:
        raise ValueError(
            f"PDB {namespace}/{pdb_name} not found or could not be queried."
        )

    if strategy == "scale_workload_up":
        plan = _plan_scale_workload(
            subscription_id,
            resource_group,
            cluster_name,
            namespace,
            pdb,
        )
    else:
        plan = _plan_relax_pdb(namespace, pdb)

    if dry_run:
        return {
            "status": "dry_run",
            "strategy": strategy,
            "pdb": {"namespace": namespace, "name": pdb_name},
            "plan": plan,
            "message": "Plan only; no cluster changes. Pass dry_run=False to apply when remediation writes are enabled.",
        }

    require_remediation_approval(check_mode, approval_token, namespace)

    return _apply_plan(
        subscription_id,
        resource_group,
        cluster_name,
        namespace,
        pdb_name,
        plan,
        strategy,
    )


def aks_rollback_pdb_remediation(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str,
    pdb_name: str,
    strategy: str,
    original_min_available: int | str | None = None,
    original_max_unavailable: int | str | None = None,
    workload_kind: str | None = None,
    workload_name: str | None = None,
    original_replicas: int | None = None,
    dry_run: bool = True,
    approval_token: str | None = None,
    check_mode: str = "full",
) -> dict[str, Any]:
    """Restore the exact state captured before a PDB remediation.

    The normal remediation response exposes rollback commands, but returning a command
    is not the same as executing it. This tool provides an explicit, auditable rollback
    operation that the agent can call after a remediation, using the original values
    captured in the remediation plan. It can restore the PDB and, for scale remediation,
    the protected workload replica count.
    """
    validate_namespace(namespace)
    validate_k8s_name(pdb_name, "pdb")
    assert_namespace_not_protected(namespace)

    if strategy not in ("scale_workload_up", "relax_pdb"):
        raise ValueError(f"Unknown strategy: {strategy!r}")

    if workload_kind is not None and workload_kind not in ("Deployment", "StatefulSet"):
        raise ValueError(f"Unsupported workload kind for rollback: {workload_kind!r}")
    if original_replicas is not None and original_replicas < 0:
        raise ValueError("original_replicas must be non-negative")
    if strategy == "scale_workload_up" and (not workload_kind or not workload_name or original_replicas is None):
        raise ValueError(
            "scale_workload_up rollback requires workload_kind, workload_name, and original_replicas"
        )
    if strategy == "relax_pdb" and workload_kind is not None:
        raise ValueError("relax_pdb rollback does not accept workload parameters")

    pdb = _fetch_pdb(subscription_id, resource_group, cluster_name, namespace, pdb_name)
    if not pdb:
        raise ValueError(
            f"PDB {namespace}/{pdb_name} not found or could not be queried."
        )

    steps: list[dict[str, Any]] = []
    if strategy == "scale_workload_up":
        assert workload_kind is not None and workload_name is not None and original_replicas is not None
        resource = "deployment" if workload_kind == "Deployment" else "statefulset"
        steps.append({
            "type": "rollback_scale",
            "kind": workload_kind,
            "name": workload_name,
            "namespace": namespace,
            "replicas": original_replicas,
            "rollback_command": f"kubectl scale {resource} {workload_name} -n {namespace} --replicas={original_replicas}",
        })
    else:
        steps.append({
            "type": "rollback_patch",
            "kind": "PodDisruptionBudget",
            "name": pdb_name,
            "namespace": namespace,
            "rollback_command": _restore_pdb_command(
                pdb_name,
                namespace,
                original_min_available,
                original_max_unavailable,
            ),
        })

    if dry_run:
        return {
            "status": "dry_run",
            "strategy": strategy,
            "pdb": {"namespace": namespace, "name": pdb_name},
            "steps": steps,
            "message": "Rollback plan only; no cluster changes.",
        }

    require_remediation_approval(check_mode, approval_token, namespace)

    applied_changes: list[dict[str, Any]] = []
    try:
        for step in steps:
            raw_logs = run_kubectl_raw(
                subscription_id,
                resource_group,
                cluster_name,
                step["rollback_command"],
            )
            applied_changes.append({
                "type": step["type"],
                "kind": step["kind"],
                "name": step["name"],
                "output": raw_logs[:200],
            })
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "failed",
            "strategy": strategy,
            "reason": str(exc),
            "applied_changes": applied_changes,
        }

    return {
        "status": "rolled_back",
        "strategy": strategy,
        "pdb": {"namespace": namespace, "name": pdb_name},
        "applied_changes": applied_changes,
        "message": "PDB remediation rollback applied successfully. Verify the restored PDB/workload state.",
    }


def _fetch_pdb(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str,
    pdb_name: str,
) -> dict[str, Any] | None:
    """Fetch the PDB object from the cluster."""
    payload = run_kubectl_json(
        subscription_id,
        resource_group,
        cluster_name,
        f"get pdb {pdb_name} -n {namespace}",
    )
    return payload if payload.get("kind") == "PodDisruptionBudget" else None


def _plan_scale_workload(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str,
    pdb: dict[str, Any],
) -> dict[str, Any]:
    """Plan scaling up the workload the PDB protects."""
    selector = pdb.get("spec", {}).get("selector", {})
    label_selector = _build_label_selector(selector)

    if not label_selector:
        return {
            "error": "Could not extract label selector from PDB spec.",
            "fallback_strategy": "relax_pdb",
        }

    deployments_payload = run_kubectl_json(
        subscription_id,
        resource_group,
        cluster_name,
        f"get deployments -n {namespace} -l {label_selector} -o json",
    )
    deployments = deployments_payload.get("items", [])

    statefulsets_payload = run_kubectl_json(
        subscription_id,
        resource_group,
        cluster_name,
        f"get statefulsets -n {namespace} -l {label_selector} -o json",
    )
    statefulsets = statefulsets_payload.get("items", [])

    if not deployments and not statefulsets:
        return {
            "error": f"No Deployments or StatefulSets found matching selector {label_selector!r}.",
            "fallback_strategy": "relax_pdb",
        }

    steps = []
    for dep in deployments:
        name = dep.get("metadata", {}).get("name")
        current_replicas = dep.get("spec", {}).get("replicas", 1)
        new_replicas = current_replicas + 1
        steps.append({
            "type": "scale",
            "kind": "Deployment",
            "name": name,
            "namespace": namespace,
            "current_replicas": current_replicas,
            "new_replicas": new_replicas,
            "kubectl_command": f"kubectl scale deployment {name} -n {namespace} --replicas={new_replicas}",
            "rollback_command": f"kubectl scale deployment {name} -n {namespace} --replicas={current_replicas}",
        })

    for sts in statefulsets:
        name = sts.get("metadata", {}).get("name")
        current_replicas = sts.get("spec", {}).get("replicas", 1)
        new_replicas = current_replicas + 1
        steps.append({
            "type": "scale",
            "kind": "StatefulSet",
            "name": name,
            "namespace": namespace,
            "current_replicas": current_replicas,
            "new_replicas": new_replicas,
            "kubectl_command": f"kubectl scale statefulset {name} -n {namespace} --replicas={new_replicas}",
            "rollback_command": f"kubectl scale statefulset {name} -n {namespace} --replicas={current_replicas}",
        })

    return {
        "strategy": "scale_workload_up",
        "selector": label_selector,
        "steps": steps,
        "post_verification": {
            "command": f"kubectl get pdb {pdb.get('metadata', {}).get('name')} -n {namespace} -o jsonpath='{{.status.disruptionsAllowed}}'",
            "expected": "value > 0",
        },
    }


def _plan_relax_pdb(
    namespace: str,
    pdb: dict[str, Any],
) -> dict[str, Any]:
    """Plan relaxing the PDB's min/maxUnavailable to allow more disruptions."""
    spec = pdb.get("spec", {})
    metadata = pdb.get("metadata", {})
    pdb_name = metadata.get("name")

    original_min_available = spec.get("minAvailable")
    original_max_unavailable = spec.get("maxUnavailable")

    new_min_available = None
    new_max_unavailable = 1

    return {
        "strategy": "relax_pdb",
        "original_spec": {
            "minAvailable": original_min_available,
            "maxUnavailable": original_max_unavailable,
        },
        "patch": {
            "spec": {
                "minAvailable": new_min_available,
                "maxUnavailable": new_max_unavailable,
            }
        },
        "steps": [
            {
                "type": "patch",
                "kind": "PodDisruptionBudget",
                "name": pdb_name,
                "namespace": namespace,
                "patch_command": f"kubectl patch pdb {pdb_name} -n {namespace} --type=merge -p '{{"
                f"\"spec\":{{\"minAvailable\":null,\"maxUnavailable\":{new_max_unavailable}}}}}'",
                "rollback_command": _restore_pdb_command(pdb_name, namespace, original_min_available, original_max_unavailable),
            }
        ],
        "post_verification": {
            "command": f"kubectl get pdb {pdb_name} -n {namespace} -o jsonpath='{{.spec.minAvailable}} {{.spec.maxUnavailable}}'",
            "expected": f"null {new_max_unavailable}",
        },
    }


def _restore_pdb_command(
    pdb_name: str,
    namespace: str,
    original_min_available: int | str | None,
    original_max_unavailable: int | str | None,
) -> str:
    """Generate the exact kubectl patch command to restore the original PDB spec."""
    import json

    patch = {
        "spec": {
            "minAvailable": original_min_available,
            "maxUnavailable": original_max_unavailable,
        }
    }
    patch_json = json.dumps(patch, separators=(",", ":"))
    return (
        f"kubectl patch pdb {pdb_name} -n {namespace} --type=merge -p "
        f"'{patch_json}'"
    )


def _build_label_selector(selector: dict[str, Any]) -> str | None:
    """Convert a PDB's matchLabels into a kubectl label selector string."""
    match_labels = selector.get("matchLabels", {})
    if not match_labels:
        return None
    return ",".join(f"{k}={v}" for k, v in match_labels.items())


def _apply_plan(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str,
    pdb_name: str,
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
            command = step.get("kubectl_command") or step.get("patch_command")
            raw_logs = run_kubectl_raw(subscription_id, resource_group, cluster_name, command)
            applied_changes.append(
                {
                    "type": step.get("type"),
                    "kind": step.get("kind"),
                    "name": step.get("name"),
                    "output": raw_logs[:200],
                }
            )
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "failed",
            "reason": str(exc),
            "applied_changes": applied_changes,
            "rollback_steps": plan.get("steps", []),
        }

    return {
        "status": "applied",
        "strategy": strategy,
        "pdb": {"namespace": namespace, "name": pdb_name},
        "applied_changes": applied_changes,
        "rollback_steps": plan.get("steps", []),
        "post_verification": plan.get("post_verification"),
        "message": "PDB remediation applied successfully. Run post_verification to confirm.",
    }
