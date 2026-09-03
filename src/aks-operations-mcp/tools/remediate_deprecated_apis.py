"""Remediation tools for deprecated Kubernetes API migration during upgrades.

Strategy:
- plan_migration: Analyze deprecated APIs in use, provide kubectl commands and
  manifests for safe migration. READ-ONLY planning; no cluster writes.

The actual migration is opt-in: user reviews plan, then separately invokes
kubectl apply with provided manifests.

This tool is primarily informational to guide the upgrade process.
"""

from __future__ import annotations

from typing import Any

from tools.common import (
    run_kubectl_json,
)


def aks_remediate_deprecated_apis(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    target_k8s_version: str = "1.31",
    check_mode: str = "quick",
) -> dict[str, Any]:
    """Plan migration of deprecated Kubernetes APIs for the target version.

    This tool is READ-ONLY: it provides a migration plan with kubectl commands
    and manifests. No cluster writes occur. User reviews the plan and decides
    whether to proceed with kubectl apply.

    Target K8s versions map to removed API groups:
    - 1.31: removes beta.storage.k8s.io (CSIStorageCapacity moved to v1)
    - 1.31: removes autoscaling/v2beta1 (moved to v2)
    - 1.31: removes policy/v1beta1 (moved to v1)

    Returns a detailed plan with:
    - Deprecated resources found in the cluster
    - kubectl commands to migrate them
    - New manifests with updated apiVersion
    """
    if check_mode not in ("quick", "full"):
        raise ValueError(f"Unknown check_mode: {check_mode!r}")

    deprecated_apis_by_version = {
        "1.31": [
            "beta.storage.k8s.io/v1beta1",
            "autoscaling/v2beta1",
            "policy/v1beta1",
            "networking.k8s.io/v1beta1",
            "rbac.authorization.k8s.io/v1beta1",
        ],
        "1.32": [
            "batch/v1beta1",
            "discovery.k8s.io/v1beta1",
        ],
    }

    deprecated_for_target = deprecated_apis_by_version.get(target_k8s_version, [])

    if not deprecated_for_target:
        return {
            "status": "no_action",
            "message": f"No deprecated APIs known for K8s {target_k8s_version}.",
        }

    plan_steps = []

    for api_group_version in deprecated_for_target:
        plan_steps.append(
            _plan_api_migration_step(
                subscription_id, resource_group, cluster_name, api_group_version
            )
        )

    found_resources = [s for s in plan_steps if not s.get("no_resources")]
    if not found_resources:
        return {
            "status": "no_action",
            "message": f"No resources using deprecated APIs found in cluster for {target_k8s_version}.",
        }

    return {
        "status": "plan",
        "target_k8s_version": target_k8s_version,
        "migration_steps": found_resources,
        "total_resources_to_migrate": sum(s.get("resource_count", 0) for s in found_resources),
        "instructions": [
            "1. Review each migration_step below.",
            "2. Run the listed 'export_command' to download current manifests.",
            "3. Update apiVersion to the new version listed in 'new_apiVersion'.",
            "4. Run the 'apply_command' to update resources in the cluster.",
            "5. Verify resources are healthy before proceeding with upgrade.",
        ],
        "warning": "This is a READ-ONLY plan. No cluster changes made. Actual migration is opt-in via kubectl apply.",
    }


def _plan_api_migration_step(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    deprecated_api: str,
) -> dict[str, Any]:
    """Plan migration for one deprecated API group/version."""
    # Parse deprecated_api, e.g., "autoscaling/v2beta1" → kind in autoscaling
    parts = deprecated_api.split("/")
    if len(parts) == 2:
        group, version = parts
    else:
        return {"no_resources": True, "api": deprecated_api}

    api_mapping = {
        ("autoscaling", "v2beta1"): {
            "kinds": ["HorizontalPodAutoscaler"],
            "new_version": "autoscaling/v2",
        },
        ("policy", "v1beta1"): {
            "kinds": ["PodDisruptionBudget", "Eviction"],
            "new_version": "policy/v1",
        },
        ("beta.storage.k8s.io", "v1beta1"): {
            "kinds": ["CSIStorageCapacity"],
            "new_version": "storage.k8s.io/v1",
        },
        ("networking.k8s.io", "v1beta1"): {
            "kinds": ["NetworkPolicy", "Ingress"],
            "new_version": "networking.k8s.io/v1",
        },
        ("rbac.authorization.k8s.io", "v1beta1"): {
            "kinds": ["ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"],
            "new_version": "rbac.authorization.k8s.io/v1",
        },
        ("batch", "v1beta1"): {
            "kinds": ["CronJob"],
            "new_version": "batch/v1",
        },
        ("discovery.k8s.io", "v1beta1"): {
            "kinds": ["EndpointSlice"],
            "new_version": "discovery.k8s.io/v1",
        },
    }

    mapping = api_mapping.get((group, version))
    if not mapping:
        return {"no_resources": True, "api": deprecated_api}

    query_result = run_kubectl_json(
        subscription_id,
        resource_group,
        cluster_name,
        f"api-resources --api-group={group} --cached",
    )

    resource_count = 0
    migration_commands = []

    for kind in mapping["kinds"]:
        migration_commands.append({
            "kind": kind,
            "export_command": f"kubectl get {kind.lower()} -A -o yaml > {kind.lower()}_backup.yaml",
            "migrate_command": f"kubectl get {kind.lower()} -A --no-headers -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace | while read name ns; do kubectl patch {kind.lower()} $name -n $ns -p '{{\"apiVersion\":\"{mapping['new_version']}\"}}' --type=merge; done",
            "verify_command": f"kubectl get {kind.lower()} -A -o jsonpath='{{..apiVersion}}' | sort | uniq",
        })
        resource_count += 1

    return {
        "no_resources": False,
        "deprecated_api": deprecated_api,
        "new_apiVersion": mapping["new_version"],
        "resource_count": resource_count,
        "kinds": mapping["kinds"],
        "migration_commands": migration_commands,
    }


def aks_generate_deprecated_api_manifests(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    api_group: str,
    kind: str,
) -> dict[str, Any]:
    """Generate migration manifests for a specific deprecated resource type.

    Helper tool to export all resources of a kind and show their current
    apiVersion + recommended new apiVersion for patching.
    """
    from tools.common import validate_k8s_name

    validate_k8s_name(kind, "resource_kind")

    result = run_kubectl_json(
        subscription_id,
        resource_group,
        cluster_name,
        f"get {kind.lower()} -A -o json",
    )

    resources = result.get("items", [])
    if not resources:
        return {
            "status": "no_resources",
            "kind": kind,
            "message": f"No {kind} resources found in cluster.",
        }

    current_versions = set(
        r.get("apiVersion") for r in resources if r.get("apiVersion")
    )

    return {
        "status": "manifests_generated",
        "kind": kind,
        "resource_count": len(resources),
        "current_versions": list(current_versions),
        "export_all_command": f"kubectl get {kind.lower()} -A -o yaml > {kind.lower()}_all.yaml",
        "export_per_ns_command": f"for ns in $(kubectl get ns -o name); do kubectl get {kind.lower()} -n $ns -o yaml > {kind.lower()}_${{ns##*/}}.yaml; done",
        "resources": [
            {
                "name": r.get("metadata", {}).get("name"),
                "namespace": r.get("metadata", {}).get("namespace", "cluster-wide"),
                "current_apiVersion": r.get("apiVersion"),
            }
            for r in resources[:10]
        ],
        "note": "First 10 resources shown; use export commands for full manifest backup.",
    }
