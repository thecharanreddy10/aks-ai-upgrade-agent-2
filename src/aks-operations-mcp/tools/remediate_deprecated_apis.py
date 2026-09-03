"""Read-only planning tools for Kubernetes deprecated API migrations."""

from __future__ import annotations

from typing import Any

from tools.common import run_kubectl_json


# Kubernetes 1.32 has one API-version removal. Older API versions listed in the
# previous implementation were already removed before a 1.29 source cluster,
# so they cannot be blockers for the project's 1.29 -> 1.32 upgrade.
DEPRECATED_APIS_BY_TARGET: dict[str, tuple[str, ...]] = {
    "1.31": (),
    "1.32": ("flowcontrol.apiserver.k8s.io/v1beta3",),
}

API_MIGRATIONS: dict[tuple[str, str], dict[str, Any]] = {
    ("flowcontrol.apiserver.k8s.io", "v1beta3"): {
        "resources": (
            ("flowschemas", "FlowSchema"),
            ("prioritylevelconfigurations", "PriorityLevelConfiguration"),
        ),
        "new_version": "flowcontrol.apiserver.k8s.io/v1",
    },
}


def aks_remediate_deprecated_apis(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    target_k8s_version: str = "1.32",
    check_mode: str = "quick",
) -> dict[str, Any]:
    """Plan migration of deprecated APIs for the requested target version.

    The tool is deliberately READ-ONLY. It detects resources through the
    deprecated API endpoint while that endpoint is still served, then returns
    export/conversion/apply guidance. It never calls a write operation.
    """
    if check_mode not in ("quick", "full"):
        raise ValueError(f"Unknown check_mode: {check_mode!r}")

    deprecated_for_target = DEPRECATED_APIS_BY_TARGET.get(target_k8s_version)
    if deprecated_for_target is None:
        return {
            "status": "unsupported_target",
            "target_k8s_version": target_k8s_version,
            "message": f"No deprecated API removal map is defined for Kubernetes {target_k8s_version}.",
        }

    if not deprecated_for_target:
        return {
            "status": "no_action",
            "target_k8s_version": target_k8s_version,
            "message": f"No API-version removals are scheduled for Kubernetes {target_k8s_version}.",
        }

    migration_steps: list[dict[str, Any]] = []
    for deprecated_api in deprecated_for_target:
        step = _plan_api_migration_step(
            subscription_id, resource_group, cluster_name, deprecated_api
        )
        if not step.get("no_resources"):
            migration_steps.append(step)

    if not migration_steps:
        return {
            "status": "no_action",
            "target_k8s_version": target_k8s_version,
            "message": f"No resources currently served through APIs removed in Kubernetes {target_k8s_version}.",
        }

    return {
        "status": "plan",
        "target_k8s_version": target_k8s_version,
        "migration_steps": migration_steps,
        "total_resources_to_migrate": sum(
            step["resource_count"] for step in migration_steps
        ),
        "instructions": [
            "1. Back up each affected resource using the supplied export command.",
            "2. Update the manifest apiVersion to the supplied new_apiVersion and review any version-specific field changes.",
            "3. Apply the reviewed manifest with kubectl apply -f <converted-manifest>.",
            "4. Verify the resource is healthy using the supplied verification command.",
        ],
        "warning": "READ-ONLY: this tool never patches, applies, deletes, or otherwise mutates cluster resources.",
    }


def _plan_api_migration_step(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    deprecated_api: str,
) -> dict[str, Any]:
    """Detect resources served by one deprecated API and build safe guidance."""
    parts = deprecated_api.split("/")
    if len(parts) != 2:
        return {"no_resources": True, "api": deprecated_api}

    group, version = parts
    mapping = API_MIGRATIONS.get((group, version))
    if mapping is None:
        return {"no_resources": True, "api": deprecated_api}

    migration_commands: list[dict[str, Any]] = []
    resource_count = 0

    for resource_name, kind in mapping["resources"]:
        # Explicitly query the deprecated endpoint. A normal `kubectl get` would
        # use the preferred API and therefore cannot prove that the deprecated
        # API is still being served/used before the upgrade.
        try:
            payload = run_kubectl_json(
                subscription_id,
                resource_group,
                cluster_name,
                f"get {resource_name} -A --api-version={deprecated_api}",
            )
        except RuntimeError:
            # The old endpoint is not served. Existing persisted objects are
            # still accessible through the stable API, but there is no current
            # deprecated-endpoint blocker to migrate on this cluster.
            continue

        items = payload.get("items", [])
        if not items:
            continue

        resource_count += len(items)
        safe_file = resource_name.replace("/", "_")
        migration_commands.append(
            {
                "kind": kind,
                "resource": resource_name,
                "resource_count": len(items),
                "export_command": (
                    f"kubectl get {resource_name} -A --api-version={deprecated_api} "
                    f"-o yaml > {safe_file}_v1beta3_backup.yaml"
                ),
                "new_apiVersion": mapping["new_version"],
                "conversion_guidance": (
                    "Review the exported manifest, change apiVersion to the new API version, "
                    "remove server-generated metadata (for example resourceVersion, uid and "
                    "managedFields), and review version-specific fields before applying."
                ),
                "apply_command": f"kubectl apply -f <reviewed-{safe_file}-manifest>.yaml",
                "verify_command": f"kubectl get {resource_name} -A",
                "resources": [
                    {
                        "name": item.get("metadata", {}).get("name"),
                        "namespace": item.get("metadata", {}).get("namespace", "cluster-wide"),
                    }
                    for item in items[:20]
                ],
            }
        )

    if resource_count == 0:
        return {"no_resources": True, "api": deprecated_api}

    return {
        "no_resources": False,
        "deprecated_api": deprecated_api,
        "new_apiVersion": mapping["new_version"],
        "resource_count": resource_count,
        "kinds": [entry[1] for entry in mapping["resources"]],
        "migration_commands": migration_commands,
    }


def aks_generate_deprecated_api_manifests(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    api_group: str,
    kind: str,
) -> dict[str, Any]:
    """Inspect resources of a kind and report their currently served API versions.

    This helper is also READ-ONLY. It does not claim that changing apiVersion
    in a live object is a valid patch operation; migration requires a reviewed
    manifest using the replacement API.
    """
    from tools.common import validate_k8s_name

    validate_k8s_name(kind, "resource_kind")
    validate_k8s_name(api_group, "api_group")

    result = run_kubectl_json(
        subscription_id,
        resource_group,
        cluster_name,
        f"get {kind.lower()} -A",
    )

    resources = result.get("items", [])
    if not resources:
        return {
            "status": "no_resources",
            "kind": kind,
            "message": f"No {kind} resources found in cluster.",
        }

    current_versions = sorted(
        {r.get("apiVersion") for r in resources if r.get("apiVersion")}
    )

    return {
        "status": "manifests_generated",
        "kind": kind,
        "api_group": api_group,
        "resource_count": len(resources),
        "current_versions": current_versions,
        "export_all_command": f"kubectl get {kind.lower()} -A -o yaml > {kind.lower()}_all.yaml",
        "resources": [
            {
                "name": r.get("metadata", {}).get("name"),
                "namespace": r.get("metadata", {}).get("namespace", "cluster-wide"),
                "current_apiVersion": r.get("apiVersion"),
            }
            for r in resources[:10]
        ],
        "note": "First 10 resources shown; export the full manifest and review the replacement API before applying.",
    }
