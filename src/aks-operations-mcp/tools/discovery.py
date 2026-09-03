"""Discovery tools for AKS operations."""

import os
from typing import Any

from tools.common import get_container_service_client


def aks_get_cluster_details(subscription_id: str, resource_group: str, cluster_name: str) -> dict[str, Any]:
    """Return AKS cluster metadata and current state."""
    client = get_container_service_client(subscription_id)
    cluster = client.managed_clusters.get(resource_group, cluster_name)

    identity_profile = getattr(cluster, "identity_profile", None) or {}
    addon_profiles = getattr(cluster, "addon_profiles", None) or {}

    return {
        "subscription_id": subscription_id,
        "resource_group": resource_group,
        "cluster_name": cluster_name,
        "location": cluster.location,
        "kubernetes_version": cluster.kubernetes_version,
        "provisioning_state": cluster.provisioning_state,
        "power_state": getattr(getattr(cluster, "power_state", None), "code", None),
        "fqdn": cluster.fqdn,
        "private_fqdn": getattr(cluster, "private_fqdn", None),
        "node_resource_group": cluster.node_resource_group,
        "sku_tier": getattr(getattr(cluster, "sku", None), "tier", None),
        "aad_enabled": bool(getattr(cluster, "aad_profile", None)),
        "workload_identity_enabled": bool(getattr(cluster, "security_profile", None) and getattr(cluster.security_profile, "workload_identity", None)),
        "oidc_issuer_enabled": bool(getattr(cluster, "oidc_issuer_profile", None) and getattr(cluster.oidc_issuer_profile, "enabled", False)),
        "managed_identity_client_ids": sorted(
            [
                profile.client_id
                for profile in identity_profile.values()
                if getattr(profile, "client_id", None)
            ]
        ),
        "enabled_addons": sorted(
            [name for name, profile in addon_profiles.items() if getattr(profile, "enabled", False)]
        ),
    }


def aks_get_node_pools(subscription_id: str, resource_group: str, cluster_name: str) -> dict[str, Any]:
    """Return node pool details for a target AKS cluster."""
    client = get_container_service_client(subscription_id)
    pools = list(client.agent_pools.list(resource_group, cluster_name))

    return {
        "subscription_id": subscription_id,
        "resource_group": resource_group,
        "cluster_name": cluster_name,
        "node_pools": [
            {
                "name": pool.name,
                "mode": pool.mode,
                "os_type": pool.os_type,
                "os_sku": getattr(pool, "os_sku", None),
                "vm_size": pool.vm_size,
                "count": pool.count,
                "min_count": getattr(pool, "min_count", None),
                "max_count": getattr(pool, "max_count", None),
                "enable_auto_scaling": bool(getattr(pool, "enable_auto_scaling", False)),
                "orchestrator_version": getattr(pool, "orchestrator_version", None),
                "provisioning_state": getattr(pool, "provisioning_state", None),
                "node_image_version": getattr(pool, "node_image_version", None),
                "max_pods": getattr(pool, "max_pods", None),
            }
            for pool in pools
        ],
    }


def aks_get_available_upgrades(subscription_id: str, resource_group: str, cluster_name: str) -> dict[str, Any]:
    """Return available Kubernetes and node image upgrade paths.

    By default this returns a fast, non-blocking payload with current versions.
    Set ENABLE_UPGRADE_PROFILE_LOOKUP=true to query ARM upgrade-profile APIs.
    """
    client = get_container_service_client(subscription_id)
    cluster = client.managed_clusters.get(resource_group, cluster_name)
    pools = list(client.agent_pools.list(resource_group, cluster_name))

    cluster_upgrades = []
    node_pool_upgrades: dict[str, list[dict[str, Any]]] = {}
    current_node_pools = [
        {
            "name": pool.name,
            "orchestrator_version": getattr(pool, "orchestrator_version", None),
            "node_image_version": getattr(pool, "node_image_version", None),
        }
        for pool in pools
    ]

    lookup_enabled = os.getenv("ENABLE_UPGRADE_PROFILE_LOOKUP", "false").lower() == "true"

    if not lookup_enabled:
        return {
            "subscription_id": subscription_id,
            "resource_group": resource_group,
            "cluster_name": cluster_name,
            "lookup_mode": "fast-current-versions",
            "message": "Set ENABLE_UPGRADE_PROFILE_LOOKUP=true to query ARM upgrade-profile APIs.",
            "current_control_plane_version": cluster.kubernetes_version,
            "current_node_pools": current_node_pools,
            "control_plane_upgrades": cluster_upgrades,
            "node_pool_upgrades": node_pool_upgrades,
        }

    upgrade_errors = []

    if hasattr(client.managed_clusters, "get_upgrade_profile"):
        try:
            profile = client.managed_clusters.get_upgrade_profile(resource_group, cluster_name)
            control_plane_profile = getattr(profile, "control_plane_profile", None)
            if control_plane_profile:
                cluster_upgrades = [
                    {
                        "kubernetes_version": item.kubernetes_version,
                        "is_preview": getattr(item, "is_preview", False),
                    }
                    # Azure may return upgrades=None (not an empty list) when no upgrades are available.
                    for item in (getattr(control_plane_profile, "upgrades", None) or [])
                ]
        except Exception as exc:  # noqa: BLE001
            upgrade_errors.append(f"control-plane profile unavailable: {exc}")

    for pool in pools:
        upgrades = []
        if hasattr(client.agent_pools, "get_upgrade_profile"):
            try:
                pool_profile = client.agent_pools.get_upgrade_profile(resource_group, cluster_name, pool.name)
                upgrades = [
                    {
                        "kubernetes_version": item.kubernetes_version,
                        "is_preview": getattr(item, "is_preview", False),
                        "node_image_version": getattr(item, "node_image_version", None),
                    }
                    # Azure may return upgrades=None (not an empty list) when no upgrades are available.
                    for item in (getattr(pool_profile, "upgrades", None) or [])
                ]
            except Exception as exc:  # noqa: BLE001
                upgrade_errors.append(f"node pool '{pool.name}' profile unavailable: {exc}")
        node_pool_upgrades[pool.name] = upgrades

    return {
        "subscription_id": subscription_id,
        "resource_group": resource_group,
        "cluster_name": cluster_name,
        "lookup_mode": "upgrade-profile",
        "current_control_plane_version": cluster.kubernetes_version,
        "current_node_pools": current_node_pools,
        "control_plane_upgrades": cluster_upgrades,
        "node_pool_upgrades": node_pool_upgrades,
        "upgrade_profile_errors": upgrade_errors,
    }
