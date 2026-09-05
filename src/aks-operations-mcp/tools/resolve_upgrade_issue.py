"""Lightweight upgrade-issue orchestration helpers for the MCP agent.

The resolver deliberately delegates execution to existing MCP remediation tools and
new controlled CLI tools. It never accepts or requires an application approval token.
"""

from __future__ import annotations

from typing import Any

from tools.cli_operations import aks_az_read, aks_az_write, aks_kubectl_read, aks_kubectl_write


def aks_resolve_upgrade_issue(
    issue: str,
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    target_version: str | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Investigate an upgrade issue and return a structured next-action plan.

    This planner is intentionally conservative: it recommends dedicated remediation tools
    for known blockers and generic CLI investigation for unforeseen workload/infrastructure
    failures. Actual generic writes remain behind full check mode and the existing write gate.
    """
    if not issue or not issue.strip():
        raise ValueError("issue must be a non-empty description")

    lowered = issue.lower()
    checks: list[dict[str, Any]] = []

    if any(term in lowered for term in ("pdb", "disruption", "eviction", "drain")):
        checks.append({"category": "pdb", "recommended_tool": "aks_check_pdb"})
    if any(term in lowered for term in ("pod", "pending", "crashloop", "unschedul", "container")):
        checks.append({"category": "pods", "recommended_tool": "aks_check_pod_health"})
    if any(term in lowered for term in ("pvc", "pv", "storage", "volume", "csi")):
        checks.append({"category": "storage", "recommended_tool": "aks_check_storage"})
    if any(term in lowered for term in ("node", "cordon", "drain")):
        checks.append({"category": "node", "recommended_tool": "aks_check_node_health"})
    if any(term in lowered for term in ("deprecated", "removed api", "api version", "crd")):
        checks.append({"category": "api", "recommended_tool": "aks_check_deprecated_apis"})

    if not checks:
        checks = [
            {"category": "cluster", "recommended_tool": "aks_get_cluster_details"},
            {"category": "nodes", "recommended_tool": "aks_check_node_health"},
            {"category": "pods", "recommended_tool": "aks_check_pod_health"},
            {"category": "pdb", "recommended_tool": "aks_check_pdb"},
            {"category": "storage", "recommended_tool": "aks_check_storage"},
            {"category": "apis", "recommended_tool": "aks_check_deprecated_apis"},
        ]

    return {
        "issue": issue,
        "target_version": target_version,
        "dry_run": dry_run,
        "recommended_checks": checks,
        "dynamic_cli_available": True,
        "cli_hint": "Use aks_kubectl_read/aks_az_read to investigate details not covered by dedicated tools, then use aks_kubectl_write/aks_az_write only when a concrete remediation is understood.",
        "write_policy": "Use dedicated remediation tools first; generic writes require full check_mode and AKS_REMEDIATION_ENABLE_WRITE=true.",
    }


__all__ = [
    "aks_az_read",
    "aks_az_write",
    "aks_kubectl_read",
    "aks_kubectl_write",
    "aks_resolve_upgrade_issue",
]
