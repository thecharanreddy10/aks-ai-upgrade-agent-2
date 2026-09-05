from __future__ import annotations

from tools.resolve_upgrade_issue import aks_resolve_upgrade_issue


def test_resolver_recommends_pdb_checks_for_disruption_issue() -> None:
    result = aks_resolve_upgrade_issue(
        issue="Node drain is blocked by a PDB",
        subscription_id="sub",
        resource_group="rg",
        cluster_name="cluster",
        target_version="1.35",
    )

    assert result["target_version"] == "1.35"
    assert result["recommended_checks"] == [{"category": "pdb", "recommended_tool": "aks_check_pdb"}]
    assert result["dynamic_cli_available"] is True
    assert "approval_token" not in result["write_policy"]


def test_resolver_recommends_multiple_checks_for_mixed_issue() -> None:
    result = aks_resolve_upgrade_issue(
        issue="Pending pod because of storage and node capacity",
        subscription_id="sub",
        resource_group="rg",
        cluster_name="cluster",
    )

    categories = {item["category"] for item in result["recommended_checks"]}
    assert {"pods", "storage", "node"} <= categories
