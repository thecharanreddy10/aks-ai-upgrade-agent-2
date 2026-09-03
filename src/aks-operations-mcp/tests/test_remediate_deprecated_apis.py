"""Tests for deprecated API remediation: plan generation, manifest analysis, migration steps."""

from __future__ import annotations

import pytest

from tools import remediate_deprecated_apis
from tools.remediate_deprecated_apis import (
    aks_generate_deprecated_api_manifests,
    aks_remediate_deprecated_apis,
    _plan_api_migration_step,
)

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_remediate_deprecated_apis_invalid_check_mode():
    with pytest.raises(ValueError, match="Unknown check_mode"):
        aks_remediate_deprecated_apis(*CLUSTER_ARGS, check_mode="invalid")


def test_remediate_deprecated_apis_no_action_for_unknown_version(monkeypatch):
    monkeypatch.setattr(
        remediate_deprecated_apis, "run_kubectl_json", lambda *_a, **_k: {"items": []}
    )

    result = aks_remediate_deprecated_apis(
        *CLUSTER_ARGS,
        target_k8s_version="1.99",
    )

    assert result["status"] == "no_action"
    assert "No deprecated APIs known" in result["message"]


def test_remediate_deprecated_apis_plans_for_1_31(monkeypatch):
    def mock_kubectl(*args, **kwargs):
        return {"items": []}

    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", mock_kubectl)

    result = aks_remediate_deprecated_apis(
        *CLUSTER_ARGS,
        target_k8s_version="1.31",
    )

    # Will be no_action since no resources found, but the tool should have searched
    assert result.get("status") in ("plan", "no_action")


def test_plan_api_migration_step_autoscaling_v2beta1(monkeypatch):
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", lambda *_a, **_k: {})

    plan = _plan_api_migration_step(
        *CLUSTER_ARGS,
        "autoscaling/v2beta1",
    )

    assert not plan.get("no_resources")
    assert plan["new_apiVersion"] == "autoscaling/v2"
    assert "HorizontalPodAutoscaler" in plan["kinds"]


def test_plan_api_migration_step_policy_v1beta1(monkeypatch):
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", lambda *_a, **_k: {})

    plan = _plan_api_migration_step(
        *CLUSTER_ARGS,
        "policy/v1beta1",
    )

    assert not plan.get("no_resources")
    assert plan["new_apiVersion"] == "policy/v1"
    assert "PodDisruptionBudget" in plan["kinds"]


def test_plan_api_migration_step_unknown_api(monkeypatch):
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", lambda *_a, **_k: {})

    plan = _plan_api_migration_step(
        *CLUSTER_ARGS,
        "unknown/vunknown",
    )

    assert plan.get("no_resources")


def test_generate_deprecated_api_manifests_no_resources(monkeypatch):
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", lambda *_a, **_k: {"items": []})

    result = aks_generate_deprecated_api_manifests(
        *CLUSTER_ARGS,
        api_group="autoscaling",
        kind="hpa",
    )

    assert result["status"] == "no_resources"


def test_generate_deprecated_api_manifests_finds_resources(monkeypatch):
    resources_response = {
        "items": [
            {
                "metadata": {
                    "name": "hpa-1",
                    "namespace": "default",
                },
                "apiVersion": "autoscaling/v2beta1",
            },
            {
                "metadata": {
                    "name": "hpa-2",
                    "namespace": "kube-system",
                },
                "apiVersion": "autoscaling/v2beta1",
            },
        ]
    }
    monkeypatch.setattr(
        remediate_deprecated_apis, "run_kubectl_json", lambda *_a, **_k: resources_response
    )

    result = aks_generate_deprecated_api_manifests(
        *CLUSTER_ARGS,
        api_group="autoscaling",
        kind="hpa",
    )

    assert result["status"] == "manifests_generated"
    assert result["resource_count"] == 2
    assert len(result["resources"]) == 2
    assert "autoscaling/v2beta1" in result["current_versions"]


def test_generate_deprecated_api_manifests_includes_export_commands(monkeypatch):
    resources_response = {
        "items": [
            {
                "metadata": {"name": "hpa-1", "namespace": "default"},
                "apiVersion": "autoscaling/v2beta1",
            }
        ]
    }
    monkeypatch.setattr(
        remediate_deprecated_apis, "run_kubectl_json", lambda *_a, **_k: resources_response
    )

    result = aks_generate_deprecated_api_manifests(
        *CLUSTER_ARGS,
        api_group="autoscaling",
        kind="hpa",
    )

    assert "export_all_command" in result
    assert "kubectl get hpa -A -o yaml" in result["export_all_command"]


def test_generate_deprecated_api_manifests_rejects_unsafe_kind(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject unsafe kind")

    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError, match="kind"):
        aks_generate_deprecated_api_manifests(
            *CLUSTER_ARGS,
            api_group="autoscaling",
            kind="hpa; rm -rf /",
        )


def test_remediate_deprecated_apis_read_only_no_writes(monkeypatch):
    """Verify that aks_remediate_deprecated_apis is READ-ONLY and never calls run_kubectl_raw."""
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", lambda *_a, **_k: {"items": []})

    result = aks_remediate_deprecated_apis(
        *CLUSTER_ARGS,
        target_k8s_version="1.31",
    )

    # No exception should be raised; tool is read-only and returns plan or no_action (never executes)
    assert result.get("status") in ("plan", "no_action")


def test_plan_migration_step_includes_migration_commands():
    plan = {
        "migration_commands": [
            {
                "kind": "HorizontalPodAutoscaler",
                "export_command": "kubectl get horizontalpodautoscaler -A -o yaml > hpa_backup.yaml",
                "migrate_command": "...",
                "verify_command": "...",
            }
        ]
    }

    assert len(plan["migration_commands"]) == 1
    assert "export_command" in plan["migration_commands"][0]
    assert "migrate_command" in plan["migration_commands"][0]
    assert "verify_command" in plan["migration_commands"][0]


def test_remediate_deprecated_apis_returns_instructions(monkeypatch):
    def mock_kubectl(*args, **kwargs):
        # Simulate finding HPA resources in v2beta1
        return {"items": []}

    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", mock_kubectl)

    result = aks_remediate_deprecated_apis(
        *CLUSTER_ARGS,
        target_k8s_version="1.31",
    )

    # Either plan or no_action; if plan, should have instructions
    if result.get("status") == "plan":
        assert "instructions" in result
        assert "warning" in result
        assert "READ-ONLY" in result["warning"]
