"""Tests for deprecated API remediation planning."""

from __future__ import annotations

import pytest

from tools import remediate_deprecated_apis
from tools.remediate_deprecated_apis import (
    _plan_api_migration_step,
    aks_generate_deprecated_api_manifests,
    aks_remediate_deprecated_apis,
)

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_invalid_check_mode():
    with pytest.raises(ValueError, match="Unknown check_mode"):
        aks_remediate_deprecated_apis(*CLUSTER_ARGS, check_mode="invalid")


def test_131_has_no_api_removal():
    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.31")
    assert result["status"] == "no_action"
    assert "No API-version removals" in result["message"]


def test_unknown_target_is_explicitly_unsupported():
    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.99")
    assert result["status"] == "unsupported_target"


def test_132_flowcontrol_detection_counts_actual_resources(monkeypatch):
    calls = []

    def mock_kubectl(*args, **kwargs):
        calls.append(args[-1])
        if "flowschemas" in args[-1]:
            return {
                "items": [
                    {"metadata": {"name": "flow-a"}},
                    {"metadata": {"name": "flow-b"}},
                ]
            }
        return {"items": [{"metadata": {"name": "priority-a"}}]}

    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", mock_kubectl)

    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.32")

    assert result["status"] == "plan"
    assert result["total_resources_to_migrate"] == 3
    assert result["migration_steps"][0]["deprecated_api"] == "flowcontrol.apiserver.k8s.io/v1beta3"
    assert any("--api-version=flowcontrol.apiserver.k8s.io/v1beta3" in call for call in calls)


def test_132_no_resources_returns_no_action(monkeypatch):
    monkeypatch.setattr(
        remediate_deprecated_apis,
        "run_kubectl_json",
        lambda *_a, **_k: {"items": []},
    )

    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.32")
    assert result["status"] == "no_action"


def test_api_not_served_is_not_reported_as_a_resource(monkeypatch):
    def not_served(*_args, **_kwargs):
        raise RuntimeError("deprecated API is not served")

    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", not_served)

    plan = _plan_api_migration_step(
        *CLUSTER_ARGS,
        "flowcontrol.apiserver.k8s.io/v1beta3",
    )

    assert plan["no_resources"] is True


def test_plan_has_no_invalid_api_version_patch_command(monkeypatch):
    monkeypatch.setattr(
        remediate_deprecated_apis,
        "run_kubectl_json",
        lambda *_a, **_k: {"items": [{"metadata": {"name": "flow-a"}}]},
    )

    plan = _plan_api_migration_step(
        *CLUSTER_ARGS,
        "flowcontrol.apiserver.k8s.io/v1beta3",
    )

    command = plan["migration_commands"][0]
    assert "kubectl patch" not in command["export_command"]
    assert "kubectl patch" not in command["apply_command"]
    assert command["new_apiVersion"] == "flowcontrol.apiserver.k8s.io/v1"
    assert "reviewed" in command["conversion_guidance"]


def test_resource_count_is_actual_item_count(monkeypatch):
    monkeypatch.setattr(
        remediate_deprecated_apis,
        "run_kubectl_json",
        lambda *_a, **_k: {
            "items": [
                {"metadata": {"name": "flow-a"}},
                {"metadata": {"name": "flow-b"}},
                {"metadata": {"name": "flow-c"}},
            ]
        },
    )

    plan = _plan_api_migration_step(
        *CLUSTER_ARGS,
        "flowcontrol.apiserver.k8s.io/v1beta3",
    )
    assert plan["resource_count"] == 6


def test_generate_deprecated_api_manifests_no_resources(monkeypatch):
    monkeypatch.setattr(
        remediate_deprecated_apis,
        "run_kubectl_json",
        lambda *_a, **_k: {"items": []},
    )

    result = aks_generate_deprecated_api_manifests(
        *CLUSTER_ARGS,
        api_group="autoscaling",
        kind="hpa",
    )
    assert result["status"] == "no_resources"


def test_generate_manifests_reports_versions_and_count(monkeypatch):
    resources_response = {
        "items": [
            {
                "metadata": {"name": "hpa-1", "namespace": "default"},
                "apiVersion": "autoscaling/v2",
            },
            {
                "metadata": {"name": "hpa-2", "namespace": "kube-system"},
                "apiVersion": "autoscaling/v2",
            },
        ]
    }
    monkeypatch.setattr(
        remediate_deprecated_apis,
        "run_kubectl_json",
        lambda *_a, **_k: resources_response,
    )

    result = aks_generate_deprecated_api_manifests(
        *CLUSTER_ARGS,
        api_group="autoscaling",
        kind="hpa",
    )

    assert result["status"] == "manifests_generated"
    assert result["resource_count"] == 2
    assert result["current_versions"] == ["autoscaling/v2"]
    assert len(result["resources"]) == 2
    assert result["api_group"] == "autoscaling"


def test_generate_manifests_rejects_unsafe_kind(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject unsafe kind")

    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError, match="kind"):
        aks_generate_deprecated_api_manifests(
            *CLUSTER_ARGS,
            api_group="autoscaling",
            kind="hpa; rm -rf /",
        )


def test_generate_manifests_rejects_unsafe_api_group(monkeypatch):
    with pytest.raises(ValueError, match="api_group"):
        aks_generate_deprecated_api_manifests(
            *CLUSTER_ARGS,
            api_group="autoscaling;rm -rf /",
            kind="hpa",
        )
