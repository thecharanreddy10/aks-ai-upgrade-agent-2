"""Tests for version-agnostic deprecated API detection and planning."""

from __future__ import annotations

import pytest

from tools import remediate_deprecated_apis
from tools.remediate_deprecated_apis import (
    _parse_deprecated_api_metrics,
    _parse_version,
    aks_generate_deprecated_api_manifests,
    aks_remediate_deprecated_apis,
)

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def _metric(api_version: str, resource: str, removed_release: str, group: str = "flowcontrol.apiserver.k8s.io") -> str:
    version = api_version.split("/")[-1]
    return (
        'apiserver_requested_deprecated_apis{'
        f'group="{group}",removed_release="{removed_release}",resource="{resource}",subresource="",version="{version}"'
        '} 1'
    )


def test_invalid_check_mode():
    with pytest.raises(ValueError, match="Unknown check_mode"):
        aks_remediate_deprecated_apis(*CLUSTER_ARGS, check_mode="invalid")


def test_invalid_target_version():
    with pytest.raises(ValueError, match="Invalid Kubernetes version"):
        aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="not-a-version")


def test_parse_version_accepts_standard_versions():
    assert _parse_version("1.34") == (1, 34)
    assert _parse_version("v1.35") == (1, 35)


def test_metric_parser_extracts_unique_deprecated_apis():
    metrics = "\n".join([
        _metric("flowcontrol.apiserver.k8s.io/v1beta3", "flowschemas", "1.32"),
        _metric("flowcontrol.apiserver.k8s.io/v1beta3", "flowschemas", "1.32"),
        "some_other_metric 1",
    ])
    findings = _parse_deprecated_api_metrics(metrics)
    assert len(findings) == 1
    assert findings[0]["apiVersion"] == "flowcontrol.apiserver.k8s.io/v1beta3"
    assert findings[0]["removed_release"] == "1.32"


def test_target_is_classification_not_hard_coded_api_selection(monkeypatch):
    metrics = _metric("flowcontrol.apiserver.k8s.io/v1beta3", "flowschemas", "1.32")
    calls = []

    def mock_raw(*args, **kwargs):
        return metrics

    def mock_json(*args, **kwargs):
        calls.append(args[-1])
        return {"items": [{"metadata": {"name": "flow-a"}}]}

    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_raw", mock_raw)
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", mock_json)

    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.35")
    assert result["status"] == "blockers_found"
    assert result["migration_steps"][0]["severity"] == "blocker"
    assert result["migration_steps"][0]["replacement_apiVersion"] == "flowcontrol.apiserver.k8s.io/v1"
    assert calls


def test_future_target_can_report_warning_for_later_removal(monkeypatch):
    metrics = _metric("flowcontrol.apiserver.k8s.io/v1beta3", "flowschemas", "1.36")
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_raw", lambda *_a, **_k: metrics)
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", lambda *_a, **_k: {"items": []})

    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.35")
    assert result["status"] == "warnings_found"
    assert result["blocker_count"] == 0
    assert result["warning_count"] == 1


def test_no_metrics_findings_returns_no_action(monkeypatch):
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_raw", lambda *_a, **_k: "# HELP foo foo\nfoo 1\n")
    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.35")
    assert result["status"] == "no_action"


def test_metrics_unavailable_is_not_reported_as_safe(monkeypatch):
    def unavailable(*_args, **_kwargs):
        raise RuntimeError("metrics unavailable")

    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_raw", unavailable)
    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.35")
    assert result["status"] == "detection_unavailable"
    assert "No blocker decision" in result["warning"]


def test_unmapped_deprecated_api_is_still_reported(monkeypatch):
    metrics = _metric("example.k8s.io/v1beta1", "widgets", "1.35", group="example.k8s.io")
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_raw", lambda *_a, **_k: metrics)
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", lambda *_a, **_k: {"items": []})

    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.35")
    finding = result["migration_steps"][0]
    assert finding["severity"] == "blocker"
    assert finding["replacement_apiVersion"] is None
    assert finding["migration"]["available"] is False


def test_manifest_helper_reports_versions_and_count(monkeypatch):
    resources_response = {
        "items": [
            {"metadata": {"name": "hpa-1", "namespace": "default"}, "apiVersion": "autoscaling/v2"},
            {"metadata": {"name": "hpa-2", "namespace": "kube-system"}, "apiVersion": "autoscaling/v2"},
        ]
    }
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", lambda *_a, **_k: resources_response)
    result = aks_generate_deprecated_api_manifests(*CLUSTER_ARGS, api_group="autoscaling", kind="hpa")
    assert result["status"] == "manifests_generated"
    assert result["resource_count"] == 2
    assert result["current_versions"] == ["autoscaling/v2"]
    assert result["api_group"] == "autoscaling"


def test_manifest_helper_rejects_unsafe_input(monkeypatch):
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_json", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not run")))
    with pytest.raises(ValueError, match="kind"):
        aks_generate_deprecated_api_manifests(*CLUSTER_ARGS, api_group="autoscaling", kind="hpa;rm -rf /")
    with pytest.raises(ValueError, match="api_group"):
        aks_generate_deprecated_api_manifests(*CLUSTER_ARGS, api_group="autoscaling;rm -rf /", kind="hpa")
