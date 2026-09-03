"""Tests for deprecated API detection and migration guidance."""

from __future__ import annotations

import pytest

from tools import remediate_deprecated_apis
from tools.remediate_deprecated_apis import (
    _lookup_migration,
    _parse_deprecated_metrics,
    _parse_version,
    aks_generate_deprecated_api_manifests,
    aks_remediate_deprecated_apis,
)

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_invalid_check_mode():
    with pytest.raises(ValueError, match="Unknown check_mode"):
        aks_remediate_deprecated_apis(*CLUSTER_ARGS, check_mode="invalid")


def test_invalid_target_version():
    with pytest.raises(ValueError, match="Invalid Kubernetes version"):
        aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="not-a-version")


def test_parse_version():
    assert _parse_version("1.35") == (1, 35)
    assert _parse_version("v1.36.2") == (1, 36)


def test_parse_version_rejects_invalid():
    with pytest.raises(ValueError):
        _parse_version("1")


def test_parse_deprecated_metrics_extracts_usage():
    metrics = '''
# HELP apiserver_requested_deprecated_apis [BETA] Number of requests to deprecated APIs.
apiserver_requested_deprecated_apis{group="autoscaling",version="v2beta1",resource="horizontalpodautoscalers",subresource="",removed_release="1.25"} 7
apiserver_requested_deprecated_apis{group="policy",version="v1beta1",resource="poddisruptionbudgets",subresource="",removed_release="1.25"} 0
'''
    findings = _parse_deprecated_metrics(metrics)
    assert len(findings) == 1
    assert findings[0]["apiVersion"] == "autoscaling/v2beta1"
    assert findings[0]["resource"] == "horizontalpodautoscalers"
    assert findings[0]["removed_release"] == "1.25"
    assert findings[0]["request_count"] == 7


def test_parse_deprecated_metrics_handles_core_api_group():
    metrics = 'apiserver_requested_deprecated_apis{group="",version="v1beta1",resource="events",removed_release="1.25"} 1'
    findings = _parse_deprecated_metrics(metrics)
    assert findings[0]["apiVersion"] == "v1beta1"


def test_lookup_known_migration():
    migration = _lookup_migration("autoscaling/v2beta1", "horizontalpodautoscalers")
    assert migration is not None
    assert migration["replacement"] == "autoscaling/v2"
    assert migration["removed_release"] == "1.25"


def test_detects_deprecated_usage_and_replacement(monkeypatch):
    metrics = (
        'apiserver_requested_deprecated_apis{group="autoscaling",version="v2beta1",'
        'resource="horizontalpodautoscalers",subresource="",removed_release="1.25"} 3\n'
    )
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_raw", lambda *_a, **_k: metrics)

    result = aks_remediate_deprecated_apis(
        *CLUSTER_ARGS,
        target_k8s_version="1.35",
    )

    assert result["status"] == "plan"
    assert result["detected_deprecated_api_usage"] == 1
    blocker = result["upgrade_blockers"][0]
    assert blocker["apiVersion"] == "autoscaling/v2beta1"
    assert blocker["replacement_apiVersion"] == "autoscaling/v2"
    assert blocker["is_upgrade_blocker"] is True
    assert "HorizontalPodAutoscaler" in blocker["affected_kinds"]


def test_does_not_treat_api_discovery_as_usage(monkeypatch):
    # api-resources output is intentionally irrelevant; only deprecated-request
    # metrics constitute usage evidence in this tool.
    monkeypatch.setattr(
        remediate_deprecated_apis,
        "run_kubectl_raw",
        lambda *_a, **_k: "NAME APIVERSION NAMESPACED KIND\nhorizontalpodautoscalers autoscaling/v2 true HorizontalPodAutoscaler",
    )

    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.35")
    assert result["status"] == "no_action"


def test_no_action_when_no_deprecated_requests(monkeypatch):
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_raw", lambda *_a, **_k: "# metrics\n")
    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.35")
    assert result["status"] == "no_action"
    assert result["detected_deprecated_api_usage"] == 0
    assert "limitations" in result


def test_current_134_to_135_target_is_supported(monkeypatch):
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_raw", lambda *_a, **_k: "")
    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.35")
    assert result["target_k8s_version"] == "1.35"


def test_generate_manifests_inspects_current_objects(monkeypatch):
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
    import json
    monkeypatch.setattr(
        remediate_deprecated_apis,
        "run_kubectl_raw",
        lambda *_a, **_k: json.dumps(resources_response),
    )

    result = aks_generate_deprecated_api_manifests(
        *CLUSTER_ARGS,
        api_group="autoscaling",
        kind="hpa",
    )

    assert result["status"] == "manifests_inspected"
    assert result["resource_count"] == 2
    assert result["current_versions"] == ["autoscaling/v2"]
    assert len(result["resources"]) == 2


def test_generate_manifests_no_resources(monkeypatch):
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_raw", lambda *_a, **_k: '{"items":[]}')
    result = aks_generate_deprecated_api_manifests(
        *CLUSTER_ARGS,
        api_group="autoscaling",
        kind="hpa",
    )
    assert result["status"] == "no_resources"


def test_generate_manifests_rejects_unsafe_kind(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject unsafe kind")

    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_raw", _should_not_run)
    with pytest.raises(ValueError, match="resource_kind"):
        aks_generate_deprecated_api_manifests(
            *CLUSTER_ARGS,
            api_group="autoscaling",
            kind="hpa; rm -rf /",
        )


def test_no_blind_api_version_patch_in_output(monkeypatch):
    metrics = (
        'apiserver_requested_deprecated_apis{group="policy",version="v1beta1",'
        'resource="poddisruptionbudgets",subresource="",removed_release="1.25"} 1\n'
    )
    monkeypatch.setattr(remediate_deprecated_apis, "run_kubectl_raw", lambda *_a, **_k: metrics)
    result = aks_remediate_deprecated_apis(*CLUSTER_ARGS, target_k8s_version="1.35")
    text = str(result)
    assert 'patch pdb' not in text
    assert '"apiVersion":"policy/v1"' not in text
    assert result["upgrade_blockers"][0]["replacement_apiVersion"] == "policy/v1"
