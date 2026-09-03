"""Tests for discovery-based deprecated API assessment."""

from __future__ import annotations

from tools import deprecated_apis
from tools.deprecated_apis import aks_check_deprecated_apis

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_deprecated_api_assessment_marks_unserved_apis_as_not_usage(monkeypatch):
    entry = {
        "group": "networking.k8s.io",
        "version": "v1beta1",
        "kind": "Ingress",
        "plural": "ingresses",
        "namespaced": True,
        "deprecated_in": (1, 19),
        "removed_in": (1, 22),
        "replacement": "networking.k8s.io/v1 Ingress",
    }
    monkeypatch.setattr(deprecated_apis, "KNOWN_API_DEPRECATIONS", [entry])
    monkeypatch.setattr(
        deprecated_apis,
        "run_kubectl_raw",
        lambda *_a, **_k: "===DISCOVERY:BEGIN===\napps/v1\n===DISCOVERY:END:EXIT=0===\n===NOTSERVED:0===\n",
    )
    monkeypatch.setattr(deprecated_apis, "aks_get_cluster_details", lambda *_a, **_k: {"kubernetes_version": "1.31.0"})

    result = aks_check_deprecated_apis(*CLUSTER_ARGS, target_version="1.31")

    assert result["assessment"] == "PASS"
    assert result["deprecated_api_health"] == "PASS"
    assert "networking.k8s.io/v1beta1 (Ingress)" in result["apis_not_served"]
    assert result["deprecated_resources_found"] == 0


def test_deprecated_api_assessment_detects_actual_deprecated_resource(monkeypatch):
    entry = {
        "group": "networking.k8s.io",
        "version": "v1beta1",
        "kind": "Ingress",
        "plural": "ingresses",
        "namespaced": True,
        "deprecated_in": (1, 19),
        "removed_in": (1, 22),
        "replacement": "networking.k8s.io/v1 Ingress",
    }
    monkeypatch.setattr(deprecated_apis, "KNOWN_API_DEPRECATIONS", [entry])
    monkeypatch.setattr(
        deprecated_apis,
        "run_kubectl_raw",
        lambda *_a, **_k: "===DISCOVERY:BEGIN===\nnetworking.k8s.io/v1beta1\n===DISCOVERY:END:EXIT=0===\n===BEGIN:0===\nnetworking.k8s.io/v1beta1|production|example-ingress\n===END:0:EXIT=0===\n",
    )
    monkeypatch.setattr(deprecated_apis, "aks_get_cluster_details", lambda *_a, **_k: {"kubernetes_version": "1.31.0"})

    result = aks_check_deprecated_apis(*CLUSTER_ARGS, target_version="1.31")

    assert result["deprecated_resources_found"] == 1
    assert result["deprecated_api_health"] == "BLOCKED"
    assert result["findings"][0]["kind"] == "Ingress"
    assert result["findings"][0]["namespace"] == "production"
    assert result["findings"][0]["replacement"] == "networking.k8s.io/v1 Ingress"


def test_deprecated_api_assessment_reports_incomplete_when_discovery_fails(monkeypatch):
    monkeypatch.setattr(deprecated_apis, "KNOWN_API_DEPRECATIONS", [
        {
            "group": "networking.k8s.io",
            "version": "v1beta1",
            "kind": "Ingress",
            "plural": "ingresses",
            "namespaced": True,
            "deprecated_in": (1, 19),
            "removed_in": (1, 22),
            "replacement": "networking.k8s.io/v1 Ingress",
        }
    ])
    monkeypatch.setattr(deprecated_apis, "run_kubectl_raw", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("cluster discovery failed")))
    monkeypatch.setattr(deprecated_apis, "aks_get_cluster_details", lambda *_a, **_k: {"kubernetes_version": "1.31.0"})

    result = aks_check_deprecated_apis(*CLUSTER_ARGS, target_version="1.31")

    assert result["assessment"] == "INCOMPLETE"
    assert result["deprecated_api_health"] == "INCOMPLETE"
    assert result["query_errors"]


def test_deprecated_api_assessment_handles_empty_resource_sets(monkeypatch):
    monkeypatch.setattr(deprecated_apis, "KNOWN_API_DEPRECATIONS", [
        {
            "group": "networking.k8s.io",
            "version": "v1beta1",
            "kind": "Ingress",
            "plural": "ingresses",
            "namespaced": True,
            "deprecated_in": (1, 19),
            "removed_in": (1, 22),
            "replacement": "networking.k8s.io/v1 Ingress",
        }
    ])
    monkeypatch.setattr(
        deprecated_apis,
        "run_kubectl_raw",
        lambda *_a, **_k: "===DISCOVERY:BEGIN===\nnetworking.k8s.io/v1\n===DISCOVERY:END:EXIT=0===\n===BEGIN:0===\n\n===END:0:EXIT=0===\n",
    )
    monkeypatch.setattr(deprecated_apis, "aks_get_cluster_details", lambda *_a, **_k: {"kubernetes_version": "1.31.0"})

    result = aks_check_deprecated_apis(*CLUSTER_ARGS, target_version="1.31")

    assert result["deprecated_resources_found"] == 0
    assert result["assessment"] == "PASS"
    assert result["deprecated_api_health"] == "PASS"
