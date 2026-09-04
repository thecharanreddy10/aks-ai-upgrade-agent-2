"""Read-only detection and migration planning for Kubernetes deprecated APIs."""

from __future__ import annotations

import re
from typing import Any

from tools.common import run_kubectl_json, run_kubectl_raw


# Replacement knowledge is API-specific. Removal timing is obtained from the
# live kube-apiserver metric, so the engine is not tied to one upgrade pair.
API_MIGRATIONS: dict[tuple[str, str], dict[str, Any]] = {
    ("flowcontrol.apiserver.k8s.io", "v1beta1"): {"resource": "flowschemas", "kind": "FlowSchema", "replacement": "flowcontrol.apiserver.k8s.io/v1beta2"},
    ("flowcontrol.apiserver.k8s.io", "v1beta2"): {"resource": "flowschemas", "kind": "FlowSchema", "replacement": "flowcontrol.apiserver.k8s.io/v1"},
    ("flowcontrol.apiserver.k8s.io", "v1beta3"): {"resource": "flowschemas", "kind": "FlowSchema", "replacement": "flowcontrol.apiserver.k8s.io/v1"},
    ("storage.k8s.io", "v1beta1"): {"resource": "csistoragecapacities", "kind": "CSIStorageCapacity", "replacement": "storage.k8s.io/v1"},
    ("autoscaling", "v2beta2"): {"resource": "horizontalpodautoscalers", "kind": "HorizontalPodAutoscaler", "replacement": "autoscaling/v2"},
    ("batch", "v1beta1"): {"resource": "cronjobs", "kind": "CronJob", "replacement": "batch/v1"},
    ("discovery.k8s.io", "v1beta1"): {"resource": "endpointslices", "kind": "EndpointSlice", "replacement": "discovery.k8s.io/v1"},
    ("events.k8s.io", "v1beta1"): {"resource": "events", "kind": "Event", "replacement": "events.k8s.io/v1"},
    ("node.k8s.io", "v1beta1"): {"resource": "runtimeclasses", "kind": "RuntimeClass", "replacement": "node.k8s.io/v1"},
    ("admissionregistration.k8s.io", "v1beta1"): {"resource": "mutatingwebhookconfigurations", "kind": "MutatingWebhookConfiguration", "replacement": "admissionregistration.k8s.io/v1"},
    ("apiextensions.k8s.io", "v1beta1"): {"resource": "customresourcedefinitions", "kind": "CustomResourceDefinition", "replacement": "apiextensions.k8s.io/v1"},
    ("apiregistration.k8s.io", "v1beta1"): {"resource": "apiservices", "kind": "APIService", "replacement": "apiregistration.k8s.io/v1"},
    ("authentication.k8s.io", "v1beta1"): {"resource": "tokenreviews", "kind": "TokenReview", "replacement": "authentication.k8s.io/v1"},
    ("coordination.k8s.io", "v1beta1"): {"resource": "leases", "kind": "Lease", "replacement": "coordination.k8s.io/v1"},
    ("networking.k8s.io", "v1beta1"): {"resource": "ingresses", "kind": "Ingress", "replacement": "networking.k8s.io/v1"},
    ("extensions", "v1beta1"): {"resource": "ingresses", "kind": "Ingress", "replacement": "networking.k8s.io/v1"},
    ("policy", "v1beta1"): {"resource": "podsecuritypolicies", "kind": "PodSecurityPolicy", "replacement": None},
}

_METRIC_RE = re.compile(r'^apiserver_requested_deprecated_apis\{(?P<labels>[^}]*)\}\s+(?P<value>[-+0-9.eE]+)')
_LABEL_RE = re.compile(r'(?P<key>[a-zA-Z_][a-zA-Z0-9_]*)="(?P<value>(?:\\.|[^"\\])*)"')
_VERSION_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?$")


def _parse_version(version: str) -> tuple[int, int]:
    match = _VERSION_RE.match(version.strip())
    if not match:
        raise ValueError(f"Invalid Kubernetes version: {version!r}")
    return int(match.group(1)), int(match.group(2) or 0)


def _parse_metric_labels(raw_labels: str) -> dict[str, str]:
    return {m.group("key"): m.group("value").replace('\\"', '"').replace('\\\\', '\\') for m in _LABEL_RE.finditer(raw_labels)}


def _parse_deprecated_api_metrics(metrics: str) -> list[dict[str, Any]]:
    """Parse deprecated-API metric samples into unique API findings."""
    findings: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for line in metrics.splitlines():
        match = _METRIC_RE.match(line.strip())
        if not match:
            continue
        try:
            value = float(match.group("value"))
        except ValueError:
            continue
        if value <= 0:
            continue
        labels = _parse_metric_labels(match.group("labels"))
        group = labels.get("group", "")
        version = labels.get("version", "")
        resource = labels.get("resource", "")
        subresource = labels.get("subresource", "")
        removed_release = labels.get("removed_release", "")
        if not version or not resource or not removed_release:
            continue
        key = (group, version, resource, subresource, removed_release)
        findings[key] = {
            "apiVersion": f"{group}/{version}" if group else version,
            "group": group,
            "version": version,
            "resource": resource,
            "subresource": subresource,
            "removed_release": removed_release,
        }
    return list(findings.values())


def _inspect_resources_for_api(subscription_id: str, resource_group: str, cluster_name: str, finding: dict[str, Any]) -> dict[str, Any]:
    """Enumerate resources behind an observed deprecated API when possible."""
    try:
        payload = run_kubectl_json(subscription_id, resource_group, cluster_name, f"get {finding['resource']} -A --api-version={finding['apiVersion']}")
    except Exception as exc:  # noqa: BLE001 - report the limitation per finding.
        return {"resource_count": None, "resources": [], "query_error": str(exc)}
    items = payload.get("items", [])
    return {
        "resource_count": len(items),
        "resources": [{"name": i.get("metadata", {}).get("name"), "namespace": i.get("metadata", {}).get("namespace", "cluster-wide")} for i in items[:20]],
        "query_error": None,
    }


def aks_remediate_deprecated_apis(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    target_k8s_version: str | None = None,
    check_mode: str = "quick",
) -> dict[str, Any]:
    """Detect deprecated API usage and produce migration plans for any target.

    The target is not used to select a hard-coded API list. The live API server
    reports the removal release for each deprecated API that is actually being
    requested. This makes the same tool usable for successive upgrades.
    """
    if check_mode not in ("quick", "full"):
        raise ValueError(f"Unknown check_mode: {check_mode!r}")
    if target_k8s_version is not None:
        _parse_version(target_k8s_version)

    try:
        metrics = run_kubectl_raw(subscription_id, resource_group, cluster_name, "kubectl get --raw /metrics")
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "detection_unavailable",
            "target_k8s_version": target_k8s_version,
            "message": "Could not read kube-apiserver deprecated API metrics.",
            "error": str(exc),
            "warning": "No blocker decision is made when deprecated-API telemetry is unavailable.",
        }

    findings = _parse_deprecated_api_metrics(metrics)
    if not findings:
        return {
            "status": "no_action",
            "target_k8s_version": target_k8s_version,
            "message": "No actively requested deprecated Kubernetes APIs were reported by kube-apiserver metrics.",
            "source": "apiserver_requested_deprecated_apis",
        }

    plans: list[dict[str, Any]] = []
    target = _parse_version(target_k8s_version) if target_k8s_version else None
    for finding in findings:
        metadata = API_MIGRATIONS.get((finding["group"], finding["version"]), {})
        resources = _inspect_resources_for_api(subscription_id, resource_group, cluster_name, finding)
        removed = bool(target and _parse_version(finding["removed_release"]) <= target)
        replacement = metadata.get("replacement")
        plans.append({
            **finding,
            "severity": "blocker" if removed else "warning",
            "replacement_apiVersion": replacement,
            "kind": metadata.get("kind"),
            **resources,
            "migration": {
                "available": replacement is not None,
                "guidance": f"Migrate manifests and clients from {finding['apiVersion']} to {replacement}." if replacement else "No replacement API is defined; follow the feature-specific Kubernetes migration guidance.",
                "export_command": f"kubectl get {finding['resource']} -A --api-version={finding['apiVersion']} -o yaml > {finding['resource']}_{finding['version']}_backup.yaml",
                "apply_guidance": "Review and convert the manifest to the replacement API; remove server-generated metadata before applying. Do not patch apiVersion on a live object.",
                "verify_command": f"kubectl get {finding['resource']} -A",
            },
        })

    blockers = [p for p in plans if p["severity"] == "blocker"]
    return {
        "status": "blockers_found" if blockers else "warnings_found",
        "target_k8s_version": target_k8s_version,
        "source": "apiserver_requested_deprecated_apis",
        "total_findings": len(plans),
        "blocker_count": len(blockers),
        "warning_count": len(plans) - len(blockers),
        "migration_steps": plans,
        "warning": "READ-ONLY: this tool never patches, applies, deletes, or otherwise mutates cluster resources.",
    }


def aks_generate_deprecated_api_manifests(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    api_group: str,
    kind: str,
) -> dict[str, Any]:
    """Inspect resources of a kind and report their currently served API versions."""
    from tools.common import validate_k8s_name

    validate_k8s_name(kind, "resource_kind")
    validate_k8s_name(api_group, "api_group")
    result = run_kubectl_json(subscription_id, resource_group, cluster_name, f"get {kind.lower()} -A")
    resources = result.get("items", [])
    if not resources:
        return {"status": "no_resources", "kind": kind, "api_group": api_group, "message": f"No {kind} resources found in cluster."}
    current_versions = sorted({r.get("apiVersion") for r in resources if r.get("apiVersion")})
    return {
        "status": "manifests_generated",
        "kind": kind,
        "api_group": api_group,
        "resource_count": len(resources),
        "current_versions": current_versions,
        "export_all_command": f"kubectl get {kind.lower()} -A -o yaml > {kind.lower()}_all.yaml",
        "resources": [{"name": r.get("metadata", {}).get("name"), "namespace": r.get("metadata", {}).get("namespace", "cluster-wide"), "current_apiVersion": r.get("apiVersion")} for r in resources[:10]],
        "note": "First 10 resources shown; export the full manifest and review the replacement API before applying.",
    }
