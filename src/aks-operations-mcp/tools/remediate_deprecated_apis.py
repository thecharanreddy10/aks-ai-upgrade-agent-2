"""Detection and migration guidance for deprecated Kubernetes APIs.

The tool is intentionally conservative: it detects deprecated API *usage* from
API-server metrics/client warnings rather than treating an API being registered
as proof that a resource uses it. It reports the Kubernetes release that removes
the API, the recommended replacement, affected resource types, and any known
schema changes. It never blindly patches ``apiVersion`` on a live object.

This matters for clusters already on a modern release (for example 1.34): many
old APIs are no longer served, so ``kubectl get`` cannot reveal that a controller
or client is still attempting to use them. Kubernetes recommends client
warnings, metrics, and audit information for locating deprecated API usage.
"""

from __future__ import annotations

import re
from typing import Any

from tools.common import run_kubectl_raw, validate_k8s_name


# Historical removals are kept here because a current 1.34+ API server can no
# longer serve/query those versions directly. The API-server metric supplies
# the actual observed usage and removed_release.
API_MIGRATIONS: dict[str, dict[str, Any]] = {
    "autoscaling/v2beta1": {
        "kinds": ["HorizontalPodAutoscaler"],
        "replacement": "autoscaling/v2",
        "removed_release": "1.25",
        "notes": [
            "targetAverageUtilization becomes target.averageUtilization with target.type=Utilization."
        ],
    },
    "autoscaling/v2beta2": {
        "kinds": ["HorizontalPodAutoscaler"],
        "replacement": "autoscaling/v2",
        "removed_release": "1.26",
        "notes": [
            "Use autoscaling/v2; review metric target fields during manifest migration."
        ],
    },
    "policy/v1beta1": {
        "kinds": ["PodDisruptionBudget"],
        "replacement": "policy/v1",
        "removed_release": "1.25",
        "notes": [
            "An empty selector has different semantics in policy/v1; verify the selector explicitly."
        ],
    },
    "batch/v1beta1": {
        "kinds": ["CronJob"],
        "replacement": "batch/v1",
        "removed_release": "1.25",
        "notes": [],
    },
    "discovery.k8s.io/v1beta1": {
        "kinds": ["EndpointSlice"],
        "replacement": "discovery.k8s.io/v1",
        "removed_release": "1.25",
        "notes": [
            "topology is replaced by nodeName/zone and deprecatedTopology fields."
        ],
    },
    "storage.k8s.io/v1beta1": {
        "kinds": ["CSIDriver", "CSINode", "StorageClass", "VolumeAttachment"],
        "replacement": "storage.k8s.io/v1",
        "removed_release": "1.22",
        "notes": [],
    },
    "storage.k8s.io/v1beta1/CSIStorageCapacity": {
        "kinds": ["CSIStorageCapacity"],
        "replacement": "storage.k8s.io/v1",
        "removed_release": "1.27",
        "notes": [],
    },
    "flowcontrol.apiserver.k8s.io/v1beta3": {
        "kinds": ["FlowSchema", "PriorityLevelConfiguration"],
        "replacement": "flowcontrol.apiserver.k8s.io/v1",
        "removed_release": "1.32",
        "notes": [
            "PriorityLevelConfiguration nominalConcurrencyShares semantics changed; review explicit zero/default behavior."
        ],
    },
    "flowcontrol.apiserver.k8s.io/v1beta2": {
        "kinds": ["FlowSchema", "PriorityLevelConfiguration"],
        "replacement": "flowcontrol.apiserver.k8s.io/v1",
        "removed_release": "1.29",
        "notes": [
            "assuredConcurrencyShares was renamed to nominalConcurrencyShares."
        ],
    },
    "flowcontrol.apiserver.k8s.io/v1beta1": {
        "kinds": ["FlowSchema", "PriorityLevelConfiguration"],
        "replacement": "flowcontrol.apiserver.k8s.io/v1beta2",
        "removed_release": "1.26",
        "notes": [],
    },
    "networking.k8s.io/v1beta1": {
        "kinds": ["Ingress", "IngressClass", "NetworkPolicy"],
        "replacement": "networking.k8s.io/v1",
        "removed_release": "1.22",
        "notes": [
            "Ingress requires pathType and uses defaultBackend/service.name/service.port fields in v1."
        ],
    },
    "extensions/v1beta1": {
        "kinds": ["Ingress", "NetworkPolicy", "DaemonSet", "Deployment", "ReplicaSet", "PodSecurityPolicy"],
        "replacement": "See resource-specific replacement",
        "removed_release": "1.22",
        "notes": [
            "The replacement differs by resource; do not mechanically replace apiVersion."
        ],
    },
    "rbac.authorization.k8s.io/v1beta1": {
        "kinds": ["ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"],
        "replacement": "rbac.authorization.k8s.io/v1",
        "removed_release": "1.22",
        "notes": [],
    },
    "admissionregistration.k8s.io/v1beta1": {
        "kinds": ["MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"],
        "replacement": "admissionregistration.k8s.io/v1",
        "removed_release": "1.22",
        "notes": [
            "v1 has required/defaulting changes for sideEffects, admissionReviewVersions, timeoutSeconds and related fields."
        ],
    },
    "apiextensions.k8s.io/v1beta1": {
        "kinds": ["CustomResourceDefinition"],
        "replacement": "apiextensions.k8s.io/v1",
        "removed_release": "1.22",
        "notes": [
            "CRD v1 requires structural schemas and moves several fields under spec.versions."
        ],
    },
    "apiregistration.k8s.io/v1beta1": {
        "kinds": ["APIService"],
        "replacement": "apiregistration.k8s.io/v1",
        "removed_release": "1.22",
        "notes": [],
    },
    "authentication.k8s.io/v1beta1": {
        "kinds": ["TokenReview"],
        "replacement": "authentication.k8s.io/v1",
        "removed_release": "1.22",
        "notes": [],
    },
    "authorization.k8s.io/v1beta1": {
        "kinds": ["LocalSubjectAccessReview", "SelfSubjectAccessReview", "SubjectAccessReview", "SelfSubjectRulesReview"],
        "replacement": "authorization.k8s.io/v1",
        "removed_release": "1.22",
        "notes": ["spec.group was renamed to spec.groups in v1 for SubjectAccessReview resources."],
    },
    "certificates.k8s.io/v1beta1": {
        "kinds": ["CertificateSigningRequest"],
        "replacement": "certificates.k8s.io/v1",
        "removed_release": "1.22",
        "notes": ["signerName and usages are required for certificate requests in v1."],
    },
    "coordination.k8s.io/v1beta1": {
        "kinds": ["Lease"],
        "replacement": "coordination.k8s.io/v1",
        "removed_release": "1.22",
        "notes": [],
    },
    "scheduling.k8s.io/v1beta1": {
        "kinds": ["PriorityClass"],
        "replacement": "scheduling.k8s.io/v1",
        "removed_release": "1.22",
        "notes": [],
    },
    "events.k8s.io/v1beta1": {
        "kinds": ["Event"],
        "replacement": "events.k8s.io/v1",
        "removed_release": "1.25",
        "notes": ["Event fields such as involvedObject/source/timestamps changed in v1."],
    },
    "node.k8s.io/v1beta1": {
        "kinds": ["RuntimeClass"],
        "replacement": "node.k8s.io/v1",
        "removed_release": "1.25",
        "notes": [],
    },
}

# Kubernetes metric format. Labels are deliberately parsed without evaluating
# arbitrary text. The metric is the API server's evidence of actual deprecated
# API requests, not merely API discovery information.
_DEPRECATED_METRIC_RE = re.compile(
    r'^apiserver_requested_deprecated_apis\{(?P<labels>[^}]*)\}\s+(?P<value>[-+0-9.eE]+)$'
)
_LABEL_RE = re.compile(r'(?P<key>[a-zA-Z_][a-zA-Z0-9_]*)="(?P<value>(?:\\.|[^"\\])*)"')


def _parse_version(version: str) -> tuple[int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)(?:\.\d+)?", version)
    if not match:
        raise ValueError(f"Invalid Kubernetes version: {version!r}")
    return int(match.group(1)), int(match.group(2))


def _release_at_or_before(release: str, target: str) -> bool:
    return _parse_version(release) <= _parse_version(target)


def _parse_deprecated_metrics(metrics: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in metrics.splitlines():
        match = _DEPRECATED_METRIC_RE.match(line.strip())
        if not match:
            continue
        labels = {
            m.group("key"): bytes(m.group("value"), "utf-8").decode("unicode_escape")
            for m in _LABEL_RE.finditer(match.group("labels"))
        }
        try:
            value = float(match.group("value"))
        except ValueError:
            continue
        if value <= 0:
            continue
        group = labels.get("group", "")
        version = labels.get("version", "")
        api = f"{group}/{version}" if group else version
        findings.append(
            {
                "apiVersion": api,
                "group": group,
                "version": version,
                "resource": labels.get("resource"),
                "subresource": labels.get("subresource", ""),
                "removed_release": labels.get("removed_release"),
                "request_count": value,
            }
        )
    return findings


def _lookup_migration(api_version: str, resource: str | None) -> dict[str, Any] | None:
    exact = API_MIGRATIONS.get(api_version)
    if exact:
        return exact
    # CSIStorageCapacity shares the storage.k8s.io/v1beta1 API group/version with
    # other storage resources, but had a later removal release.
    if api_version == "storage.k8s.io/v1beta1" and resource == "csistoragecapacities":
        return API_MIGRATIONS["storage.k8s.io/v1beta1/CSIStorageCapacity"]
    return None


def aks_remediate_deprecated_apis(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    target_k8s_version: str = "1.35",
    check_mode: str = "quick",
) -> dict[str, Any]:
    """Detect deprecated API usage and produce safe migration guidance.

    The cluster is queried through the API-server ``/metrics`` endpoint. A
    positive ``apiserver_requested_deprecated_apis`` series is evidence that a
    client/controller has requested a deprecated API. The tool never treats
    ``kubectl api-resources`` as proof of usage and never patches apiVersion
    blindly.
    """
    if check_mode not in ("quick", "full"):
        raise ValueError(f"Unknown check_mode: {check_mode!r}")
    _parse_version(target_k8s_version)

    metrics = run_kubectl_raw(
        subscription_id,
        resource_group,
        cluster_name,
        "get --raw /metrics",
    )
    observations = _parse_deprecated_metrics(metrics)

    relevant: list[dict[str, Any]] = []
    for observation in observations:
        migration = _lookup_migration(
            observation["apiVersion"], observation.get("resource")
        )
        removed_release = observation.get("removed_release")
        if not migration and not removed_release:
            continue
        release = removed_release or migration.get("removed_release")
        if not release or not _release_at_or_before(release, target_k8s_version):
            continue

        item = {
            **observation,
            "removed_in": release,
            "is_upgrade_blocker": _release_at_or_before(release, target_k8s_version),
        }
        if migration:
            item.update(
                {
                    "affected_kinds": migration["kinds"],
                    "replacement_apiVersion": migration["replacement"],
                    "migration_notes": migration["notes"],
                    "remediation": "Update the calling client/controller or source manifest to the replacement API; review schema changes before applying.",
                }
            )
        else:
            item.update(
                {
                    "affected_kinds": [],
                    "replacement_apiVersion": None,
                    "migration_notes": ["No built-in mapping is available; manual/vendor guidance is required."],
                    "remediation": "Identify the resource and vendor/client that is issuing the deprecated request before attempting migration.",
                }
            )
        relevant.append(item)

    if not relevant:
        return {
            "status": "no_action",
            "target_k8s_version": target_k8s_version,
            "detected_deprecated_api_usage": 0,
            "message": "No deprecated API requests matching the known migration data were observed in API-server metrics.",
            "limitations": [
                "Metrics show observed API requests; they do not prove that a dormant manifest is safe.",
                "Also inspect Helm charts, Git manifests, operators, and client/controller versions for APIs not currently being called.",
            ],
        }

    return {
        "status": "plan",
        "target_k8s_version": target_k8s_version,
        "detected_deprecated_api_usage": len(relevant),
        "upgrade_blockers": relevant,
        "migration_steps": [
            {
                "apiVersion": item["apiVersion"],
                "resource": item.get("resource"),
                "replacement_apiVersion": item.get("replacement_apiVersion"),
                "action": item["remediation"],
                "notes": item["migration_notes"],
            }
            for item in relevant
        ],
        "instructions": [
            "Identify the client/controller generating each deprecated request.",
            "Update the client/controller and source manifests to the recommended replacement API.",
            "Review documented schema/semantic changes before applying the converted manifest.",
            "Validate with server-side dry-run and then re-check API-server deprecated-request metrics.",
        ],
        "warning": "Detection is evidence-based and conservative. Do not mechanically patch apiVersion on a live object; existing persisted objects are normally served through the current API version.",
    }


def aks_generate_deprecated_api_manifests(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    api_group: str,
    kind: str,
) -> dict[str, Any]:
    """Inspect current objects and return migration metadata for a resource kind.

    This helper is deliberately read-only. Current objects are returned in the
    API version the server serves today; that is not proof of the API version a
    client used to create/update them.
    """
    validate_k8s_name(kind, "resource_kind")
    validate_k8s_name(api_group.replace("/", "-"), "api_group")

    result = run_kubectl_raw(
        subscription_id,
        resource_group,
        cluster_name,
        f"get {kind.lower()} -A -o json",
    )
    # run_kubectl_raw is used because the caller needs explicit control of the
    # command output; parse the JSON portion without allowing shell data back in.
    import json
    payload = result.strip()
    start = min([i for i in (payload.find("{"), payload.find("[")) if i >= 0], default=-1)
    if start < 0:
        raise RuntimeError(f"Could not parse kubectl JSON for {kind}.")
    resources_payload = json.loads(payload[start:])
    resources = resources_payload.get("items", [])

    if not resources:
        return {
            "status": "no_resources",
            "kind": kind,
            "api_group": api_group,
            "message": f"No {kind} resources found in cluster.",
        }

    current_versions = sorted({r.get("apiVersion") for r in resources if r.get("apiVersion")})
    mappings = []
    for version in current_versions:
        migration = _lookup_migration(version, kind.lower())
        if migration:
            mappings.append(
                {
                    "current_apiVersion": version,
                    "replacement_apiVersion": migration["replacement"],
                    "removed_in": migration["removed_release"],
                    "notes": migration["notes"],
                }
            )

    return {
        "status": "manifests_inspected",
        "kind": kind,
        "api_group": api_group,
        "resource_count": len(resources),
        "current_versions": current_versions,
        "migration_options": mappings,
        "resources": [
            {
                "name": r.get("metadata", {}).get("name"),
                "namespace": r.get("metadata", {}).get("namespace", "cluster-wide"),
                "current_apiVersion": r.get("apiVersion"),
            }
            for r in resources[:20]
        ],
        "note": "Current apiVersion is the server representation. Use deprecated-request metrics, client warnings, audit logs, and source manifests to identify deprecated client usage.",
    }
