"""Deprecated/removed Kubernetes API detection for AKS upgrade pre-assessment.

Detection approach (see POC-PROGRESS.md for the full rationale):
- `kubectl api-resources` alone only shows what the CURRENT server serves; it cannot tell us
  whether an API still in use will be removed by a future target version. Instead, for each
  entry in KNOWN_API_DEPRECATIONS below we check for real objects still using that old apiVersion.
- The target Kubernetes version is compared against each entry's documented deprecated_in/
  removed_in Kubernetes release to classify severity. This mapping cannot be derived from the
  live cluster (the target version doesn't exist yet from the cluster's point of view), so a
  small, explicitly maintained table is required - kept intentionally short (well-known,
  high-impact removals only) rather than an exhaustive compatibility matrix.
- Source: https://kubernetes.io/docs/reference/using-api/deprecation-guide/

Performance note (2026-08-31): AKS Run Command has ~25-35s of per-invocation overhead. The
original implementation issued one Run Command per matrix entry (17 calls, measured at 546s
against the real cluster). This was replaced with a single batched Run Command (see
_build_batch_script) that checks every relevant entry in one invocation, using compact
`-o name` + count output only - never full object JSON - to stay well below AKS Run Command's
output size limit. Each entry's kubectl exit code is captured separately from its output so an
unavailable/removed API (non-zero exit) is never confused with zero matching objects (exit 0,
count 0). This does trade away the previous per-object namespace/name detail (only counts are
now reported per API version) in exchange for the single-invocation design; classification
accuracy (BLOCKER/WARNING) is unchanged.

Correctness note (2026-08-31): real-cluster validation surfaced a bug where entries with
unavailable/unqueryable APIs (query_errors) could coexist with a "HEALTHY" / "no usage detected"
result, incorrectly implying usage had been confirmed absent. Fixed: determine_deprecated_api_health
now returns "INCOMPLETE" (not "HEALTHY") when there are no confirmed findings but some entries
could not be checked, and the "no usage detected" recommendation is never emitted when
query_errors is non-empty. A confirmed BLOCKER/WARNING finding still takes precedence over
INCOMPLETE, since it is more actionable - query_errors remain visible in the result either way.
"""

from __future__ import annotations

import re
from typing import Any

from tools.common import run_kubectl_raw, validate_namespace
from tools.discovery import aks_get_cluster_details

# Each entry: the deprecated/removed GroupVersionKind, whether it's namespaced, the Kubernetes
# (major, minor) release it was deprecated in / removed in (None if not applicable), and the
# recommended replacement apiVersion. Deliberately limited to well-known, high-impact API
# removals rather than an exhaustive historical matrix - extend this list as needed.
KNOWN_API_DEPRECATIONS: list[dict[str, Any]] = [
    {"group": "extensions", "version": "v1beta1", "kind": "Ingress", "plural": "ingresses", "namespaced": True,
     "deprecated_in": (1, 14), "removed_in": (1, 22), "replacement": "networking.k8s.io/v1 Ingress"},
    {"group": "networking.k8s.io", "version": "v1beta1", "kind": "Ingress", "plural": "ingresses", "namespaced": True,
     "deprecated_in": (1, 19), "removed_in": (1, 22), "replacement": "networking.k8s.io/v1 Ingress"},
    {"group": "batch", "version": "v1beta1", "kind": "CronJob", "plural": "cronjobs", "namespaced": True,
     "deprecated_in": (1, 21), "removed_in": (1, 25), "replacement": "batch/v1 CronJob"},
    {"group": "policy", "version": "v1beta1", "kind": "PodDisruptionBudget", "plural": "poddisruptionbudgets", "namespaced": True,
     "deprecated_in": (1, 21), "removed_in": (1, 25), "replacement": "policy/v1 PodDisruptionBudget"},
    {"group": "policy", "version": "v1beta1", "kind": "PodSecurityPolicy", "plural": "podsecuritypolicies", "namespaced": False,
     "deprecated_in": (1, 21), "removed_in": (1, 25), "replacement": "Pod Security Admission (PSA) namespace labels"},
    {"group": "scheduling.k8s.io", "version": "v1beta1", "kind": "PriorityClass", "plural": "priorityclasses", "namespaced": False,
     "deprecated_in": (1, 14), "removed_in": (1, 22), "replacement": "scheduling.k8s.io/v1 PriorityClass"},
    {"group": "admissionregistration.k8s.io", "version": "v1beta1", "kind": "MutatingWebhookConfiguration", "plural": "mutatingwebhookconfigurations", "namespaced": False,
     "deprecated_in": (1, 16), "removed_in": (1, 22), "replacement": "admissionregistration.k8s.io/v1 MutatingWebhookConfiguration"},
    {"group": "admissionregistration.k8s.io", "version": "v1beta1", "kind": "ValidatingWebhookConfiguration", "plural": "validatingwebhookconfigurations", "namespaced": False,
     "deprecated_in": (1, 16), "removed_in": (1, 22), "replacement": "admissionregistration.k8s.io/v1 ValidatingWebhookConfiguration"},
    {"group": "apiextensions.k8s.io", "version": "v1beta1", "kind": "CustomResourceDefinition", "plural": "customresourcedefinitions", "namespaced": False,
     "deprecated_in": (1, 16), "removed_in": (1, 22), "replacement": "apiextensions.k8s.io/v1 CustomResourceDefinition"},
    {"group": "apiregistration.k8s.io", "version": "v1beta1", "kind": "APIService", "plural": "apiservices", "namespaced": False,
     "deprecated_in": (1, 16), "removed_in": (1, 22), "replacement": "apiregistration.k8s.io/v1 APIService"},
    {"group": "rbac.authorization.k8s.io", "version": "v1beta1", "kind": "ClusterRole", "plural": "clusterroles", "namespaced": False,
     "deprecated_in": (1, 17), "removed_in": (1, 22), "replacement": "rbac.authorization.k8s.io/v1 ClusterRole"},
    {"group": "rbac.authorization.k8s.io", "version": "v1beta1", "kind": "ClusterRoleBinding", "plural": "clusterrolebindings", "namespaced": False,
     "deprecated_in": (1, 17), "removed_in": (1, 22), "replacement": "rbac.authorization.k8s.io/v1 ClusterRoleBinding"},
    {"group": "certificates.k8s.io", "version": "v1beta1", "kind": "CertificateSigningRequest", "plural": "certificatesigningrequests", "namespaced": False,
     "deprecated_in": (1, 19), "removed_in": (1, 22), "replacement": "certificates.k8s.io/v1 CertificateSigningRequest"},
    {"group": "coordination.k8s.io", "version": "v1beta1", "kind": "Lease", "plural": "leases", "namespaced": True,
     "deprecated_in": (1, 19), "removed_in": (1, 22), "replacement": "coordination.k8s.io/v1 Lease"},
    {"group": "discovery.k8s.io", "version": "v1beta1", "kind": "EndpointSlice", "plural": "endpointslices", "namespaced": True,
     "deprecated_in": (1, 21), "removed_in": (1, 25), "replacement": "discovery.k8s.io/v1 EndpointSlice"},
    {"group": "autoscaling", "version": "v2beta1", "kind": "HorizontalPodAutoscaler", "plural": "horizontalpodautoscalers", "namespaced": True,
     "deprecated_in": (1, 18), "removed_in": (1, 22), "replacement": "autoscaling/v2 HorizontalPodAutoscaler"},
    {"group": "autoscaling", "version": "v2beta2", "kind": "HorizontalPodAutoscaler", "plural": "horizontalpodautoscalers", "namespaced": True,
     "deprecated_in": (1, 23), "removed_in": (1, 26), "replacement": "autoscaling/v2 HorizontalPodAutoscaler"},
]

_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)")


def _parse_major_minor(version: str) -> tuple[int, int]:
    """Parse a Kubernetes version string (e.g. '1.27.7' or 'v1.27') into (major, minor)."""
    if not isinstance(version, str) or not version.strip():
        raise ValueError(f"Invalid Kubernetes version: {version!r}")
    match = _VERSION_RE.match(version.strip())
    if not match:
        raise ValueError(f"Invalid Kubernetes version format: {version!r}")
    return (int(match.group(1)), int(match.group(2)))


def _format_version(major_minor: tuple[int, int]) -> str:
    return f"{major_minor[0]}.{major_minor[1]}"


def classify_entry(entry: dict[str, Any], target_major_minor: tuple[int, int], target_version_label: str) -> dict[str, Any] | None:
    """Classify a matrix entry against the target version. Returns None if not yet relevant."""
    removed_in = entry.get("removed_in")
    deprecated_in = entry.get("deprecated_in")
    api_version = f"{entry['group']}/{entry['version']}"

    if removed_in is not None and target_major_minor >= removed_in:
        return {
            "severity": "BLOCKER",
            "status": "REMOVED_IN_TARGET",
            "reason": (
                f"{api_version} {entry['kind']} was removed starting in Kubernetes {_format_version(removed_in)}; "
                f"it will not be served by target version {target_version_label}."
            ),
            "recommended_action": f"Migrate to {entry['replacement']} before upgrading to {target_version_label}.",
        }

    if deprecated_in is not None and target_major_minor >= deprecated_in:
        removal_note = f" and is scheduled for removal in {_format_version(removed_in)}" if removed_in else ""
        return {
            "severity": "WARNING",
            "status": "DEPRECATED_STILL_SERVED",
            "reason": (
                f"{api_version} {entry['kind']} has been deprecated since Kubernetes {_format_version(deprecated_in)}"
                f"{removal_note}; still served at target version {target_version_label} but should be migrated."
            ),
            "recommended_action": f"Migrate to {entry['replacement']} ahead of its eventual removal.",
        }

    return None


def determine_deprecated_api_health(
    blockers: list[str],
    warnings: list[str],
    query_errors: list[str] | None = None,
) -> str:
    """Classify overall deprecated-API health.

    Precedence: a confirmed BLOCKER/WARNING finding is always reported as such, even if some
    other entries were unqueryable (those are still preserved in query_errors for transparency).
    Only when there are NO confirmed findings AND some entries could not be checked does this
    return INCOMPLETE - an unavailable/unqueryable API must never be read as "HEALTHY", since
    that would incorrectly imply usage was confirmed absent when it simply could not be checked.
    """
    if blockers:
        return "BLOCKED"
    if warnings:
        return "WARNING"
    if query_errors:
        return "INCOMPLETE"
    return "PASS"


_RESOURCE_BLOCK_RE = re.compile(r"===BEGIN:(?P<label>[^=]+)===\n(?P<body>.*?)\n===END:(?P=label):EXIT=(?P<code>-?\d+)===", re.DOTALL)


def _build_resource_scan_script(entries: list[dict[str, Any]], namespace: str | None) -> str:
    """Run one AKS Run Command with one discovery pass and only served API queries."""
    lines: list[str] = []
    lines.extend(
        [
            "SERVED_APIS=$(kubectl api-versions 2>/dev/null)",
            "DISCOVERY_CODE=$?",
            "echo '===DISCOVERY:BEGIN==='",
            'echo "$SERVED_APIS"',
            "echo '===DISCOVERY:END:EXIT='$DISCOVERY_CODE'==='",
        ]
    )
    for index, entry in enumerate(entries):
        scope_flag = ""
        if entry["namespaced"]:
            scope_flag = f"-n {namespace}" if namespace else "-A"

        api_version = f"{entry['group']}/{entry['version']}"
        resource_ref = entry["plural"]
        lines.extend(
            [
                f"if ! printf '%s\\n' \"$SERVED_APIS\" | grep -Fxq '{api_version}'; then",
                f"  echo '===NOTSERVED:{index}==='",
                "else",
                f"  echo '===BEGIN:{index}==='",
                f"  RAW=$(kubectl get {resource_ref} {scope_flag} --api-version={api_version} -o jsonpath='{{range .items[*]}}{{.apiVersion}}|{{.metadata.namespace}}|{{.metadata.name}}{{\"\\n\"}}{{end}}' 2>/dev/null)",
                "  CODE=$?",
                '  echo "$RAW"',
                f"  echo '===END:{index}:EXIT='$CODE'==='",
                "fi",
            ]
        )
    return "\n".join(lines)


def _parse_resource_scan_output(raw_output: str) -> dict[int, tuple[int, list[str]]]:
    """Parse the single-run scan output into {entry_index: (exit_code, lines)}."""
    parsed: dict[int, tuple[int, list[str]]] = {}
    for match in _RESOURCE_BLOCK_RE.finditer(raw_output):
        idx = int(match.group("label"))
        exit_code = int(match.group("code"))
        body = match.group("body").strip()
        lines = [line.strip() for line in body.splitlines() if line.strip()]
        parsed[idx] = (exit_code, lines)
    return parsed


def _parse_scan_metadata(raw_output: str) -> tuple[bool, set[int]]:
    """Return discovery success and indexes whose deprecated API is not served."""
    discovery_match = re.search(
        r"===DISCOVERY:BEGIN===\n(?P<body>.*?)\n===DISCOVERY:END:EXIT=(?P<code>-?\d+)===" ,
        raw_output,
        re.DOTALL,
    )
    discovery_succeeded = bool(discovery_match and int(discovery_match.group("code")) == 0)
    not_served = {
        int(match.group("index"))
        for match in re.finditer(r"===NOTSERVED:(?P<index>\d+)===" , raw_output)
    }
    return discovery_succeeded, not_served


def _resource_kind_matches(entry: dict[str, Any], resource_api_version: str | None) -> bool:
    """Return True when the discovered object still uses the entry's deprecated API version."""
    if not resource_api_version:
        return False
    return resource_api_version == f"{entry['group']}/{entry['version']}"


def aks_check_deprecated_apis(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    target_version: str | None = None,
    namespace: str | None = None,
) -> dict[str, Any]:
    """Detect Kubernetes API usage that is deprecated or removed relative to a target version.

    The assessment uses a single AKS Run Command that queries only the relevant resource kinds from
    the compatibility matrix rather than probing each obsolete API endpoint individually. Objects are
    inspected for their current apiVersion and compared against the matrix. A resource that is not
    served is recorded under apis_not_served instead of being treated as an in-use deprecated API.
    """
    if namespace is not None:
        validate_namespace(namespace)

    if target_version is not None:
        target_major_minor = _parse_major_minor(target_version)
        resolved_target_version = target_version
        target_version_source = "user_provided"
    else:
        cluster = aks_get_cluster_details(subscription_id, resource_group, cluster_name)
        resolved_target_version = cluster["kubernetes_version"]
        target_major_minor = _parse_major_minor(resolved_target_version)
        target_version_source = "cluster_current_version (no target_version provided)"

    relevant: list[tuple[dict[str, Any], dict[str, Any]]] = []
    checked_api_versions: list[str] = []
    for entry in KNOWN_API_DEPRECATIONS:
        classification = classify_entry(entry, target_major_minor, resolved_target_version)
        if classification is None:
            continue
        relevant.append((entry, classification))
        checked_api_versions.append(f"{entry['group']}/{entry['version']} {entry['kind']}")

    if not relevant:
        return {
            "subscription_id": subscription_id,
            "resource_group": resource_group,
            "cluster_name": cluster_name,
            "scope": namespace or "all-namespaces",
            "target_kubernetes_version": resolved_target_version,
            "target_version_source": target_version_source,
            "assessment": "PASS",
            "deprecated_api_health": "HEALTHY",
            "checked_api_versions": checked_api_versions,
            "apis_not_served": [],
            "resources_checked": 0,
            "deprecated_resources_found": 0,
            "supported_resources": [],
            "run_command_invocations": 0,
            "findings": [],
            "query_errors": [],
            "blockers": [],
            "warnings": [],
            "recommendations": ["No deprecated or removed Kubernetes API usage detected for the target version."],
        }

    findings: list[dict[str, Any]] = []
    apis_not_served: list[str] = []
    supported_resources: list[str] = []
    query_errors: list[str] = []
    resources_checked = 0
    run_command_invocations = 0

    if relevant:
        script = _build_resource_scan_script([entry for entry, _classification in relevant], namespace)
        try:
            raw_output = run_kubectl_raw(subscription_id, resource_group, cluster_name, script)
            run_command_invocations = 1
        except Exception as exc:  # noqa: BLE001
            query_errors.append(f"deprecated API discovery failed: {exc}")
            raw_output = ""

        parsed = _parse_resource_scan_output(raw_output) if raw_output else {}
        discovery_succeeded, not_served_indexes = _parse_scan_metadata(raw_output) if raw_output else (False, set())
        if raw_output and not discovery_succeeded:
            query_errors.append("Kubernetes API discovery failed; served API versions could not be determined.")

        for index, (entry, classification) in enumerate(relevant):
            api_version = f"{entry['group']}/{entry['version']}"
            if index in not_served_indexes:
                apis_not_served.append(f"{api_version} ({entry['kind']})")
                continue
            if index not in parsed:
                if discovery_succeeded:
                    query_errors.append(f"{api_version} {entry['kind']}: resource query result missing from the batch output.")
                    continue
                query_errors.append(f"{api_version} {entry['kind']}: discovery result missing from the batch output.")
                continue

            exit_code, lines = parsed[index]
            if exit_code != 0:
                apis_not_served.append(f"{api_version} ({entry['kind']})")
                continue

            for line in lines:
                if not line:
                    continue
                parts = [item.strip() for item in line.split("|")]
                if len(parts) < 3:
                    continue
                resource_api_version, resource_namespace, resource_name = parts[:3]
                resources_checked += 1

                if _resource_kind_matches(entry, resource_api_version):
                    findings.append(
                        {
                            "kind": entry["kind"],
                            "api_version": resource_api_version,
                            "namespace": resource_namespace if resource_namespace and resource_namespace != "<none>" else None,
                            "name": resource_name,
                            "target_kubernetes_version": resolved_target_version,
                            "replacement": entry["replacement"],
                            "severity": classification["severity"],
                            "status": classification["status"],
                            "reason": classification["reason"],
                            "recommended_action": classification["recommended_action"],
                        }
                    )
                elif resource_api_version:
                    supported_resources.append(f"{resource_api_version} {entry['kind']} {resource_name}")

    blockers: list[str] = []
    warnings: list[str] = []
    for finding in findings:
        message = (
            f"{finding['kind']} ({finding['api_version']}): {finding.get('namespace') or 'cluster-scoped'} / "
            f"{finding.get('name') or 'unknown'} - {finding['reason']}"
        )
        (blockers if finding["severity"] == "BLOCKER" else warnings).append(message)

    recommendations: list[str] = []
    if blockers:
        recommendations.append("Migrate resources using removed API versions before proceeding with the upgrade.")
    if warnings:
        recommendations.append("Plan migration for deprecated-but-still-served API versions.")
    if not blockers and not warnings and not query_errors:
        recommendations.append("No deprecated or removed Kubernetes API usage detected for the target version.")
    if query_errors:
        recommendations.append("Deprecated API assessment is incomplete because some discovery or query operations could not be completed.")
    if apis_not_served:
        recommendations.append("The current cluster does not serve some legacy API versions; they are listed under apis_not_served and are not treated as active usage.")

    assessment = "FAIL" if blockers or warnings else "PASS" if not query_errors else "INCOMPLETE"
    deprecated_api_health = determine_deprecated_api_health(blockers, warnings, query_errors)

    return {
        "subscription_id": subscription_id,
        "resource_group": resource_group,
        "cluster_name": cluster_name,
        "scope": namespace or "all-namespaces",
        "target_kubernetes_version": resolved_target_version,
        "target_version_source": target_version_source,
        "assessment": assessment,
        "deprecated_api_health": deprecated_api_health,
        "checked_api_versions": checked_api_versions,
        "apis_not_served": sorted(set(apis_not_served)),
        "resources_checked": resources_checked,
        "deprecated_resources_found": len(findings),
        "supported_resources": supported_resources[:50],
        "run_command_invocations": run_command_invocations,
        "findings": findings,
        "query_errors": query_errors,
        "blockers": blockers,
        "warnings": warnings,
        "recommendations": recommendations,
    }
