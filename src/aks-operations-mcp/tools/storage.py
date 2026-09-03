"""Storage health tool for AKS operations.

Read-only diagnostics for PVCs, PVs, StorageClasses, and storage-related pod/event
failures that could block application pods from becoming healthy during an upgrade.

Performance note (2026-08-31): the 5 kubectl queries below (PVCs, PVs, StorageClasses, pods,
events) were originally issued as 5 separate AKS Run Command invocations (measured baseline:
~159s namespace-scoped), each paying AKS Run Command's ~25-35s per-invocation overhead. They were
first batched into a SINGLE Run Command using full `-o json` for every query, following the same
principle used to optimize aks_check_deprecated_apis (17 calls -> 1).

Real-cluster follow-up (2026-08-31): a cluster-wide (`-A`) run of that batched implementation came
back with `pvc`/`pv`/`storageclass` populated correctly, but `pods` and `events` were entirely
absent from the combined output ("no result returned in the batched output"), while a
namespace-scoped run of the exact same code succeeded cleanly for all 5 queries. This points at
AKS Run Command's own output-size limit being hit by the *combined* response once full pod/event
JSON is included cluster-wide (`pvc`/`pv`/`storageclass` are queried first and stayed intact;
`pods`/`events` are queried last and were the ones cut off) - not a bug in the parsing regex
itself, since it parsed the surviving sections correctly. Fix: `pods` and `events` are now
requested via compact `-o jsonpath` rows (see _POD_STORAGE_JSONPATH/_EVENT_STORAGE_JSONPATH)
carrying only the fields find_pod_storage_failures/find_storage_events/classify_pvcs actually
read - never full pod/event objects - while `pvc`/`pv`/`storageclass` (small even cluster-wide)
keep using full `-o json`. All 5 queries remain in ONE Run Command invocation via a single
`run_kubectl_raw` call (no run_kubectl_batch/common.py changes were needed or made). The compact
pod/event rows are converted back into the exact nested dict shape the existing classification
functions already expect, so those functions (and every one of their pre-existing unit tests)
are completely unchanged. Known limitation: pod/event fields are pipe/caret/tilde-delimited, so
a waiting message or event message containing those literal characters could shift field
boundaries - accepted trade-off for staying well under the output-size limit, same category of
trade-off already made in aks_check_deprecated_apis (count-only findings).

Correctness note (2026-08-31): the real cluster run above also exposed that `storage_health`
could report "HEALTHY" even while `pods`/`events` query_errors were non-empty, because
determine_storage_health() only considered blockers/warnings. Fixed to mirror the same
precedence already used by aks_check_deprecated_apis: BLOCKED > WARNING > INCOMPLETE > HEALTHY -
a query failure must never be reported as a healthy/clean result.
"""

from __future__ import annotations

import json
import re
from typing import Any

from tools.common import run_kubectl_raw, validate_namespace

# Event/waiting reasons that are unambiguously storage-related on their own.
_STRONG_STORAGE_REASONS = {
    "FailedMount",
    "FailedAttachVolume",
    "FailedMountVolume",
    "FailedMapVolume",
    "FailedBinding",
    "ProvisioningFailed",
    "VolumeFailedDelete",
}

# Generic keywords that only count as storage-related when paired with a reason/message,
# e.g. so a plain "FailedScheduling" (which can be CPU/memory) isn't misclassified.
_STORAGE_KEYWORDS = ("volume", "mount", "attach", "persistentvolumeclaim", "pvc", "storage", "provision")


def _text_indicates_storage_issue(reason: str | None, message: str | None) -> bool:
    """Return whether a reason/message pair describes a storage-related failure."""
    if reason and reason in _STRONG_STORAGE_REASONS:
        return True
    combined = f"{reason or ''} {message or ''}".lower()
    return any(keyword in combined for keyword in _STORAGE_KEYWORDS)


def find_pod_storage_failures(pod_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find non-running pods whose container state indicates a storage-related failure."""
    failures = []
    for pod in pod_items:
        metadata = pod.get("metadata", {})
        status = pod.get("status", {})
        if status.get("phase") in ("Running", "Succeeded"):
            continue

        for container_status in status.get("containerStatuses", []) or []:
            waiting = container_status.get("state", {}).get("waiting", {}) or {}
            reason = waiting.get("reason")
            message = waiting.get("message")
            if _text_indicates_storage_issue(reason, message):
                failures.append(
                    {
                        "namespace": metadata.get("namespace"),
                        "name": metadata.get("name"),
                        "reason": reason,
                        "message": message,
                    }
                )
                break

    return failures


def find_storage_events(event_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find Kubernetes events that indicate a storage-related warning/error."""
    events = []
    for event in event_items:
        reason = event.get("reason")
        message = event.get("message")
        if not _text_indicates_storage_issue(reason, message):
            continue

        involved = event.get("involvedObject", {}) or {}
        events.append(
            {
                "namespace": event.get("metadata", {}).get("namespace") or involved.get("namespace"),
                "involved_kind": involved.get("kind"),
                "involved_object": involved.get("name"),
                "reason": reason,
                "message": message,
                "last_timestamp": event.get("lastTimestamp") or event.get("eventTime"),
            }
        )

    return events


def summarize_storage_classes(sc_items: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Summarize StorageClasses; not a source of blockers/warnings on its own."""
    items = []
    by_name: dict[str, dict[str, Any]] = {}
    for storage_class in sc_items:
        name = storage_class.get("metadata", {}).get("name")
        info = {
            "name": name,
            "provisioner": storage_class.get("provisioner"),
            "reclaim_policy": storage_class.get("reclaimPolicy"),
            "volume_binding_mode": storage_class.get("volumeBindingMode"),
            "allow_volume_expansion": storage_class.get("allowVolumeExpansion"),
        }
        items.append(info)
        by_name[name] = info

    return {"total": len(items), "items": items}, by_name


def _pvc_names_referenced_by_pods(pod_items: list[dict[str, Any]]) -> set[tuple[str | None, str]]:
    referenced = set()
    for pod in pod_items:
        namespace = pod.get("metadata", {}).get("namespace")
        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim_name = (volume.get("persistentVolumeClaim") or {}).get("claimName")
            if claim_name:
                referenced.add((namespace, claim_name))

    return referenced


def _pvc_claims_of_failing_pods(
    pod_items: list[dict[str, Any]],
    pod_storage_failures: list[dict[str, Any]],
) -> set[tuple[str | None, str]]:
    failing_pod_keys = {(failure["namespace"], failure["name"]) for failure in pod_storage_failures}
    claims = set()
    for pod in pod_items:
        metadata = pod.get("metadata", {})
        key = (metadata.get("namespace"), metadata.get("name"))
        if key not in failing_pod_keys:
            continue
        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim_name = (volume.get("persistentVolumeClaim") or {}).get("claimName")
            if claim_name:
                claims.add((metadata.get("namespace"), claim_name))

    return claims


def classify_pvcs(
    pvc_items: list[dict[str, Any]],
    pod_items: list[dict[str, Any]],
    storage_classes_by_name: dict[str, dict[str, Any]] | None = None,
    pod_storage_failures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Classify PVCs, using pod references/failures for context on Pending claims."""
    storage_classes_by_name = storage_classes_by_name or {}
    referenced = _pvc_names_referenced_by_pods(pod_items)
    actively_failing_claims = _pvc_claims_of_failing_pods(pod_items, pod_storage_failures or [])

    total = 0
    bound = 0
    pending = 0
    problematic: list[dict[str, Any]] = []

    for pvc in pvc_items:
        total += 1
        metadata = pvc.get("metadata", {})
        namespace = metadata.get("namespace")
        name = metadata.get("name")
        spec = pvc.get("spec", {})
        phase = pvc.get("status", {}).get("phase")
        key = (namespace, name)

        if phase == "Bound":
            bound += 1
            if not spec.get("volumeName"):
                problematic.append(
                    {
                        "namespace": namespace,
                        "name": name,
                        "phase": phase,
                        "severity": "BLOCKER",
                        "reason": "PVC reports Bound phase but has no bound volumeName (inconsistent state).",
                    }
                )
            continue

        if phase == "Pending":
            pending += 1
            binding_mode = (storage_classes_by_name.get(spec.get("storageClassName")) or {}).get("volume_binding_mode")
            is_referenced = key in referenced
            is_actively_failing = key in actively_failing_claims

            if is_actively_failing:
                severity = "BLOCKER"
                reason = "PVC is Pending and the pod requiring it is actively failing to mount/attach storage."
            elif is_referenced and binding_mode == "WaitForFirstConsumer":
                severity = "WARNING"
                reason = (
                    "PVC is Pending with WaitForFirstConsumer binding; this is expected until its "
                    "pod is scheduled. Monitor for mount failures."
                )
            elif is_referenced:
                severity = "BLOCKER"
                reason = "PVC is Pending and is required by an existing pod."
            else:
                severity = "WARNING"
                reason = "PVC is Pending but is not currently referenced by any pod."

            problematic.append(
                {"namespace": namespace, "name": name, "phase": phase, "severity": severity, "reason": reason}
            )
            continue

        severity = "BLOCKER" if phase == "Lost" else "WARNING"
        problematic.append(
            {
                "namespace": namespace,
                "name": name,
                "phase": phase,
                "severity": severity,
                "reason": f"PVC is in unexpected phase '{phase}'.",
            }
        )

    return {"total": total, "bound": bound, "pending": pending, "problematic": problematic}


def classify_pvs(pv_items: list[dict[str, Any]]) -> dict[str, Any]:
    """Classify PVs. An orphaned/unclaimed PV is a warning, never an automatic blocker."""
    total = 0
    bound = 0
    problematic: list[dict[str, Any]] = []

    for pv in pv_items:
        total += 1
        name = pv.get("metadata", {}).get("name")
        phase = pv.get("status", {}).get("phase")
        claim_ref = pv.get("spec", {}).get("claimRef")

        if phase == "Bound":
            bound += 1
            if not claim_ref:
                problematic.append(
                    {
                        "name": name,
                        "phase": phase,
                        "severity": "WARNING",
                        "reason": "PV reports Bound phase but has no claimRef (suspicious state).",
                    }
                )
            continue

        if phase == "Available":
            problematic.append(
                {
                    "name": name,
                    "phase": phase,
                    "severity": "WARNING",
                    "reason": "PV is unclaimed/orphaned (Available). Not currently blocking any workload.",
                }
            )
            continue

        if phase == "Released":
            problematic.append(
                {
                    "name": name,
                    "phase": phase,
                    "severity": "WARNING",
                    "reason": "PV is Released; depending on reclaim policy it may need manual cleanup.",
                }
            )
            continue

        if phase == "Failed":
            problematic.append(
                {"name": name, "phase": phase, "severity": "BLOCKER", "reason": "PV is in Failed state."}
            )
            continue

        problematic.append(
            {"name": name, "phase": phase, "severity": "WARNING", "reason": f"PV is in unexpected phase '{phase}'."}
        )

    return {"total": total, "bound": bound, "unbound_or_problematic": problematic}


def determine_storage_health(blockers: list[str], warnings: list[str], query_errors: list[str] | None = None) -> str:
    """Classify overall storage health. BLOCKED > WARNING > INCOMPLETE > HEALTHY.

    A non-empty query_errors with no confirmed blockers/warnings means the assessment could not
    be completed - it must be reported as INCOMPLETE, never as a false HEALTHY.
    """
    if blockers:
        return "BLOCKED"
    if warnings:
        return "WARNING"
    if query_errors:
        return "INCOMPLETE"
    return "HEALTHY"


def _extract_items(label: str, batch: dict[str, tuple[int, str]], query_errors: list[str]) -> list[dict[str, Any]]:
    """Pull a resource's `items` list out of a batched query result, or record why it's missing.

    A non-zero exit code or unparseable JSON is appended to query_errors and treated as "unknown",
    never as a silent empty/healthy result - the caller must be able to see that this specific
    check could not be confirmed.
    """
    entry = batch.get(label)
    if entry is None:
        query_errors.append(f"{label}: no result returned in the batched output.")
        return []

    exit_code, raw_json = entry
    if exit_code != 0:
        query_errors.append(f"{label}: kubectl exited with code {exit_code}; query could not be executed.")
        return []
    if not raw_json.strip():
        return []

    try:
        return json.loads(raw_json).get("items", [])
    except json.JSONDecodeError as exc:
        truncation_hint = (
            " Output may be truncated near AKS Run Command's output size limit; retry with a "
            "narrower namespace scope."
            if len(raw_json) >= 500_000
            else ""
        )
        query_errors.append(f"{label}: failed to parse kubectl JSON output ({exc}).{truncation_hint}")
        return []


# Compact per-pod jsonpath row: namespace|name|phase|containers|volumes, where `containers` is
# "reason^message~reason^message~..." (one entry per container currently in a waiting state) and
# `volumes` is "claimName~claimName~..." (one entry per volume backed by a PVC). Never `-o json` -
# only the fields find_pod_storage_failures/classify_pvcs actually read are requested, which is
# what keeps a cluster-wide query from disappearing from the combined batch response (see module
# docstring).
_POD_STORAGE_JSONPATH = (
    "{range .items[*]}{.metadata.namespace}|{.metadata.name}|{.status.phase}|"
    "{range .status.containerStatuses[?(@.state.waiting)]}{.state.waiting.reason}^{.state.waiting.message}~{end}|"
    "{range .spec.volumes[?(@.persistentVolumeClaim)]}{.persistentVolumeClaim.claimName}~{end}"
    '{"\\n"}{end}'
)

# Compact per-event jsonpath row: namespace|involvedKind|involvedName|reason|message|lastTimestamp|eventTime.
# Never `-o json` - only the fields find_storage_events actually reads are requested.
_EVENT_STORAGE_JSONPATH = (
    "{range .items[*]}{.metadata.namespace}|{.involvedObject.kind}|{.involvedObject.name}|"
    '{.reason}|{.message}|{.lastTimestamp}|{.eventTime}{"\\n"}{end}'
)

_STORAGE_BATCH_SECTION_RE = re.compile(
    r"===BEGIN:(?P<label>[^=]+)===\n(?P<body>.*?)\n===END:(?P=label):EXIT=(?P<code>-?\d+)===", re.DOTALL
)


def _build_storage_batch_script(ns_flag: str) -> str:
    """Build the single script covering all 5 storage queries in ONE Run Command invocation.

    pvc/pv/storageclass stay small even cluster-wide, so they keep using full `-o json`. pods/
    events use the compact jsonpath templates above instead - see module docstring for why.
    """
    sections = {
        "pvc": f"get pvc {ns_flag} -o json",
        "pv": "get pv -o json",
        "storageclass": "get storageclass -o json",
        "pods": f"get pods {ns_flag} -o jsonpath='{_POD_STORAGE_JSONPATH}'",
        "events": f"get events {ns_flag} -o jsonpath='{_EVENT_STORAGE_JSONPATH}'",
    }
    lines: list[str] = []
    for label, kubectl_args in sections.items():
        lines.append(f"RAW=$(kubectl {kubectl_args} 2>/dev/null)")
        lines.append("CODE=$?")
        lines.append(f"echo '===BEGIN:{label}==='")
        lines.append('echo "$RAW"')
        lines.append(f"echo '===END:{label}:EXIT='$CODE'==='")
    return "\n".join(lines)


def _parse_storage_batch_output(raw_output: str) -> dict[str, tuple[int, str]]:
    """Parse the combined script output into {label: (exit_code, body)} for all 5 queries."""
    return {
        match.group("label"): (int(match.group("code")), match.group("body"))
        for match in _STORAGE_BATCH_SECTION_RE.finditer(raw_output)
    }


def _parse_pod_storage_rows(raw_rows: str) -> tuple[list[dict[str, Any]], int]:
    """Convert compact pod rows back into the nested pod shape find_pod_storage_failures/
    classify_pvcs already expect, so those functions (and their existing tests) are unchanged.

    Returns (pods, malformed_row_count) - a malformed row is skipped, never silently ignored.
    """
    pods: list[dict[str, Any]] = []
    malformed = 0
    for line in raw_rows.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split("|")
        if len(fields) != 5:
            malformed += 1
            continue

        namespace, name, phase, containers_raw, volumes_raw = fields
        container_statuses = []
        for token in containers_raw.split("~"):
            if not token:
                continue
            reason, _, message = token.partition("^")
            container_statuses.append({"state": {"waiting": {"reason": reason or None, "message": message or None}}})

        volumes = [{"persistentVolumeClaim": {"claimName": claim}} for claim in volumes_raw.split("~") if claim]

        pods.append(
            {
                "metadata": {"namespace": namespace or None, "name": name or None},
                "spec": {"volumes": volumes},
                "status": {"phase": phase or None, "containerStatuses": container_statuses},
            }
        )

    return pods, malformed


def _parse_event_storage_rows(raw_rows: str) -> tuple[list[dict[str, Any]], int]:
    """Convert compact event rows back into the nested event shape find_storage_events expects.

    Returns (events, malformed_row_count).
    """
    events: list[dict[str, Any]] = []
    malformed = 0
    for line in raw_rows.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split("|")
        if len(fields) != 7:
            malformed += 1
            continue

        namespace, kind, name, reason, message, last_timestamp, event_time = fields
        events.append(
            {
                "metadata": {"namespace": namespace or None},
                "reason": reason or None,
                "message": message or None,
                "involvedObject": {"kind": kind or None, "name": name or None, "namespace": namespace or None},
                "lastTimestamp": last_timestamp or None,
                "eventTime": event_time or None,
            }
        )

    return events, malformed


def _extract_pod_storage_rows(batch: dict[str, tuple[int, str]], query_errors: list[str]) -> list[dict[str, Any]]:
    """Pull compact pod rows out of the batched output and convert them to nested pod objects.

    Mirrors _extract_items' error handling (missing label / non-zero exit are query errors, never
    a silent empty result), but parses compact jsonpath rows instead of `-o json`.
    """
    entry = batch.get("pods")
    if entry is None:
        query_errors.append("pods: no result returned in the batched output.")
        return []

    exit_code, raw_rows = entry
    if exit_code != 0:
        query_errors.append(f"pods: kubectl exited with code {exit_code}; query could not be executed.")
        return []
    if not raw_rows.strip():
        return []

    pods, malformed = _parse_pod_storage_rows(raw_rows)
    if malformed:
        query_errors.append(f"pods: {malformed} row(s) in the compact batched output could not be parsed.")
    return pods


def _extract_event_storage_rows(batch: dict[str, tuple[int, str]], query_errors: list[str]) -> list[dict[str, Any]]:
    """Pull compact event rows out of the batched output and convert them to nested event objects."""
    entry = batch.get("events")
    if entry is None:
        query_errors.append("events: no result returned in the batched output.")
        return []

    exit_code, raw_rows = entry
    if exit_code != 0:
        query_errors.append(f"events: kubectl exited with code {exit_code}; query could not be executed.")
        return []
    if not raw_rows.strip():
        return []

    events, malformed = _parse_event_storage_rows(raw_rows)
    if malformed:
        query_errors.append(f"events: {malformed} row(s) in the compact batched output could not be parsed.")
    return events


def aks_check_storage(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str | None = None,
) -> dict[str, Any]:
    """Check PVC/PV/StorageClass/pod/event health for upgrade-blocking storage issues.

    All 5 queries are issued in a single AKS Run Command invocation (see module docstring):
    pvc/pv/storageclass use full `-o json` (small even cluster-wide), while pods/events use
    compact `-o jsonpath` rows carrying only the fields needed for classification. A query
    failure is treated as unknown (not empty) and recorded in query_errors; storage_health is
    only ever HEALTHY when there are no blockers, warnings, AND no query_errors.
    """
    if namespace is not None:
        validate_namespace(namespace)

    ns_flag = f"-n {namespace}" if namespace else "-A"

    script = _build_storage_batch_script(ns_flag)
    raw_output = run_kubectl_raw(subscription_id, resource_group, cluster_name, script)
    batch = _parse_storage_batch_output(raw_output)

    query_errors: list[str] = []
    pvc_items = _extract_items("pvc", batch, query_errors)
    pv_items = _extract_items("pv", batch, query_errors)
    sc_items = _extract_items("storageclass", batch, query_errors)
    pod_items = _extract_pod_storage_rows(batch, query_errors)

    events_query_errors: list[str] = []
    event_items = _extract_event_storage_rows(batch, events_query_errors)
    events_available = not events_query_errors
    events_error = events_query_errors[0] if events_query_errors else None
    query_errors.extend(events_query_errors)

    storage_classes, storage_classes_by_name = summarize_storage_classes(sc_items)
    pod_storage_failures = find_pod_storage_failures(pod_items)
    storage_events = find_storage_events(event_items)
    pvcs = classify_pvcs(pvc_items, pod_items, storage_classes_by_name, pod_storage_failures)
    pvs = classify_pvs(pv_items)

    blockers: list[str] = []
    warnings: list[str] = []

    for item in pvcs["problematic"]:
        (blockers if item["severity"] == "BLOCKER" else warnings).append(
            f"PVC {item['namespace']}/{item['name']}: {item['reason']}"
        )

    for item in pvs["unbound_or_problematic"]:
        (blockers if item["severity"] == "BLOCKER" else warnings).append(f"PV {item['name']}: {item['reason']}")

    for failure in pod_storage_failures:
        blockers.append(
            f"Pod {failure['namespace']}/{failure['name']}: storage-related failure ({failure.get('reason')})."
        )

    for event in storage_events:
        warnings.append(
            f"Event for {event.get('involved_kind')}/{event.get('involved_object')} "
            f"in {event.get('namespace') or 'cluster-scope'}: {event.get('reason')} - {event.get('message')}"
        )

    recommendations: list[str] = []
    if blockers:
        recommendations.append("Investigate blocking PVC/PV/pod storage issues before proceeding with an upgrade.")
    if not events_available:
        recommendations.append("Kubernetes events could not be retrieved; storage diagnostics may be incomplete.")
    if query_errors:
        recommendations.append("Storage assessment is incomplete because some storage checks could not be executed.")
    if not blockers and not warnings and not query_errors:
        recommendations.append("No storage issues detected.")

    return {
        "subscription_id": subscription_id,
        "resource_group": resource_group,
        "cluster_name": cluster_name,
        "scope": namespace or "all-namespaces",
        "storage_health": determine_storage_health(blockers, warnings, query_errors),
        "pvcs": pvcs,
        "pvs": pvs,
        "storage_classes": storage_classes,
        "pod_storage_failures": {"count": len(pod_storage_failures), "pods": pod_storage_failures},
        "storage_events": {
            "count": len(storage_events),
            "events_available": events_available,
            "events": storage_events,
            "error": events_error,
        },
        "run_command_invocations": 1,
        "query_errors": query_errors,
        "blockers": blockers,
        "warnings": warnings,
        "recommendations": recommendations,
    }
