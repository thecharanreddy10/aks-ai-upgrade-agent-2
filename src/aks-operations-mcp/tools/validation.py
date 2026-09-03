"""Validation tools for AKS operations.

Performance/correctness note (2026-08-31): aks_check_pod_health previously ran
`kubectl get pods -A -o json`, which returns FULL pod objects (env vars, volume mounts,
resource specs, labels/annotations, ownerReferences, etc.) for every pod cluster-wide. This
can exceed AKS Run Command's 512 KiB output limit on clusters with many pods, causing the
query to fail entirely with no pod-health data at all. It has been replaced with a single
`kubectl get pods ... -o jsonpath=...` invocation (see _POD_JSONPATH) that emits only the
compact fields needed for health classification, one line per pod - never full JSON. This is
still exactly one AKS Run Command call; the fix is about per-pod payload size, not call count.
A query failure (non-zero kubectl exit, no output, or unparseable rows) is reported via
query_errors and pod_health_status="INCOMPLETE" - it is never converted into a "healthy"/empty
result, since 0 unhealthy pods found is not the same as "pods could not be checked".
"""

from __future__ import annotations

import re
from typing import Any

from tools.common import (
    INFRA_ARTIFACT_NAMESPACES,
    run_kubectl_json,
    run_kubectl_raw,
    validate_namespace,
)


def aks_check_node_health(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
) -> dict[str, Any]:
    """Check node readiness and pressure conditions."""
    payload = run_kubectl_json(subscription_id, resource_group, cluster_name, "get nodes")
    items = payload.get("items", [])

    unhealthy_nodes = []
    for node in items:
        node_name = node.get("metadata", {}).get("name")
        conditions = node.get("status", {}).get("conditions", [])
        condition_map = {item.get("type"): item.get("status") for item in conditions}

        not_ready = condition_map.get("Ready") != "True"
        pressure_flags = {
            "memory_pressure": condition_map.get("MemoryPressure") == "True",
            "disk_pressure": condition_map.get("DiskPressure") == "True",
            "pid_pressure": condition_map.get("PIDPressure") == "True",
        }

        if not_ready or any(pressure_flags.values()):
            unhealthy_nodes.append(
                {
                    "name": node_name,
                    "ready": not not_ready,
                    **pressure_flags,
                }
            )

    return {
        "cluster_name": cluster_name,
        "total_nodes": len(items),
        "healthy_nodes": len(items) - len(unhealthy_nodes),
        "unhealthy_nodes": unhealthy_nodes,
    }


_POD_FIELD_SEP = "|"
_POD_EXIT_RE = re.compile(r"===PODS_EXIT=(-?\d+)===")

# One compact line per pod: namespace|name|phase|restartCounts|waitingReasons|schedStatus|schedReason|readyStatus.
# Deliberately never `-o json` - only the fields needed for health classification are requested,
# which is what keeps cluster-wide output well under AKS Run Command's 512 KiB limit.
_POD_JSONPATH = (
    '{range .items[*]}{.metadata.namespace}|{.metadata.name}|{.status.phase}|'
    '{.status.containerStatuses[*].restartCount}|{.status.containerStatuses[*].state.waiting.reason}|'
    '{.status.conditions[?(@.type=="PodScheduled")].status}|{.status.conditions[?(@.type=="PodScheduled")].reason}|'
    '{.status.conditions[?(@.type=="Ready")].status}{"\\n"}{end}'
)


def _build_pod_health_script(ns_flag: str) -> str:
    """Build the single Run Command script that lists pods in the compact jsonpath format above."""
    get_args = f"get pods {ns_flag} -o jsonpath='{_POD_JSONPATH}'"
    return f'RAW=$(kubectl {get_args} 2>/dev/null)\nCODE=$?\necho "$RAW"\necho \'===PODS_EXIT=\'$CODE\'===\'\n'


def _parse_pod_health_output(raw_output: str) -> tuple[list[dict[str, Any]], int, list[str]]:
    """Parse the compact per-pod jsonpath rows. Returns (rows, exit_code, parse_errors).

    exit_code is -1 (never a valid kubectl exit code) if the exit marker itself is missing,
    which is treated as a query failure rather than silently returning zero pods.
    """
    match = _POD_EXIT_RE.search(raw_output)
    exit_code = int(match.group(1)) if match else -1
    body = raw_output[: match.start()] if match else raw_output

    rows: list[dict[str, Any]] = []
    parse_errors: list[str] = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split(_POD_FIELD_SEP)
        if len(fields) != 8:
            parse_errors.append(f"Malformed pod health row (expected 8 fields, got {len(fields)}): {line!r}")
            continue

        namespace, name, phase, restarts_raw, waiting_raw, sched_status, sched_reason, ready_status = fields
        restart_counts = [int(value) for value in restarts_raw.split() if value.isdigit()]
        rows.append(
            {
                "namespace": namespace or None,
                "name": name or None,
                "phase": phase or None,
                "restart_count": sum(restart_counts),
                "waiting_reasons": [value for value in waiting_raw.split() if value],
                "scheduled_status": sched_status or None,
                "scheduled_reason": sched_reason or None,
                "ready_status": ready_status or None,
            }
        )

    return rows, exit_code, parse_errors


def aks_check_pod_health(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str | None = None,
) -> dict[str, Any]:
    """Check pod status, restart counts, scheduling, and readiness issues.

    Uses a single AKS Run Command invocation with a compact `-o jsonpath` query (see module
    docstring/_POD_JSONPATH) instead of `-o json`, so cluster-wide queries stay well under AKS
    Run Command's 512 KiB output limit. A pod is unhealthy if its phase isn't Running/Succeeded,
    any container reports a waiting reason (CrashLoopBackOff, ImagePullBackOff/ErrImagePull,
    ContainerCreating, etc.), or it's Running but failing its readiness check.

    A query failure never produces a "healthy" result: pod_health_status is "INCOMPLETE" (with
    details in query_errors) whenever pods could not be listed/parsed and no unhealthy pods were
    otherwise confirmed - distinct from "HEALTHY", which means pods were actually checked.

    Pods in INFRA_ARTIFACT_NAMESPACES (the transient pods AKS Run Command creates to service
    these very queries) are reported separately and never counted as upgrade blockers.
    """
    if namespace is not None:
        validate_namespace(namespace)

    ns_flag = f"-n {namespace}" if namespace else "-A"
    script = _build_pod_health_script(ns_flag)

    query_errors: list[str] = []
    rows: list[dict[str, Any]] = []
    try:
        raw_output = run_kubectl_raw(subscription_id, resource_group, cluster_name, script)
    except Exception as exc:  # noqa: BLE001 - a query failure must surface as query_errors, not raise
        query_errors.append(f"pod health check failed: {exc}")
        raw_output = ""

    if raw_output:
        rows, exit_code, parse_errors = _parse_pod_health_output(raw_output)
        query_errors.extend(parse_errors)
        if exit_code != 0:
            query_errors.append(f"kubectl exited with code {exit_code}; pod list could not be retrieved.")
            rows = []

    unhealthy_pods = []
    infra_artifact_pods = []
    for row in rows:
        is_unhealthy = (
            row["phase"] not in ("Running", "Succeeded")
            or bool(row["waiting_reasons"])
            or (row["phase"] == "Running" and row["ready_status"] == "False")
        )
        if not is_unhealthy:
            continue
        entry = {
            "namespace": row["namespace"],
            "name": row["name"],
            "phase": row["phase"],
            "restart_count": row["restart_count"],
            "waiting_reasons": row["waiting_reasons"],
            "scheduled_reason": row["scheduled_reason"],
        }
        if row["namespace"] in INFRA_ARTIFACT_NAMESPACES:
            infra_artifact_pods.append({**entry, "is_infra_artifact": True})
            continue
        unhealthy_pods.append(entry)

    if unhealthy_pods:
        pod_health_status = "UNHEALTHY"
    elif query_errors:
        pod_health_status = "INCOMPLETE"
    else:
        pod_health_status = "HEALTHY"

    return {
        "cluster_name": cluster_name,
        "scope": namespace or "all-namespaces",
        "total_pods": len(rows),
        "healthy_pods": len(rows) - len(unhealthy_pods) - len(infra_artifact_pods),
        "unhealthy_pods": unhealthy_pods,
        "infra_artifact_pods": infra_artifact_pods,
        "pod_health_status": pod_health_status,
        "query_errors": query_errors,
        "run_command_invocations": 1,
    }


def aks_check_pdb(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str | None = None,
) -> dict[str, Any]:
    """Check Pod Disruption Budget constraints before upgrades."""
    if namespace is not None:
        validate_namespace(namespace)

    ns_flag = f"-n {namespace}" if namespace else "-A"
    payload = run_kubectl_json(subscription_id, resource_group, cluster_name, f"get pdb {ns_flag}")
    items = payload.get("items", [])

    blocking_pdbs = []
    for pdb in items:
        metadata = pdb.get("metadata", {})
        status = pdb.get("status", {})

        disruptions_allowed = int(status.get("disruptionsAllowed", 0) or 0)
        expected_pods = int(status.get("expectedPods", 0) or 0)
        current_healthy = int(status.get("currentHealthy", 0) or 0)
        desired_healthy = int(status.get("desiredHealthy", 0) or 0)

        if expected_pods > 0 and disruptions_allowed == 0:
            blocking_pdbs.append(
                {
                    "namespace": metadata.get("namespace"),
                    "name": metadata.get("name"),
                    "disruptions_allowed": disruptions_allowed,
                    "current_healthy": current_healthy,
                    "desired_healthy": desired_healthy,
                    "expected_pods": expected_pods,
                }
            )

    return {
        "cluster_name": cluster_name,
        "scope": namespace or "all-namespaces",
        "total_pdbs": len(items),
        "blocking_pdbs": blocking_pdbs,
        "is_upgrade_safe": len(blocking_pdbs) == 0,
    }
