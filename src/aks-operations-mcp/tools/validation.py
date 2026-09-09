"""Validation tools for AKS operations.

Performance/correctness note (2026-08-31): aks_check_pod_health previously ran
`kubectl get pods -A -o json`, which returns FULL pod objects (env vars, volume mounts,
resource specs, labels/annotations, ownerReferences, etc.) for every pod cluster-wide. This
can exceed AKS Run Command's 512 KiB output limit on clusters with many pods, causing the
query to fail entirely with no pod-health data at all. It has been replaced with a single
`kubectl get pods ... -o jsonpath=...` invocation (see _POD_JSONPATH) that emits only the
compact fields needed for health classification, one line per pod - never full JSON. This
is still exactly one AKS Run Command call; the fix is about per-pod payload size, not call
count.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

from tools.common import (
    INFRA_ARTIFACT_NAMESPACES,
    get_container_service_client,
    run_kubectl_batch,
    run_kubectl_json,
    run_kubectl_raw,
    validate_k8s_name,
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
    """Parse the compact per-pod jsonpath rows. Returns (rows, exit_code, parse_errors)."""
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
    """Check pod status, restart counts, scheduling, and readiness issues."""
    if namespace is not None:
        validate_namespace(namespace)

    ns_flag = f"-n {namespace}" if namespace else "-A"
    script = _build_pod_health_script(ns_flag)

    query_errors: list[str] = []
    rows: list[dict[str, Any]] = []
    try:
        raw_output = run_kubectl_raw(subscription_id, resource_group, cluster_name, script)
    except Exception as exc:  # noqa: BLE001
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


_SELECTOR_RE = re.compile(r"^[A-Za-z0-9_.\-/=,!()\s]+$")


def _validate_selector(selector: str) -> None:
    """Apply a conservative label-selector grammar before embedding it in kubectl arguments."""
    if not isinstance(selector, str) or not selector.strip() or len(selector) > 256 or not _SELECTOR_RE.fullmatch(selector):
        raise ValueError(f"Invalid Kubernetes label selector: {selector!r}")


def _scope_flag(namespace: str | None) -> str:
    if namespace is not None:
        validate_namespace(namespace)
        return f"-n {namespace}"
    return "-A"


def _parse_batch_json(batch: dict[str, tuple[int, str]], label: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse one batched kubectl JSON section and return items plus query errors."""
    if label not in batch:
        return [], [f"{label}: batched kubectl section missing"]
    exit_code, raw_json = batch[label]
    if exit_code != 0:
        return [], [f"{label}: kubectl exited with code {exit_code}"]
    if not raw_json.strip():
        return [], [f"{label}: kubectl returned no JSON output"]
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        return [], [f"{label}: invalid JSON output: {exc}"]
    return payload.get("items", []), []


def aks_check_single_replica_services(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str | None = None,
    label_selector: str | None = None,
) -> dict[str, Any]:
    """Check configured critical Cerebral Plus workloads for single-replica risk.

    This validation never guesses which workloads are Cerebral Plus. Callers must provide a
    namespace and/or label selector that identifies the critical service set. Deployments and
    StatefulSets are checked in one batched AKS Run Command invocation.
    """
    if namespace is not None:
        validate_namespace(namespace)
    if namespace is None and label_selector is None:
        return {
            "status": "NOT_CONFIGURED",
            "scope": namespace or "all-namespaces",
            "matched_workloads": [],
            "single_replica_workloads": [],
            "query_errors": [],
            "recommendation": "Configure a Cerebral Plus namespace and/or label selector before using this check.",
        }
    if label_selector is not None:
        _validate_selector(label_selector)

    scope = _scope_flag(namespace)
    selector = f"-l {label_selector}" if label_selector else ""
    batch = run_kubectl_batch(
        subscription_id,
        resource_group,
        cluster_name,
        {
            "deployments": f"get deployments {scope} {selector}".strip(),
            "statefulsets": f"get statefulsets {scope} {selector}".strip(),
        },
    )

    deployment_items, deployment_errors = _parse_batch_json(batch, "deployments")
    statefulset_items, statefulset_errors = _parse_batch_json(batch, "statefulsets")
    query_errors = deployment_errors + statefulset_errors

    matched_workloads: list[dict[str, Any]] = []
    single_replica_workloads: list[dict[str, Any]] = []
    for kind, items in (("Deployment", deployment_items), ("StatefulSet", statefulset_items)):
        for item in items:
            metadata = item.get("metadata", {})
            spec = item.get("spec", {})
            status = item.get("status", {})
            replicas = int(spec.get("replicas", 1) or 0)
            available = int(status.get("availableReplicas", status.get("readyReplicas", 0)) or 0)
            entry = {
                "namespace": metadata.get("namespace"),
                "name": metadata.get("name"),
                "kind": kind,
                "desired_replicas": replicas,
                "available_replicas": available,
                "selector": spec.get("selector", {}).get("matchLabels", {}),
            }
            matched_workloads.append(entry)
            if replicas == 1:
                single_replica_workloads.append(entry)

    status = "INCOMPLETE" if query_errors else ("WARNING" if single_replica_workloads else "PASS")
    return {
        "status": status,
        "scope": namespace or "all-namespaces",
        "label_selector": label_selector,
        "matched_workloads": matched_workloads,
        "single_replica_workloads": single_replica_workloads,
        "query_errors": query_errors,
        "run_command_invocations": 1,
        "recommendation": "Scale critical single-replica Cerebral Plus workloads to 2 before node-drain-based upgrades.",
    }


def _extract_observable_version(item: dict[str, Any]) -> str | None:
    """Extract the best available operator version without inventing a target version."""
    metadata = item.get("metadata", {})
    labels = metadata.get("labels", {}) or {}
    annotations = metadata.get("annotations", {}) or {}
    for key in ("app.kubernetes.io/version", "app.kubernetes.io/managed-by", "helm.sh/chart"):
        value = labels.get(key) or annotations.get(key)
        if value:
            return str(value)
    containers = item.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []) or []
    for container in containers:
        image = container.get("image")
        if image:
            return str(image).rsplit("@", 1)[0].rsplit(":", 1)[-1]
    return None


def aks_check_operator_health(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    environment: str = "SIT",
    namespace: str | None = None,
    operator_selector: str | None = None,
    target_version: str | None = None,
) -> dict[str, Any]:
    """Check configured operator workloads for SIT without performing Helm upgrades.

    The operator set must be explicitly identified by namespace and/or label selector. The
    validation reports health and observable version information; it only compares versions when
    a target_version is explicitly supplied.
    """
    if environment.upper() != "SIT":
        return {
            "status": "SKIPPED",
            "environment": environment,
            "reason": "Operator upgrade validation is enabled for SIT only.",
            "operators": [],
            "query_errors": [],
        }
    if namespace is not None:
        validate_namespace(namespace)
    if operator_selector is None:
        return {
            "status": "NOT_CONFIGURED",
            "environment": "SIT",
            "scope": namespace or "all-namespaces",
            "operators": [],
            "query_errors": [],
            "recommendation": "Configure the SIT operator namespace and/or label selector.",
        }
    _validate_selector(operator_selector)

    scope = _scope_flag(namespace)
    selector = f"-l {operator_selector}"
    batch = run_kubectl_batch(
        subscription_id,
        resource_group,
        cluster_name,
        {
            "deployments": f"get deployments {scope} {selector}".strip(),
            "statefulsets": f"get statefulsets {scope} {selector}".strip(),
        },
    )
    deployment_items, deployment_errors = _parse_batch_json(batch, "deployments")
    statefulset_items, statefulset_errors = _parse_batch_json(batch, "statefulsets")
    query_errors = deployment_errors + statefulset_errors

    operators: list[dict[str, Any]] = []
    unhealthy: list[dict[str, Any]] = []
    version_mismatches: list[dict[str, Any]] = []
    for kind, items in (("Deployment", deployment_items), ("StatefulSet", statefulset_items)):
        for item in items:
            metadata = item.get("metadata", {})
            spec = item.get("spec", {})
            status = item.get("status", {})
            desired = int(spec.get("replicas", 1) or 0)
            available = int(status.get("availableReplicas", status.get("readyReplicas", 0)) or 0)
            current_version = _extract_observable_version(item)
            healthy = desired == available and desired > 0
            entry = {
                "namespace": metadata.get("namespace"),
                "name": metadata.get("name"),
                "kind": kind,
                "desired_replicas": desired,
                "available_replicas": available,
                "healthy": healthy,
                "current_version": current_version,
            }
            if target_version is not None:
                entry["target_version"] = target_version
                entry["version_matches_target"] = current_version == target_version
                if current_version is not None and current_version != target_version:
                    version_mismatches.append(entry)
            operators.append(entry)
            if not healthy:
                unhealthy.append(entry)

    status = "BLOCKED" if unhealthy else ("WARNING" if version_mismatches else ("INCOMPLETE" if query_errors else "PASS"))
    return {
        "status": status,
        "environment": "SIT",
        "scope": namespace or "all-namespaces",
        "operator_selector": operator_selector,
        "operators": operators,
        "unhealthy_operators": unhealthy,
        "version_mismatches": version_mismatches,
        "query_errors": query_errors,
        "run_command_invocations": 1,
    }


def _parse_max_surge(value: Any, node_count: int) -> dict[str, Any]:
    """Parse an AKS maxSurge value while preserving its original representation."""
    raw = str(value) if value is not None else None
    if raw is None or raw == "":
        return {"raw": raw, "kind": "unset", "surge_nodes": None}
    if raw.endswith("%"):
        try:
            percent = float(raw[:-1])
        except ValueError:
            return {"raw": raw, "kind": "invalid", "surge_nodes": None}
        return {
            "raw": raw,
            "kind": "percent",
            "percent": percent,
            "surge_nodes": math.ceil(node_count * percent / 100),
        }
    try:
        surge_nodes = int(raw)
    except ValueError:
        return {"raw": raw, "kind": "invalid", "surge_nodes": None}
    return {"raw": raw, "kind": "count", "surge_nodes": surge_nodes}


def _is_user_node_pool(pool: Any) -> bool:
    """Match User pools across Azure SDK enum and string representations."""
    mode = getattr(pool, "mode", None)
    mode_value = getattr(mode, "value", mode)
    return str(mode_value).lower() == "user"


def aks_check_node_pool_surge(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    node_pool_name: str | None = None,
) -> dict[str, Any]:
    """Check maxSurge for user-mode AKS node pools; recommend 33% for a 10-node pool."""
    if node_pool_name is not None:
        validate_k8s_name(node_pool_name, "node pool")

    client = get_container_service_client(subscription_id)
    pools = list(client.agent_pools.list(resource_group, cluster_name))
    selected = [pool for pool in pools if _is_user_node_pool(pool)]
    if node_pool_name is not None:
        selected = [pool for pool in selected if getattr(pool, "name", None) == node_pool_name]

    pool_results: list[dict[str, Any]] = []
    recommendations: list[dict[str, Any]] = []
    for pool in selected:
        count = int(getattr(pool, "count", 0) or 0)
        upgrade_settings = getattr(pool, "upgrade_settings", None)
        max_surge = getattr(upgrade_settings, "max_surge", None) if upgrade_settings else None
        parsed = _parse_max_surge(max_surge, count)
        applicable = count == 10
        compliant = False
        if applicable:
            compliant = (
                parsed.get("kind") == "percent" and math.isclose(float(parsed.get("percent", 0)), 33.0, abs_tol=1e-9)
            ) or (parsed.get("kind") == "count" and parsed.get("surge_nodes") == 4)
        entry = {
            "name": getattr(pool, "name", None),
            "mode": getattr(pool, "mode", None),
            "node_count": count,
            "current_max_surge": max_surge,
            "parsed_max_surge": parsed,
            "applicable_10_node_rule": applicable,
            "recommended_max_surge": "33%" if applicable else None,
            "recommended_surge_nodes": 4 if applicable else None,
            "status": "PASS" if applicable and compliant else ("WARNING" if applicable else "NOT_APPLICABLE"),
        }
        pool_results.append(entry)
        if applicable and not compliant:
            recommendations.append({
                "pool_name": getattr(pool, "name", None),
                "current_max_surge": max_surge,
                "recommended_max_surge": "33%",
                "recommended_surge_nodes": 4,
            })

    if not selected:
        status = "NOT_FOUND" if node_pool_name else "INCOMPLETE"
    elif recommendations:
        status = "WARNING"
    else:
        status = "PASS"

    return {
        "status": status,
        "user_pools_checked": len(selected),
        "node_pools": pool_results,
        "recommendations": recommendations,
        "severity": "recommendation",
        "query_errors": [],
    }


def aks_check_priority_class(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    namespace: str = "kube-system",
    critical_selector: str | None = None,
) -> dict[str, Any]:
    """Check explicitly identified critical system pods use system-cluster-critical."""
    validate_namespace(namespace)
    if critical_selector is None:
        return {
            "status": "NOT_CONFIGURED",
            "namespace": namespace,
            "checked_pods": [],
            "violations": [],
            "query_errors": [],
            "recommendation": "Configure a critical-system pod label selector before enabling this check.",
        }
    _validate_selector(critical_selector)

    payload = run_kubectl_json(
        subscription_id,
        resource_group,
        cluster_name,
        f"get pods -n {namespace} -l {critical_selector}",
    )
    items = payload.get("items", [])
    checked: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    for item in items:
        metadata = item.get("metadata", {})
        priority_class = metadata.get("priorityClassName") or item.get("spec", {}).get("priorityClassName")
        entry = {
            "namespace": metadata.get("namespace"),
            "name": metadata.get("name"),
            "priority_class": priority_class,
            "expected_priority_class": "system-cluster-critical",
            "compliant": priority_class == "system-cluster-critical",
        }
        checked.append(entry)
        if not entry["compliant"]:
            violations.append(entry)

    return {
        "status": "WARNING" if violations else "PASS",
        "namespace": namespace,
        "critical_selector": critical_selector,
        "checked_pods": checked,
        "violations": violations,
        "query_errors": [],
        "severity": "recommendation",
        "recommendation": "Critical system pods should use priorityClassName=system-cluster-critical for upgrade surge scheduling preference.",
    }
