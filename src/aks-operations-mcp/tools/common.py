"""Shared AKS client, command, and remediation-guardrail helpers for MCP tools."""

from __future__ import annotations

import json
import os
import re
import secrets
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.mgmt.containerservice import ContainerServiceClient

try:
    from azure.mgmt.containerservice.models import ManagedClusterRunCommandRequest as RunCommandRequest
except ImportError:
    from azure.mgmt.containerservice.models import RunCommandRequest

# Namespaces whose objects must never be mutated by a remediation tool. `aks-command` holds the
# transient pods AKS Run Command creates for our own queries, so it is both infrastructure and a
# source of false-positive "unhealthy pod" findings.
PROTECTED_NAMESPACES = frozenset(
    {
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "aks-command",
        "gatekeeper-system",
        "calico-system",
        "tigera-operator",
    }
)

# Pods in these namespaces are artifacts of this tool's own operation, not real workload failures.
INFRA_ARTIFACT_NAMESPACES = frozenset({"aks-command"})

_NAMESPACE_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_K8S_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")


def validate_namespace(namespace: str) -> None:
    """Reject anything that isn't a valid Kubernetes namespace name (RFC 1123 label).

    namespace ends up embedded in a shell command run via AKS Run Command, so this also
    prevents shell-metacharacter injection via this parameter.
    """
    if not isinstance(namespace, str) or len(namespace) > 63 or not _NAMESPACE_RE.match(namespace):
        raise ValueError(f"Invalid Kubernetes namespace: {namespace!r}")


def validate_k8s_name(value: str, kind: str = "resource") -> None:
    """Reject anything that isn't a valid Kubernetes object name (RFC 1123 subdomain).

    Same shell-injection concern as validate_namespace: object names are interpolated into
    kubectl commands executed through AKS Run Command.
    """
    if not isinstance(value, str) or len(value) > 253 or not _K8S_NAME_RE.match(value):
        raise ValueError(f"Invalid Kubernetes {kind} name: {value!r}")


def assert_namespace_not_protected(namespace: str | None) -> None:
    """Refuse to mutate cluster-critical or tool-owned namespaces."""
    if namespace in PROTECTED_NAMESPACES:
        raise PermissionError(
            f"Namespace {namespace!r} is protected and cannot be modified by remediation tools. "
            f"Protected namespaces: {', '.join(sorted(PROTECTED_NAMESPACES))}."
        )


def require_remediation_approval(
    check_mode: str,
    approval_token: str | None,
    namespace: str | None = None,
    is_destructive: bool = False,
    confirm_destructive: bool = False,
) -> None:
    """Enforce write gates for remediation tools.

    The approval token is intentionally resolved server-side when the caller does not supply one.
    This lets an agent request an approved remediation without receiving the secret token itself.
    The runtime still fails closed unless AKS_REMEDIATION_APPROVAL_TOKEN is configured and
    AKS_REMEDIATION_ENABLE_WRITE=true.
    """
    if check_mode != "full":
        raise PermissionError("Remediation write operations require check_mode='full'.")

    if os.getenv("AKS_REMEDIATION_ENABLE_WRITE", "false").lower() != "true":
        raise PermissionError(
            "Remediation write operations are disabled. Set AKS_REMEDIATION_ENABLE_WRITE=true to enable."
        )

    expected_token = os.getenv("AKS_REMEDIATION_APPROVAL_TOKEN")
    if not expected_token:
        raise PermissionError(
            "AKS_REMEDIATION_APPROVAL_TOKEN is not configured; remediation cannot be approved."
        )

    # Never require the LLM/agent to know the secret. If a caller supplies a token, validate it;
    # otherwise use the server-configured token as the service-side approval.
    candidate_token = approval_token or expected_token
    if not secrets.compare_digest(candidate_token, expected_token):
        raise PermissionError("Invalid approval token for remediation execution.")

    assert_namespace_not_protected(namespace)

    if is_destructive and not confirm_destructive:
        raise PermissionError(
            "This remediation permanently deletes cluster objects; pass confirm_destructive=True to proceed."
        )


def get_container_service_client(subscription_id: str) -> ContainerServiceClient:
    """Create a ContainerServiceClient using managed identity/default credentials.

    If AZURE_CLIENT_ID is set, it pins DefaultAzureCredential to that user-assigned
    identity so resolution is unambiguous if more than one identity is ever attached.
    """
    client_id = os.getenv("AZURE_CLIENT_ID")
    credential = DefaultAzureCredential(managed_identity_client_id=client_id) if client_id else DefaultAzureCredential()
    return ContainerServiceClient(credential=credential, subscription_id=subscription_id)


def run_kubectl_json(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    kubectl_arguments: str,
) -> dict[str, Any]:
    """Run a kubectl command through AKS run command and parse JSON output."""
    full_command = f"kubectl {kubectl_arguments} -o json"
    raw_logs = _execute_run_command(subscription_id, resource_group, cluster_name, full_command)

    if not raw_logs:
        raise RuntimeError("AKS run command did not return logs output.")

    payload = _extract_json_payload(raw_logs)
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        truncation_hint = (
            " Output length is at/near AKS Run Command's known output size limit; the result was "
            "likely truncated. Retry with a namespace-scoped query (-n <namespace>) instead of -A."
            if len(raw_logs) >= 524288
            else ""
        )
        raise RuntimeError(
            f"Failed to parse kubectl JSON output for '{full_command}' (raw output length={len(raw_logs)}): {exc}."
            f"{truncation_hint}"
        ) from exc


def _extract_json_payload(output: str) -> str:
    """Extract the first JSON document from mixed command output."""
    first_obj = output.find("{")
    first_arr = output.find("[")

    candidates = [idx for idx in (first_obj, first_arr) if idx != -1]
    if not candidates:
        raise ValueError("No JSON payload found in command output.")

    start = min(candidates)
    end_obj = output.rfind("}")
    end_arr = output.rfind("]")
    end = max(end_obj, end_arr)

    if end < start:
        raise ValueError("Invalid JSON boundaries in command output.")

    return output[start : end + 1]


def _execute_run_command(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    command: str,
) -> str | None:
    """Submit a single AKS Run Command invocation and return its raw log text."""
    client = get_container_service_client(subscription_id)
    request_obj = RunCommandRequest(command=command)
    try:
        poller = client.managed_clusters.begin_run_command(
            resource_group_name=resource_group,
            resource_name=cluster_name,
            request_payload=request_obj,
        )
    except TypeError:
        poller = client.managed_clusters.begin_run_command(
            resource_group_name=resource_group,
            resource_name=cluster_name,
            request=request_obj,
        )
    result = poller.result()
    return getattr(result, "logs", None)


def run_kubectl_raw(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    command: str,
) -> str:
    """Run an arbitrary shell/kubectl command through AKS run command; return raw log text as-is.

    Unlike run_kubectl_json, this does not assume `-o json` output and performs no JSON parsing -
    intended for compact, custom-formatted batched queries (e.g. deprecated API detection) where
    the caller controls the exact output format and needs a single Run Command invocation to cover
    multiple checks instead of one invocation per check (AKS Run Command has ~25-35s per-invocation
    overhead, so batching is the primary lever for reducing wall-clock time).
    """
    raw_logs = _execute_run_command(subscription_id, resource_group, cluster_name, command)
    if not raw_logs:
        raise RuntimeError("AKS run command did not return logs output.")
    return raw_logs


_BATCH_SECTION_RE = re.compile(r"===BEGIN:(?P<label>[^=]+)===\n(?P<body>.*?)\n===END:(?P=label):EXIT=(?P<code>-?\d+)===", re.DOTALL)


def run_kubectl_batch(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    queries: dict[str, str],
) -> dict[str, tuple[int, str]]:
    """Run multiple `kubectl get ... -o json` queries in a SINGLE AKS Run Command invocation.

    `queries` maps a caller-chosen label to kubectl arguments (without `-o json`, which is added
    automatically). Returns {label: (exit_code, raw_json_text)}. Each query's kubectl exit code is
    captured via command substitution (never through a pipe, which would lose it), so callers can
    distinguish a genuine query failure (non-zero exit) from a valid empty result - a failed query
    must be treated as an explicit error, never as an empty/healthy result.
    """
    lines: list[str] = []
    for label, kubectl_args in queries.items():
        lines.append(f"RAW=$(kubectl {kubectl_args} -o json 2>/dev/null)")
        lines.append("CODE=$?")
        lines.append(f"echo '===BEGIN:{label}==='")
        lines.append('echo "$RAW"')
        lines.append(f"echo '===END:{label}:EXIT='$CODE'===")
    script = "\n".join(lines)

    raw_output = run_kubectl_raw(subscription_id, resource_group, cluster_name, script)

    return {
        match.group("label"): (int(match.group("code")), match.group("body"))
        for match in _BATCH_SECTION_RE.finditer(raw_output)
    }
