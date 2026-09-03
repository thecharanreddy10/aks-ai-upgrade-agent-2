"""Shared AKS client, command, and remediation-guardrail helpers for MCP tools."""

from __future__ import annotations

import json
import os
import re
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.mgmt.containerservice import ContainerServiceClient

try:
    from azure.mgmt.containerservice.models import ManagedClusterRunCommandRequest as RunCommandRequest
except ImportError:
    from azure.mgmt.containerservice.models import RunCommandRequest

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

INFRA_ARTIFACT_NAMESPACES = frozenset({"aks-command"})

_NAMESPACE_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_K8S_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")


def validate_namespace(namespace: str) -> None:
    """Reject anything that isn't a valid Kubernetes namespace name (RFC 1123 label)."""
    if not isinstance(namespace, str) or len(namespace) > 63 or not _NAMESPACE_RE.match(namespace):
        raise ValueError(f"Invalid Kubernetes namespace: {namespace!r}")


def validate_k8s_name(value: str, kind: str = "resource") -> None:
    """Reject anything that isn't a valid Kubernetes object name (RFC 1123 subdomain)."""
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
    namespace: str | None = None,
    is_destructive: bool = False,
    confirm_destructive: bool = False,
) -> None:
    """Enforce write guardrails without an application-level approval token.

    Authorization is provided by the explicit full-check/write gates and the MCP runtime's
    Azure/Kubernetes identity. No secret token is accepted, read, or validated here.
    """
    if check_mode != "full":
        raise PermissionError("Remediation write operations require check_mode='full'.")

    if os.getenv("AKS_REMEDIATION_ENABLE_WRITE", "false").lower() != "true":
        raise PermissionError(
            "Remediation write operations are disabled. Set AKS_REMEDIATION_ENABLE_WRITE=true to enable."
        )

    assert_namespace_not_protected(namespace)

    if is_destructive and not confirm_destructive:
        raise PermissionError(
            "This remediation permanently deletes cluster objects; pass confirm_destructive=True to proceed."
        )


def get_container_service_client(subscription_id: str) -> ContainerServiceClient:
    """Create a ContainerServiceClient using managed identity/default credentials."""
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
    """Run an arbitrary shell/kubectl command through AKS run command."""
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
    """Run multiple `kubectl get ... -o json` queries in a single AKS Run Command invocation."""
    lines: list[str] = []
    for label, kubectl_args in queries.items():
        lines.append(f"RAW=$(kubectl {kubectl_args} -o json 2>/dev/null)")
        lines.append("CODE=$?")
        lines.append("echo '===BEGIN:" + label + "==='")
        lines.append('echo "$RAW"')
        lines.append("echo '===END:" + label + ":EXIT='$CODE'==='" )
    script = "\n".join(lines)

    raw_output = run_kubectl_raw(subscription_id, resource_group, cluster_name, script)

    return {
        match.group("label"): (int(match.group("code")), match.group("body"))
        for match in _BATCH_SECTION_RE.finditer(raw_output)
    }
