"""Controlled generic kubectl and Azure CLI operations for AKS investigation/remediation.

These tools intentionally avoid an application-level approval token. Azure/Kubernetes
identity and the existing remediation write gate provide authorization, while explicit
command allowlists constrain what the agent can execute.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from typing import Any

from tools.common import run_kubectl_raw

_KUBECTL_READ_COMMANDS = frozenset(
    {
        "get",
        "describe",
        "logs",
        "explain",
        "api-resources",
        "api-versions",
        "auth",
        "top",
        "version",
    }
)

_KUBECTL_WRITE_COMMANDS = frozenset(
    {
        "patch",
        "scale",
        "rollout",
        "annotate",
        "label",
        "delete",
    }
)

_AZ_READ_COMMANDS = (
    ("aks", "show"),
    ("aks", "get-upgrades"),
    ("aks", "nodepool", "list"),
    ("aks", "nodepool", "show"),
    ("aks", "addon", "list"),
    ("resource", "show"),
)

_AZ_WRITE_COMMANDS = (
    ("aks", "nodepool", "update"),
    ("aks", "nodepool", "upgrade"),
)

_BLOCKED_KUBECTL_TOKENS = frozenset(
    {
        "namespace",
        "namespaces",
        "crd",
        "customresourcedefinition",
        "clusterrole",
        "clusterrolebinding",
        "rolebinding",
        "node",
        "persistentvolume",
        "pv",
        "pvc",
    }
)

_BLOCKED_AZ_TOKENS = frozenset(
    {
        "delete",
        "remove",
        "purge",
        "role",
        "policy",
        "lock",
        "group",
        "subscription",
    }
)


def _command_tokens(command: str, expected_cli: str) -> list[str]:
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a non-empty string")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError(f"Invalid command quoting: {exc}") from exc
    if not tokens or tokens[0].lower() != expected_cli:
        raise ValueError(f"command must start with '{expected_cli}'")
    if any(token in {"|", ";", "&&", "||", ">", ">>", "<", "`"} or token.startswith("$") for token in tokens):
        raise ValueError("shell operators and variable expansion are not allowed")
    return tokens


def _validate_kubectl(tokens: list[str], *, write: bool) -> None:
    base = tokens[1].lower()
    allowed = _KUBECTL_WRITE_COMMANDS if write else _KUBECTL_READ_COMMANDS
    if base not in allowed:
        raise PermissionError(f"kubectl subcommand '{base}' is not allowed for this operation")

    if any(token.lower() in _BLOCKED_KUBECTL_TOKENS for token in tokens[1:]):
        raise PermissionError("The requested kubectl resource is protected from generic CLI operations")

    if write and base == "delete":
        if any(token.lower() in {"namespace", "node", "pvc", "pv", "crd"} for token in tokens[1:]):
            raise PermissionError("Generic deletion of protected resource types is not allowed")
        if "--all" in tokens:
            raise PermissionError("Generic --all deletion is not allowed")

    if write and base == "rollout":
        if len(tokens) < 3 or tokens[2].lower() not in {"restart"}:
            raise PermissionError("Only 'kubectl rollout restart' is allowed")


def _validate_az(tokens: list[str], *, write: bool) -> None:
    lowered = [token.lower() for token in tokens[1:]]
    candidates = _AZ_WRITE_COMMANDS if write else _AZ_READ_COMMANDS
    if not any(tuple(lowered[: len(prefix)]) == prefix for prefix in candidates):
        raise PermissionError("The requested Azure CLI operation is not allowlisted")
    if any(token in _BLOCKED_AZ_TOKENS for token in lowered):
        raise PermissionError("The requested Azure CLI operation contains a blocked operation")


def _run_azure_cli(command: str) -> str:
    completed = subprocess.run(
        shlex.split(command, posix=True),
        check=False,
        capture_output=True,
        text=True,
        timeout=int(os.getenv("AKS_CLI_TIMEOUT_SECONDS", "120")),
    )
    output = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
    if completed.returncode != 0:
        raise RuntimeError(f"Azure CLI command failed with exit code {completed.returncode}: {output.strip()}")
    return output.strip()


def aks_kubectl_read(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    command: str,
) -> dict[str, Any]:
    """Run an allowlisted read-only kubectl command against an AKS cluster."""
    tokens = _command_tokens(command, "kubectl")
    _validate_kubectl(tokens, write=False)
    raw = run_kubectl_raw(subscription_id, resource_group, cluster_name, shlex.join(tokens))
    return {"command": shlex.join(tokens), "output": raw}


def aks_kubectl_write(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
    command: str,
    check_mode: str = "quick",
    confirm_destructive: bool = False,
) -> dict[str, Any]:
    """Run a tightly allowlisted kubectl write operation without an application approval token."""
    if check_mode != "full":
        raise PermissionError("kubectl write operations require check_mode='full'.")
    if os.getenv("AKS_REMEDIATION_ENABLE_WRITE", "false").lower() != "true":
        raise PermissionError("kubectl write operations are disabled. Set AKS_REMEDIATION_ENABLE_WRITE=true to enable.")

    tokens = _command_tokens(command, "kubectl")
    _validate_kubectl(tokens, write=True)

    destructive = tokens[1].lower() == "delete"
    if destructive and not confirm_destructive:
        raise PermissionError("This CLI operation deletes cluster objects; pass confirm_destructive=True to proceed.")

    raw = run_kubectl_raw(subscription_id, resource_group, cluster_name, shlex.join(tokens))
    return {"command": shlex.join(tokens), "output": raw, "destructive": destructive}


def aks_az_read(command: str) -> dict[str, Any]:
    """Run an allowlisted read-only Azure CLI command using the container's Azure identity."""
    tokens = _command_tokens(command, "az")
    _validate_az(tokens, write=False)
    raw = _run_azure_cli(shlex.join(tokens))
    return {"command": shlex.join(tokens), "output": raw}


def aks_az_write(
    command: str,
    check_mode: str = "quick",
) -> dict[str, Any]:
    """Run a tightly allowlisted Azure CLI write operation without an application approval token."""
    if check_mode != "full":
        raise PermissionError("Azure CLI write operations require check_mode='full'.")
    if os.getenv("AKS_REMEDIATION_ENABLE_WRITE", "false").lower() != "true":
        raise PermissionError("Azure CLI write operations are disabled. Set AKS_REMEDIATION_ENABLE_WRITE=true to enable.")

    tokens = _command_tokens(command, "az")
    _validate_az(tokens, write=True)
    raw = _run_azure_cli(shlex.join(tokens))
    return {"command": shlex.join(tokens), "output": raw}
