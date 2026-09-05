from __future__ import annotations

import pytest

from tools.cli_operations import (
    _command_tokens,
    _validate_az,
    _validate_kubectl,
)


def test_kubectl_read_allowlist_accepts_get_and_describe() -> None:
    for command in ("kubectl get pods -A", "kubectl get nodes", "kubectl describe pod web -n default"):
        tokens = _command_tokens(command, "kubectl")
        _validate_kubectl(tokens, write=False)


def test_kubectl_read_rejects_write_subcommands() -> None:
    tokens = _command_tokens("kubectl delete pod web -n default", "kubectl")
    with pytest.raises(PermissionError):
        _validate_kubectl(tokens, write=False)


def test_kubectl_rejects_shell_operators() -> None:
    with pytest.raises(ValueError):
        _command_tokens("kubectl get pods; rm -rf /", "kubectl")


def test_kubectl_write_rejects_protected_resource_types() -> None:
    tokens = _command_tokens("kubectl patch pvc data -n default --type merge -p '{}'", "kubectl")
    with pytest.raises(PermissionError):
        _validate_kubectl(tokens, write=True)


def test_kubectl_write_rejects_protected_namespaces() -> None:
    tokens = _command_tokens("kubectl patch deployment web -n kube-system --type merge -p '{}'", "kubectl")
    with pytest.raises(PermissionError):
        _validate_kubectl(tokens, write=True)


def test_kubectl_write_allows_rollout_restart() -> None:
    tokens = _command_tokens("kubectl rollout restart deployment web -n default", "kubectl")
    _validate_kubectl(tokens, write=True)


def test_kubectl_write_rejects_all_delete() -> None:
    tokens = _command_tokens("kubectl delete pod --all -n default", "kubectl")
    with pytest.raises(PermissionError):
        _validate_kubectl(tokens, write=True)


def test_azure_read_accepts_aks_show() -> None:
    tokens = _command_tokens("az aks show -g rg -n cluster", "az")
    _validate_az(tokens, write=False)


def test_azure_read_rejects_write_command() -> None:
    tokens = _command_tokens("az aks nodepool update -g rg --cluster-name cluster -n nodepool --max-surge 20%", "az")
    with pytest.raises(PermissionError):
        _validate_az(tokens, write=False)


def test_azure_write_allows_nodepool_update() -> None:
    tokens = _command_tokens("az aks nodepool update -g rg --cluster-name cluster -n nodepool --max-surge 20%", "az")
    _validate_az(tokens, write=True)


def test_azure_write_rejects_delete() -> None:
    tokens = _command_tokens("az aks delete -g rg -n cluster", "az")
    with pytest.raises(PermissionError):
        _validate_az(tokens, write=True)
