from __future__ import annotations

import pytest
from unittest.mock import patch

from tools.cli_operations import (
    _command_tokens,
    _validate_az,
    _validate_kubectl,
    aks_kubectl_write,
)


def test_kubectl_read_allowlist_accepts_get_and_describe() -> None:
    for command in (
        "kubectl get pods -A",
        "kubectl get nodes",
        "kubectl describe pod web -n default",
        "kubectl -n deprecated-api-tests get pods",
        "kubectl --namespace=deprecated-api-tests get pods",
        "kubectl get pods -n deprecated-api-tests",
    ):
        tokens = _command_tokens(command, "kubectl")
        _validate_kubectl(tokens, write=False)


def test_kubectl_read_rejects_write_subcommands() -> None:
    tokens = _command_tokens("kubectl delete pod web -n default", "kubectl")
    with pytest.raises(PermissionError):
        _validate_kubectl(tokens, write=False)


def test_kubectl_rejects_shell_operators() -> None:
    for command in (
        "kubectl get pods; rm -rf /",
        "kubectl get pods && rm -rf /",
        "kubectl get pods | something",
        "kubectl get pods > output.txt",
    ):
        with pytest.raises(ValueError):
            _command_tokens(command, "kubectl")


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


def test_kubectl_write_accepts_structured_git_repo_migration_tokens(monkeypatch) -> None:
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    patch_payload = (
        '[{"op":"remove","path":"/spec/template/spec/volumes/0/gitRepo"},'
        '{"op":"add","path":"/spec/template/spec/volumes/0/emptyDir","value":{}},'
        '{"op":"add","path":"/spec/template/spec/initContainers","value":[{'
        '"name":"git-sync","image":"k8s.gcr.io/git-sync/git-sync:v3.6.3",'
        '"args":["--repo=https://github.com/esricharnreddy/aks-gitrepo-api-test.git",'
        '"--rev=main","--dest=/git","--depth=1","--one-time"],'
        '"volumeMounts":[{"name":"git-source","mountPath":"/git"}]}]}]'
    )
    command_tokens = [
        "kubectl",
        "patch",
        "deployment",
        "gitrepo-test",
        "-n",
        "deprecated-api-tests",
        "--type=json",
        "-p",
        patch_payload,
    ]

    with patch("tools.cli_operations.run_kubectl_raw", return_value="patched") as run:
        result = aks_kubectl_write(
            "sub",
            "rg",
            "cluster",
            command_tokens=command_tokens,
            check_mode="full",
        )

    assert result["output"] == "patched"
    assert run.call_args.args[-1].startswith("kubectl patch deployment gitrepo-test")


def test_kubectl_write_structured_tokens_reject_shell_operators(monkeypatch) -> None:
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    with pytest.raises(ValueError):
        aks_kubectl_write(
            "sub",
            "rg",
            "cluster",
            command_tokens=["kubectl", "patch", "deployment", "gitrepo-test;", "-n", "default"],
            check_mode="full",
        )


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
