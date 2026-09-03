from __future__ import annotations

import pytest

from tools.common import require_remediation_approval


def test_remediation_does_not_require_application_token(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    monkeypatch.delenv("AKS_REMEDIATION_APPROVAL_TOKEN", raising=False)
    require_remediation_approval("full", namespace="phonebook")


def test_remediation_ignores_approval_token_when_present(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    monkeypatch.setenv("AKS_REMEDIATION_APPROVAL_TOKEN", "stale-token")
    require_remediation_approval("full", namespace="phonebook")


def test_remediation_still_requires_full_check_mode(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    with pytest.raises(PermissionError, match="check_mode='full'"):
        require_remediation_approval("quick", namespace="phonebook")


def test_remediation_still_fails_closed_when_write_disabled(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "false")
    with pytest.raises(PermissionError, match="disabled"):
        require_remediation_approval("full", namespace="phonebook")
