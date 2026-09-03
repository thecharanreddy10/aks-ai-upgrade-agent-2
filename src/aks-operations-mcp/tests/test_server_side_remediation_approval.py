from __future__ import annotations

import pytest

from tools.common import require_remediation_approval


def test_remediation_can_use_server_side_approval(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    monkeypatch.setenv("AKS_REMEDIATION_APPROVAL_TOKEN", "test-server-token")

    # The agent does not need to receive or send the secret token.
    require_remediation_approval("full", None, "phonebook")


def test_remediation_still_requires_full_check_mode(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    monkeypatch.setenv("AKS_REMEDIATION_APPROVAL_TOKEN", "test-server-token")

    with pytest.raises(PermissionError, match="check_mode='full'"):
        require_remediation_approval("quick", None, "phonebook")


def test_remediation_still_fails_closed_when_write_disabled(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "false")
    monkeypatch.setenv("AKS_REMEDIATION_APPROVAL_TOKEN", "test-server-token")

    with pytest.raises(PermissionError, match="disabled"):
        require_remediation_approval("full", None, "phonebook")
