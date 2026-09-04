from __future__ import annotations

import pytest

from tools.common import require_remediation_approval


def test_remediation_write_gate_allows_full_check_mode(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    require_remediation_approval("full", "phonebook")


def test_remediation_still_requires_full_check_mode(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")

    with pytest.raises(PermissionError, match="check_mode='full'"):
        require_remediation_approval("quick", "phonebook")


def test_remediation_still_fails_closed_when_write_disabled(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "false")

    with pytest.raises(PermissionError, match="disabled"):
        require_remediation_approval("full", "phonebook")
