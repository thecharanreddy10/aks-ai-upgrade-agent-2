from __future__ import annotations

import pytest

from tools.cli_operations import _command_tokens, _validate_kubectl


def test_kubectl_read_can_inspect_nodes() -> None:
    tokens = _command_tokens("kubectl get nodes", "kubectl")
    _validate_kubectl(tokens, write=False)


def test_kubectl_read_can_inspect_pvcs() -> None:
    tokens = _command_tokens("kubectl get pvc -A", "kubectl")
    _validate_kubectl(tokens, write=False)


def test_kubectl_write_cannot_delete_pvc() -> None:
    tokens = _command_tokens("kubectl delete pvc data -n default", "kubectl")
    with pytest.raises(PermissionError):
        _validate_kubectl(tokens, write=True)
