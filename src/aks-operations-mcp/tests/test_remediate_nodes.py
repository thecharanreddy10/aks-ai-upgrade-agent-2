"""Tests for node remediation: strategy planning, node validation, and drain/restart procedures."""

from __future__ import annotations

import pytest

from tools import remediate_nodes
from tools.remediate_nodes import (
    aks_remediate_node,
    _plan_drain_node,
    _plan_restart_node,
)

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_remediate_node_rejects_unsafe_node_name(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject unsafe node_name before any query")

    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError, match="node"):
        aks_remediate_node(*CLUSTER_ARGS, "$(id)")


def test_remediate_node_rejects_shell_injection_in_name(monkeypatch):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("validation must reject injection before any query")

    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError, match="node"):
        aks_remediate_node(*CLUSTER_ARGS, "node; rm -rf /")


def test_remediate_node_invalid_strategy(monkeypatch):
    node = {
        "kind": "Node",
        "metadata": {"name": "aks-nodepool1-12345678-abcde"},
        "status": {},
    }
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: node)

    with pytest.raises(ValueError, match="Unknown strategy"):
        aks_remediate_node(
            *CLUSTER_ARGS,
            "aks-nodepool1-12345678-abcde",
            strategy="unknown_strategy",
        )


def test_remediate_node_not_found(monkeypatch):
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: {})

    with pytest.raises(ValueError, match="not found"):
        aks_remediate_node(*CLUSTER_ARGS, "missing-node")


def test_plan_drain_node_generates_cordon_and_drain():
    node_name = "aks-nodepool1-12345678-abcde"
    plan = _plan_drain_node(node_name)

    assert plan["strategy"] == "drain_node"
    assert len(plan["steps"]) == 2

    cordon_step = plan["steps"][0]
    assert cordon_step["type"] == "cordon"
    assert f"kubectl cordon {node_name}" in cordon_step["kubectl_command"]

    drain_step = plan["steps"][1]
    assert drain_step["type"] == "drain"
    assert "kubectl drain" in drain_step["kubectl_command"]
    assert "--ignore-daemonsets" in drain_step["kubectl_command"]
    assert "--delete-emptydir-data" in drain_step["kubectl_command"]


def test_plan_drain_node_includes_uncordon_command():
    node_name = "aks-nodepool1-12345678-abcde"
    plan = _plan_drain_node(node_name)

    assert "uncordon_command" in plan
    assert f"kubectl uncordon {node_name}" in plan["uncordon_command"]


def test_plan_drain_node_includes_verification():
    node_name = "aks-nodepool1-12345678-abcde"
    plan = _plan_drain_node(node_name)

    assert "post_drain_verification" in plan
    assert node_name in plan["post_drain_verification"]["command"]


def test_plan_restart_node_generates_reboot_command():
    node_name = "aks-nodepool1-12345678-abcde"
    plan = _plan_restart_node(node_name)

    assert plan["strategy"] == "restart_node"
    assert len(plan["steps"]) == 1

    restart_step = plan["steps"][0]
    assert restart_step["type"] == "restart"
    assert "kubectl debug node" in restart_step["kubectl_command"]
    assert "chroot /host shutdown -r" in restart_step["kubectl_command"]


def test_plan_restart_node_includes_monitoring():
    node_name = "aks-nodepool1-12345678-abcde"
    plan = _plan_restart_node(node_name)

    assert "monitoring" in plan
    assert "check_command" in plan["monitoring"]
    assert node_name in plan["monitoring"]["check_command"]


def test_dry_run_drain_returns_plan_without_execution(monkeypatch):
    node = {
        "kind": "Node",
        "metadata": {"name": "aks-nodepool1-12345678-abcde"},
        "status": {},
    }
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: node)
    monkeypatch.setattr(remediate_nodes, "run_kubectl_raw", lambda *_a, **_k: ("should not run"))

    result = aks_remediate_node(
        *CLUSTER_ARGS,
        "aks-nodepool1-12345678-abcde",
        strategy="drain_node",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert "plan" in result
    assert result["message"] == "Plan only; no cluster changes. Pass dry_run=False + approval_token to apply."


def test_dry_run_restart_returns_plan_without_execution(monkeypatch):
    node = {
        "kind": "Node",
        "metadata": {"name": "aks-nodepool1-12345678-abcde"},
        "status": {},
    }
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: node)
    monkeypatch.setattr(remediate_nodes, "run_kubectl_raw", lambda *_a, **_k: ("should not run"))

    result = aks_remediate_node(
        *CLUSTER_ARGS,
        "aks-nodepool1-12345678-abcde",
        strategy="restart_node",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert "plan" in result


def test_approval_gates_required_for_write(monkeypatch):
    node = {
        "kind": "Node",
        "metadata": {"name": "aks-nodepool1-12345678-abcde"},
        "status": {},
    }
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: node)

    with pytest.raises(PermissionError, match="check_mode"):
        aks_remediate_node(
            *CLUSTER_ARGS,
            "aks-nodepool1-12345678-abcde",
            strategy="drain_node",
            dry_run=False,
            check_mode="quick",
        )


def test_drain_plan_ignores_daemonsets():
    """Verify drain plan explicitly ignores daemonsets (don't evict system daemonsets)."""
    node_name = "aks-nodepool1-12345678-abcde"
    plan = _plan_drain_node(node_name)

    drain_cmd = plan["steps"][1]["kubectl_command"]
    assert "--ignore-daemonsets" in drain_cmd


def test_drain_plan_allows_empty_dir_deletion():
    """Verify drain plan allows deletion of pods with local storage."""
    node_name = "aks-nodepool1-12345678-abcde"
    plan = _plan_drain_node(node_name)

    drain_cmd = plan["steps"][1]["kubectl_command"]
    assert "--delete-emptydir-data" in drain_cmd


def test_restart_plan_uses_kubectl_debug_node():
    """Verify restart strategy uses kubectl debug node (privileged container access)."""
    node_name = "aks-nodepool1-12345678-abcde"
    plan = _plan_restart_node(node_name)

    restart_cmd = plan["steps"][0]["kubectl_command"]
    assert "kubectl debug node" in restart_cmd
    assert node_name in restart_cmd
