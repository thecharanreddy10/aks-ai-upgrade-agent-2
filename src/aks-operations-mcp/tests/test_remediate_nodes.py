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
NODE_NAME = "aks-nodepool1-12345678-abcde"
NODE = {
    "kind": "Node",
    "metadata": {"name": NODE_NAME},
    "status": {},
}


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
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: NODE)

    with pytest.raises(ValueError, match="Unknown strategy"):
        aks_remediate_node(
            *CLUSTER_ARGS,
            NODE_NAME,
            strategy="unknown_strategy",
        )


def test_remediate_node_not_found(monkeypatch):
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: {})

    with pytest.raises(ValueError, match="not found"):
        aks_remediate_node(*CLUSTER_ARGS, "missing-node")


def test_plan_drain_node_generates_cordon_and_drain():
    plan = _plan_drain_node(NODE_NAME)

    assert plan["strategy"] == "drain_node"
    assert len(plan["steps"]) == 2

    cordon_step = plan["steps"][0]
    assert cordon_step["type"] == "cordon"
    assert f"kubectl cordon {NODE_NAME}" in cordon_step["kubectl_command"]
    assert f"kubectl uncordon {NODE_NAME}" == cordon_step["rollback_command"]

    drain_step = plan["steps"][1]
    assert drain_step["type"] == "drain"
    assert "kubectl drain" in drain_step["kubectl_command"]
    assert "--ignore-daemonsets" in drain_step["kubectl_command"]
    assert "--delete-emptydir-data" in drain_step["kubectl_command"]


def test_plan_drain_node_includes_uncordon_command():
    plan = _plan_drain_node(NODE_NAME)

    assert "uncordon_command" in plan
    assert f"kubectl uncordon {NODE_NAME}" in plan["uncordon_command"]


def test_plan_drain_node_includes_verification():
    plan = _plan_drain_node(NODE_NAME)

    assert "post_drain_verification" in plan
    assert NODE_NAME in plan["post_drain_verification"]["command"]
    assert "daemonset-managed pods may remain" in plan["post_drain_verification"]["expected"]


def test_plan_restart_node_generates_noninteractive_reboot_command():
    plan = _plan_restart_node(NODE_NAME)

    assert plan["strategy"] == "restart_node"
    assert len(plan["steps"]) == 1

    restart_step = plan["steps"][0]
    assert restart_step["type"] == "restart"
    assert "kubectl debug node" in restart_step["kubectl_command"]
    assert "--profile=sysadmin" in restart_step["kubectl_command"]
    assert "--image=busybox:1.36" in restart_step["kubectl_command"]
    assert "-it" not in restart_step["kubectl_command"]
    assert "chroot /host shutdown -r" in restart_step["kubectl_command"]


def test_plan_restart_node_includes_monitoring():
    plan = _plan_restart_node(NODE_NAME)

    assert "monitoring" in plan
    assert "check_command" in plan["monitoring"]
    assert NODE_NAME in plan["monitoring"]["check_command"]


def test_dry_run_drain_returns_plan_without_execution(monkeypatch):
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: NODE)
    monkeypatch.setattr(
        remediate_nodes,
        "run_kubectl_raw",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("should not execute")),
    )

    result = aks_remediate_node(
        *CLUSTER_ARGS,
        NODE_NAME,
        strategy="drain_node",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert "plan" in result


def test_dry_run_restart_returns_plan_without_execution(monkeypatch):
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: NODE)
    monkeypatch.setattr(
        remediate_nodes,
        "run_kubectl_raw",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("should not execute")),
    )

    result = aks_remediate_node(
        *CLUSTER_ARGS,
        NODE_NAME,
        strategy="restart_node",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert "plan" in result


def test_write_succeeds_when_write_gate_is_enabled(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: NODE)
    commands = []

    def _run_raw(*_args, **_kwargs):
        commands.append(_args[-1])
        return "ok"

    monkeypatch.setattr(remediate_nodes, "run_kubectl_raw", _run_raw)

    result = aks_remediate_node(
        *CLUSTER_ARGS,
        NODE_NAME,
        strategy="drain_node",
        dry_run=False,
        check_mode="full",
    )

    assert result["status"] == "applied"
    assert len(commands) == 2


def test_write_requires_full_check_mode(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: NODE)

    with pytest.raises(PermissionError, match="check_mode"):
        aks_remediate_node(
            *CLUSTER_ARGS,
            NODE_NAME,
            strategy="drain_node",
            dry_run=False,
            check_mode="quick",
        )


def test_failed_drain_returns_rollback_for_completed_cordon(monkeypatch):
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: NODE)
    calls = []

    def _run_raw(*_args, **_kwargs):
        calls.append(_args[-1])
        if len(calls) == 2:
            raise RuntimeError("drain failed")
        return "cordoned"

    monkeypatch.setattr(remediate_nodes, "run_kubectl_raw", _run_raw)

    result = aks_remediate_node(
        *CLUSTER_ARGS,
        NODE_NAME,
        strategy="drain_node",
        dry_run=False,
        check_mode="full",
    )

    assert result["status"] == "failed"
    assert result["applied_changes"][0]["type"] == "cordon"
    assert result["rollback_steps"] == [
        {
            "type": "rollback",
            "kind": "Node",
            "name": NODE_NAME,
            "command": f"kubectl uncordon {NODE_NAME}",
        }
    ]


def test_drain_plan_ignores_daemonsets():
    """Verify drain plan explicitly ignores daemonsets."""
    plan = _plan_drain_node(NODE_NAME)
    drain_cmd = plan["steps"][1]["kubectl_command"]
    assert "--ignore-daemonsets" in drain_cmd


def test_drain_plan_allows_empty_dir_deletion():
    """Verify drain plan explicitly opts into deletion of local emptyDir data."""
    plan = _plan_drain_node(NODE_NAME)
    drain_cmd = plan["steps"][1]["kubectl_command"]
    assert "--delete-emptydir-data" in drain_cmd


def test_restart_plan_uses_kubectl_debug_node():
    """Verify restart strategy uses kubectl debug node with a privileged profile."""
    plan = _plan_restart_node(NODE_NAME)
    restart_cmd = plan["steps"][0]["kubectl_command"]
    assert "kubectl debug node" in restart_cmd
    assert NODE_NAME in restart_cmd
    assert "--profile=sysadmin" in restart_cmd
