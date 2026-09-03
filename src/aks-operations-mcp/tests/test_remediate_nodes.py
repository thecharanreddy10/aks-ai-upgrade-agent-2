"""Tests for node remediation: strategy planning, validation, and procedures."""

from __future__ import annotations

import pytest

from tools import remediate_nodes
from tools.remediate_nodes import aks_remediate_node, _plan_drain_node, _plan_restart_node

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_remediate_node_rejects_unsafe_node_name(monkeypatch):
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("validation must reject unsafe node_name before any query")))
    with pytest.raises(ValueError, match="node"):
        aks_remediate_node(*CLUSTER_ARGS, "$(id)")


def test_remediate_node_rejects_shell_injection_in_name(monkeypatch):
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("validation must reject injection before any query")))
    with pytest.raises(ValueError, match="node"):
        aks_remediate_node(*CLUSTER_ARGS, "node; rm -rf /")


def test_remediate_node_invalid_strategy(monkeypatch):
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: {"kind": "Node", "metadata": {"name": "aks-nodepool1-12345678-abcde"}, "status": {}})
    with pytest.raises(ValueError, match="Unknown strategy"):
        aks_remediate_node(*CLUSTER_ARGS, "aks-nodepool1-12345678-abcde", strategy="unknown_strategy")


def test_remediate_node_not_found(monkeypatch):
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: {})
    with pytest.raises(ValueError, match="not found"):
        aks_remediate_node(*CLUSTER_ARGS, "missing-node")


def test_plan_drain_node_generates_cordon_and_drain():
    node_name = "aks-nodepool1-12345678-abcde"
    plan = _plan_drain_node(node_name)
    assert plan["strategy"] == "drain_node"
    assert len(plan["steps"]) == 2
    assert f"kubectl cordon {node_name}" in plan["steps"][0]["kubectl_command"]
    assert "kubectl drain" in plan["steps"][1]["kubectl_command"]
    assert "--ignore-daemonsets" in plan["steps"][1]["kubectl_command"]
    assert "--delete-emptydir-data" in plan["steps"][1]["kubectl_command"]


def test_plan_drain_node_includes_uncordon_command():
    node_name = "aks-nodepool1-12345678-abcde"
    plan = _plan_drain_node(node_name)
    assert f"kubectl uncordon {node_name}" in plan["uncordon_command"]


def test_plan_drain_node_includes_verification():
    node_name = "aks-nodepool1-12345678-abcde"
    assert node_name in _plan_drain_node(node_name)["post_drain_verification"]["command"]


def test_plan_restart_node_generates_reboot_command():
    node_name = "aks-nodepool1-12345678-abcde"
    plan = _plan_restart_node(node_name)
    assert plan["strategy"] == "restart_node"
    assert "kubectl debug node" in plan["steps"][0]["kubectl_command"]
    assert "chroot /host shutdown -r" in plan["steps"][0]["kubectl_command"]


def test_plan_restart_node_includes_monitoring():
    node_name = "aks-nodepool1-12345678-abcde"
    plan = _plan_restart_node(node_name)
    assert "check_command" in plan["monitoring"]
    assert node_name in plan["monitoring"]["check_command"]


def test_dry_run_drain_returns_plan_without_execution(monkeypatch):
    node = {"kind": "Node", "metadata": {"name": "aks-nodepool1-12345678-abcde"}, "status": {}}
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: node)
    monkeypatch.setattr(remediate_nodes, "run_kubectl_raw", lambda *_a, **_k: "should not run")
    result = aks_remediate_node(*CLUSTER_ARGS, "aks-nodepool1-12345678-abcde", strategy="drain_node", dry_run=True)
    assert result["status"] == "dry_run"
    assert "approval_token" not in result["message"]


def test_dry_run_restart_returns_plan_without_execution(monkeypatch):
    node = {"kind": "Node", "metadata": {"name": "aks-nodepool1-12345678-abcde"}, "status": {}}
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: node)
    monkeypatch.setattr(remediate_nodes, "run_kubectl_raw", lambda *_a, **_k: "should not run")
    result = aks_remediate_node(*CLUSTER_ARGS, "aks-nodepool1-12345678-abcde", strategy="restart_node", dry_run=True)
    assert result["status"] == "dry_run"


def test_write_still_requires_full_check_mode(monkeypatch):
    node = {"kind": "Node", "metadata": {"name": "aks-nodepool1-12345678-abcde"}, "status": {}}
    monkeypatch.setattr(remediate_nodes, "run_kubectl_json", lambda *_a, **_k: node)
    monkeypatch.setenv("AKS_REMEDIATION_ENABLE_WRITE", "true")
    with pytest.raises(PermissionError, match="check_mode"):
        aks_remediate_node(*CLUSTER_ARGS, "aks-nodepool1-12345678-abcde", strategy="drain_node", dry_run=False, check_mode="quick")


def test_drain_plan_ignores_daemonsets():
    assert "--ignore-daemonsets" in _plan_drain_node("aks-nodepool1-12345678-abcde")["steps"][1]["kubectl_command"]


def test_drain_plan_allows_empty_dir_deletion():
    assert "--delete-emptydir-data" in _plan_drain_node("aks-nodepool1-12345678-abcde")["steps"][1]["kubectl_command"]


def test_restart_plan_uses_kubectl_debug_node():
    command = _plan_restart_node("aks-nodepool1-12345678-abcde")["steps"][0]["kubectl_command"]
    assert "kubectl debug node" in command
