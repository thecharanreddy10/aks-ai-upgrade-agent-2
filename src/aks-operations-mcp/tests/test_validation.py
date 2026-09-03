"""Tests for pod-health parsing, infra-artifact separation, and PDB input validation."""

from __future__ import annotations

import pytest

from tools import validation
from tools.validation import _parse_pod_health_output, aks_check_pdb, aks_check_pod_health

CLUSTER_ARGS = ("sub-id", "rg", "cluster")


def test_parse_pod_health_output_reads_rows_and_exit_code():
    raw = "default|web-1|Running|2|CrashLoopBackOff|True||False\n===PODS_EXIT=0===\n"
    rows, exit_code, errors = _parse_pod_health_output(raw)

    assert exit_code == 0
    assert errors == []
    assert rows == [
        {
            "namespace": "default",
            "name": "web-1",
            "phase": "Running",
            "restart_count": 2,
            "waiting_reasons": ["CrashLoopBackOff"],
            "scheduled_status": "True",
            "scheduled_reason": None,
            "ready_status": "False",
        }
    ]


def test_parse_pod_health_output_missing_exit_marker_is_a_failure():
    # -1 is never a real kubectl exit code, so a missing marker can't be mistaken for success.
    rows, exit_code, _errors = _parse_pod_health_output("default|web-1|Running|0||True||True\n")
    assert exit_code == -1
    assert len(rows) == 1


def test_parse_pod_health_output_records_malformed_rows():
    raw = "too|few|fields\n===PODS_EXIT=0===\n"
    rows, _exit_code, errors = _parse_pod_health_output(raw)

    assert rows == []
    assert len(errors) == 1
    assert "expected 8 fields" in errors[0]


def test_parse_pod_health_output_sums_restarts_across_containers():
    raw = "default|web-1|Running|3 4||||\n===PODS_EXIT=0===\n"
    rows, _exit_code, errors = _parse_pod_health_output(raw)
    assert errors == []
    assert rows[0]["restart_count"] == 7


def test_aks_command_pods_are_not_reported_as_blockers(monkeypatch):
    raw = (
        "aks-command|command-abc|Pending|0|ContainerCreating|True||False\n"
        "phonebook|web-1|Pending|0|ContainerCreating|True||False\n"
        "default|healthy-1|Running|0||True||True\n"
        "===PODS_EXIT=0===\n"
    )
    monkeypatch.setattr(validation, "run_kubectl_raw", lambda *_a, **_k: raw)

    result = aks_check_pod_health(*CLUSTER_ARGS)

    assert [pod["namespace"] for pod in result["unhealthy_pods"]] == ["phonebook"]
    assert [pod["namespace"] for pod in result["infra_artifact_pods"]] == ["aks-command"]
    assert all(pod["is_infra_artifact"] for pod in result["infra_artifact_pods"])
    assert result["total_pods"] == 3
    assert result["healthy_pods"] == 1
    assert result["pod_health_status"] == "UNHEALTHY"


def test_only_infra_artifacts_reports_healthy(monkeypatch):
    raw = (
        "aks-command|command-abc|Pending|0|ContainerCreating|True||False\n"
        "default|healthy-1|Running|0||True||True\n"
        "===PODS_EXIT=0===\n"
    )
    monkeypatch.setattr(validation, "run_kubectl_raw", lambda *_a, **_k: raw)

    result = aks_check_pod_health(*CLUSTER_ARGS)

    assert result["unhealthy_pods"] == []
    assert result["pod_health_status"] == "HEALTHY"


def test_failed_query_never_reports_healthy(monkeypatch):
    def _boom(*_args, **_kwargs):
        raise RuntimeError("run command failed")

    monkeypatch.setattr(validation, "run_kubectl_raw", _boom)

    result = aks_check_pod_health(*CLUSTER_ARGS)

    assert result["pod_health_status"] == "INCOMPLETE"
    assert result["query_errors"]


def test_nonzero_exit_discards_rows(monkeypatch):
    raw = "default|web-1|Running|0||True||True\n===PODS_EXIT=1===\n"
    monkeypatch.setattr(validation, "run_kubectl_raw", lambda *_a, **_k: raw)

    result = aks_check_pod_health(*CLUSTER_ARGS)

    assert result["total_pods"] == 0
    assert result["pod_health_status"] == "INCOMPLETE"


@pytest.mark.parametrize("bad_namespace", ["default; rm -rf /", "$(id)", "UPPER"])
def test_pod_health_rejects_unsafe_namespace(monkeypatch, bad_namespace):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("kubectl must not run for an invalid namespace")

    monkeypatch.setattr(validation, "run_kubectl_raw", _should_not_run)

    with pytest.raises(ValueError):
        aks_check_pod_health(*CLUSTER_ARGS, namespace=bad_namespace)


@pytest.mark.parametrize("bad_namespace", ["default; rm -rf /", "$(id)", "UPPER"])
def test_pdb_rejects_unsafe_namespace(monkeypatch, bad_namespace):
    def _should_not_run(*_args, **_kwargs):
        raise AssertionError("kubectl must not run for an invalid namespace")

    monkeypatch.setattr(validation, "run_kubectl_json", _should_not_run)

    with pytest.raises(ValueError):
        aks_check_pdb(*CLUSTER_ARGS, namespace=bad_namespace)


def test_pdb_flags_blocking_budget(monkeypatch):
    payload = {
        "items": [
            {
                "metadata": {"namespace": "phonebook", "name": "webserver-pdb"},
                "status": {
                    "disruptionsAllowed": 0,
                    "expectedPods": 2,
                    "currentHealthy": 2,
                    "desiredHealthy": 2,
                },
            },
            {
                "metadata": {"namespace": "shop", "name": "api-pdb"},
                "status": {
                    "disruptionsAllowed": 1,
                    "expectedPods": 3,
                    "currentHealthy": 3,
                    "desiredHealthy": 2,
                },
            },
        ]
    }
    monkeypatch.setattr(validation, "run_kubectl_json", lambda *_a, **_k: payload)

    result = aks_check_pdb(*CLUSTER_ARGS)

    assert result["is_upgrade_safe"] is False
    assert [pdb["name"] for pdb in result["blocking_pdbs"]] == ["webserver-pdb"]
