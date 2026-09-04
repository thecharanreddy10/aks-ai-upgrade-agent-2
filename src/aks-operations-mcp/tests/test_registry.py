"""Tests for the shared tool registry that keeps both entrypoints in sync."""

from __future__ import annotations

from tools.registry import ALL_TOOLS, build_input_schema, tool_description
from tools.validation import aks_check_pdb, aks_check_pod_health


def test_tool_names_are_unique():
    names = [tool.__name__ for tool in ALL_TOOLS]
    assert len(names) == len(set(names))


def test_every_tool_has_a_description():
    for tool in ALL_TOOLS:
        assert tool_description(tool).strip()


def test_schema_marks_cluster_args_required_and_namespace_optional():
    schema = build_input_schema(aks_check_pod_health)

    assert schema["type"] == "object"
    assert schema["required"] == ["subscription_id", "resource_group", "cluster_name"]
    assert schema["properties"]["subscription_id"] == {"type": "string"}
    assert schema["properties"]["namespace"] == {"type": ["string", "null"]}


def test_schema_generated_for_every_registered_tool():
    for tool in ALL_TOOLS:
        schema = build_input_schema(tool)
        assert schema["properties"], f"{tool.__name__} produced an empty schema"
        for arg in ("subscription_id", "resource_group", "cluster_name"):
            assert arg in schema["properties"]


def test_boolean_and_optional_defaults_are_not_required():
    schema = build_input_schema(aks_check_pdb)
    assert "namespace" not in schema["required"]


def test_function_app_surface_matches_registry():
    # function_app.py derives its tables from ALL_TOOLS; assert the derivation itself holds.
    tools = {tool.__name__: tool for tool in ALL_TOOLS}
    schemas = {name: build_input_schema(tool) for name, tool in tools.items()}
    assert set(tools) == set(schemas)
    assert len(tools) == len(ALL_TOOLS)


def test_remediation_schemas_do_not_expose_approval_token():
    affected_tools = {
        "aks_remediate_pdb",
        "aks_rollback_pdb_remediation",
        "aks_remediate_pods",
        "aks_remediate_node",
        "aks_remediate_storage",
    }
    schemas = {
        tool.__name__: build_input_schema(tool)
        for tool in ALL_TOOLS
        if tool.__name__ in affected_tools
    }

    assert set(schemas) == affected_tools
    for schema in schemas.values():
        assert "approval_token" not in schema["properties"]
