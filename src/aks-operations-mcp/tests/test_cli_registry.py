from __future__ import annotations

from tools.registry import ALL_TOOLS, build_input_schema


def test_generic_cli_tools_are_registered() -> None:
    names = {tool.__name__ for tool in ALL_TOOLS}
    assert {
        "aks_kubectl_read",
        "aks_kubectl_write",
        "aks_az_read",
        "aks_az_write",
    } <= names


def test_generic_cli_write_tools_have_no_approval_token() -> None:
    for tool in ALL_TOOLS:
        if tool.__name__ in {"aks_kubectl_write", "aks_az_write"}:
            assert "approval_token" not in build_input_schema(tool)["properties"]


def test_kubectl_write_schema_exposes_structured_command_tokens() -> None:
    tool = next(tool for tool in ALL_TOOLS if tool.__name__ == "aks_kubectl_write")
    schema = build_input_schema(tool)

    assert schema["properties"]["command_tokens"] == {
        "anyOf": [
            {"type": "array", "items": {"type": "string"}},
            {"type": "null"},
        ]
    }
