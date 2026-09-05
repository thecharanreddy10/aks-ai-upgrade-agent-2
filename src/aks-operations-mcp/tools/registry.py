"""Single source of truth for the tools this server exposes.

Both entrypoints build their tool tables from ALL_TOOLS - the FastMCP server in main.py and
the Azure Functions JSON-RPC surface in function_app.py - so the two can no longer drift apart
as tools are added.
"""

from __future__ import annotations

import inspect
from typing import Any, Callable, get_args, get_type_hints

from tools.cli_operations import aks_az_read, aks_az_write, aks_kubectl_read, aks_kubectl_write
from tools.deprecated_apis import aks_check_deprecated_apis
from tools.discovery import (
    aks_get_available_upgrades,
    aks_get_cluster_details,
    aks_get_node_pools,
)
from tools.remediate_deprecated_apis import (
    aks_generate_deprecated_api_manifests,
    aks_remediate_deprecated_apis,
)
from tools.remediate_nodes import aks_remediate_node
from tools.remediate_pdb import aks_remediate_pdb, aks_rollback_pdb_remediation
from tools.remediate_pods import aks_remediate_pods
from tools.remediate_storage import aks_remediate_storage
from tools.resolve_upgrade_issue import aks_resolve_upgrade_issue
from tools.storage import aks_check_storage
from tools.upgrade import aks_upgrade_node_pool, aks_validate_upgrade_readiness
from tools.validation import aks_check_node_health, aks_check_pdb, aks_check_pod_health

ALL_TOOLS: tuple[Callable[..., dict[str, Any]], ...] = (
    aks_get_cluster_details,
    aks_get_node_pools,
    aks_get_available_upgrades,
    aks_check_node_health,
    aks_check_pod_health,
    aks_check_pdb,
    aks_check_storage,
    aks_check_deprecated_apis,
    aks_validate_upgrade_readiness,
    aks_upgrade_node_pool,
    aks_remediate_pdb,
    aks_rollback_pdb_remediation,
    aks_remediate_pods,
    aks_remediate_node,
    aks_remediate_storage,
    aks_remediate_deprecated_apis,
    aks_generate_deprecated_api_manifests,
    aks_kubectl_read,
    aks_kubectl_write,
    aks_az_read,
    aks_az_write,
    aks_resolve_upgrade_issue,
)

_JSON_TYPES: dict[Any, str] = {str: "string", int: "integer", float: "number", bool: "boolean"}


def _schema_for_annotation(annotation: Any) -> dict[str, Any]:
    """Map a Python annotation onto a minimal JSON Schema fragment."""
    union_args = get_args(annotation)
    if union_args:
        nullable = type(None) in union_args
        names = sorted({_JSON_TYPES[arg] for arg in union_args if arg in _JSON_TYPES})
        if not names:
            return {}
        return {"type": [*names, "null"] if nullable else (names[0] if len(names) == 1 else names)}

    mapped = _JSON_TYPES.get(annotation)
    return {"type": mapped} if mapped else {}


def build_input_schema(func: Callable[..., Any]) -> dict[str, Any]:
    """Derive a JSON Schema for a tool from its signature, so schemas can't fall out of sync."""
    hints = get_type_hints(func)
    properties: dict[str, Any] = {}
    required: list[str] = []

    for name, param in inspect.signature(func).parameters.items():
        properties[name] = _schema_for_annotation(hints.get(name))
        if param.default is inspect.Parameter.empty:
            required.append(name)

    return {"type": "object", "properties": properties, "required": required}


def tool_description(func: Callable[..., Any]) -> str:
    """First line of the tool's docstring, used as its advertised description."""
    doc = inspect.getdoc(func) or ""
    return doc.split("\n", 1)[0] or f"AKS operation: {func.__name__}"
