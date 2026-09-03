"""Azure Functions entrypoint for AKS MCP operations.

This implements a compact MCP-compatible JSON-RPC surface for tools/list and tools/call,
exposed at /api/mcp.
"""

from __future__ import annotations

import json
from typing import Any

import azure.functions as func

from tools.registry import ALL_TOOLS, build_input_schema, tool_description

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Derived from the shared registry so this surface always exposes the same tools as main.py.
TOOLS = {tool.__name__: tool for tool in ALL_TOOLS}
TOOL_SCHEMAS = {name: build_input_schema(tool) for name, tool in TOOLS.items()}


def _response(payload: dict[str, Any], status_code: int = 200) -> func.HttpResponse:
    return func.HttpResponse(
        body=json.dumps(payload),
        status_code=status_code,
        mimetype="application/json",
    )


@app.route(route="mcp", methods=["POST"])
def mcp(req: func.HttpRequest) -> func.HttpResponse:
    try:
        request_payload = req.get_json()
    except ValueError:
        return _response({"error": {"code": -32700, "message": "Invalid JSON payload."}}, status_code=400)

    req_id = request_payload.get("id")
    method = request_payload.get("method")
    params = request_payload.get("params", {})

    if method == "tools/list":
        tools = [
            {
                "name": name,
                "description": tool_description(TOOLS[name]),
                "inputSchema": TOOL_SCHEMAS[name],
            }
            for name in sorted(TOOLS.keys())
        ]
        return _response({"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}})

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name not in TOOLS:
            return _response(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                },
                status_code=404,
            )

        try:
            result = TOOLS[tool_name](**arguments)
        except TypeError as exc:
            return _response(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Invalid arguments: {exc}"},
                },
                status_code=400,
            )
        except Exception as exc:  # noqa: BLE001
            return _response(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": str(exc)},
                },
                status_code=500,
            )

        return _response(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result),
                        }
                    ]
                },
            }
        )

    return _response(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Unsupported method: {method}"},
        },
        status_code=400,
    )


@app.route(route="health", methods=["GET"])
def health(_: func.HttpRequest) -> func.HttpResponse:
    return _response({"status": "ok", "service": "aks-operations-mcp"})
