"""AKS operations MCP server entrypoint.

Exposes discovery, validation, and upgrade tools over the Model Context
Protocol (MCP) using the Streamable HTTP transport, so Foundry Toolbox (and
any other spec-compliant MCP client) can discover and invoke them at /mcp.
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from tools.registry import ALL_TOOLS

mcp = FastMCP(
    "aks-operations-mcp",
    host=os.getenv("AKS_MCP_HOST", "0.0.0.0"),
    port=int(os.getenv("AKS_MCP_PORT", "8000")),
    stateless_http=True,
)

for _tool in ALL_TOOLS:
    mcp.add_tool(_tool)


def list_registered_tools() -> list[str]:
    """Return the list of registered tool names."""
    return sorted(mcp._tool_manager._tools.keys())  # noqa: SLF001


if __name__ == "__main__":
    print(f"Starting AKS MCP server (streamable-http) on {mcp.settings.host}:{mcp.settings.port}")
    mcp.run(transport="streamable-http")
