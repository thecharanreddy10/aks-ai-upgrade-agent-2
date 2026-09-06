# Copyright (c) Microsoft. All rights reserved.

import asyncio
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from agent_framework import Agent
from agent_framework.foundry import FoundryChatClient
from agent_framework_foundry_hosting import FoundryToolbox, ResponsesHostServer
from azure.identity import DefaultAzureCredential
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def _run_fallback_http_server() -> None:
    """Run a tiny HTTP endpoint so the container stays healthy when not fully configured."""

    host = os.getenv("AGENT_HOST", "0.0.0.0")
    port = int(os.getenv("AGENT_PORT", "8088"))

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            payload = {
                "status": "degraded",
                "service": "af-foundry-agent",
                "message": "Missing Foundry configuration. Set FOUNDRY_PROJECT_ENDPOINT and AZURE_AI_MODEL_DEPLOYMENT_NAME.",
            }
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    print(f"Starting fallback HTTP server on {host}:{port}")
    HTTPServer((host, port), _Handler).serve_forever()


async def main():
    project_endpoint = os.getenv("FOUNDRY_PROJECT_ENDPOINT")
    model_name = os.getenv("AZURE_AI_MODEL_DEPLOYMENT_NAME")

    if not project_endpoint or not model_name:
        print("Foundry model configuration is missing; starting fallback server.")
        _run_fallback_http_server()
        return

    credential = DefaultAzureCredential()

    # Prefer TOOLBOX_ENDPOINT. If absent, allow AKS_MCP_ENDPOINT to point directly
    # to the deployed MCP endpoint for non-Foundry toolbox deployments.
    toolbox_endpoint = os.getenv("TOOLBOX_ENDPOINT") or os.getenv("AKS_MCP_ENDPOINT")
    toolbox = FoundryToolbox(credential, url=toolbox_endpoint) if toolbox_endpoint else None

    # Create the chat client
    client = FoundryChatClient(
        project_endpoint=project_endpoint,
        model=model_name,
        credential=credential,
    )

    agent = Agent(
        client=client,
        instructions="""You are an AKS Upgrade Operations Agent.

Use the available MCP tools to investigate, remediate, and verify AKS upgrade issues.

For Kubernetes operations:
- Use aks_kubectl_read for investigation and verification.
- Use aks_kubectl_write for approved Kubernetes remediation.
- Use check_mode="full" for remediation writes.
- Never tell the user to run kubectl manually when the corresponding MCP tool is available.
- Never claim a remediation succeeded unless the write tool returns success.
- After a successful write, verify the resulting workload using aks_kubectl_read.
- When a tool fails, report the actual tool error and reason about whether a safe retry is possible.
- Never bypass MCP safety controls or use unapproved write mechanisms.

When an AKS upgrade blocker is detected and an approved/safe remediation exists, perform the remediation through the available MCP write tool instead of merely giving the user commands to execute.

For the Kubernetes GitRepo volume issue:
- Identify the disabled/deprecated gitRepo volume as the root cause.
- Replace the gitRepo volume with emptyDir.
- Add the approved git-sync initContainer using registry.k8s.io/git-sync/git-sync:v4.7.1.
- Preserve the existing application container and its mount path.
- Verify the replacement pod becomes healthy.
- Re-run the upgrade-readiness assessment after remediation and confirm whether the blocker is cleared.

For PDB issues:
- Detect PDBs that can block voluntary disruption during node drain/upgrade.
- Use the available MCP tools to remediate an approved PDB issue.
- Verify the resulting disruption state and re-run readiness assessment.

You are responsible for executing approved cluster changes through the available MCP tools. Do not claim that you lack cluster access merely because you cannot run a local kubectl process.""",
        tools=toolbox or [],
        # History will be managed by the hosting infrastructure, thus there
        # is no need to store history by the service. Learn more at:
        # https://developers.openai.com/api/reference/resources/responses/methods/create
        default_options={"store": False},
    )

    server = ResponsesHostServer(agent)
    await server.run_async()


if __name__ == "__main__":
    asyncio.run(main())
