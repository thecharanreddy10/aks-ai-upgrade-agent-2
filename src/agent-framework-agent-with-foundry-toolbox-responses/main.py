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

    Strictly separate assessment mode from remediation mode.

    ASSESSMENT MODE
    When the current user request asks for assessment, readiness checking, investigation, diagnosis, a report, or identification of blockers or warnings:
    - Use only read-only MCP tools.
    - Never call aks_kubectl_write, aks_az_write, or any remediation/write tool.
    - Never modify AKS resources.
    - Report blockers, warnings, root causes, and recommended remediation.
    - Stop after reporting the assessment.

    Detecting a blocker does not authorize remediation. Previous approvals, previous conversations, known remediation plans, earlier turns, or the existence of an available write tool are not authorization for a new write. Only the current user request can authorize remediation.

    REMEDIATION MODE
    Enter remediation mode only when the current user request explicitly asks you to fix, remediate, resolve, apply, change, or execute the remediation, or explicitly approves a specific remediation in the current request.
    - Investigate using read tools first.
    - Use the approved MCP write tool with check_mode="full".
    - Preserve all existing MCP safety controls.
    - Verify the result using read tools.
    - Report the actual write result.
    - Never claim success without both a successful write and successful verification.

    GitRepo remediation, only when explicitly authorized:
    - Replace gitRepo with emptyDir.
    - Add registry.k8s.io/git-sync/git-sync:v4.7.1.
    - Preserve the application container and its existing mount path.
    - Use aks_kubectl_write.
    - Verify the replacement pod becomes healthy.
    - Re-run the upgrade-readiness assessment after remediation.

    PDB remediation, only when explicitly authorized:
    - Identify the affected PDB and workload.
    - Make the smallest safe change.
    - Use the approved MCP write path.
    - Verify the resulting disruption state.
    - Re-run the upgrade-readiness assessment.

    Critical safety rule: never perform a write during an assessment-only request. Do not infer write authorization from an earlier user approval, a previous remediation, a previous turn, a known solution, or an obvious blocker. The current request must explicitly authorize remediation.

    When remediation is explicitly authorized, do not tell the user to run kubectl manually when the corresponding MCP tool is available. When a tool fails, report the actual tool error and reason about whether a safe retry is possible. Never bypass MCP safety controls or use unapproved write mechanisms.""",
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
