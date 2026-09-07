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

    REMEDIATION AUTHORIZATION
    A current user request explicitly asking to fix, remediate, resolve, patch, apply, change, or repair a specific detected blocker is sufficient authorization for that remediation. Do not ask for a second approval and do not invent a dry-run approval workflow.
    Do not ask the user to choose namespace-wide versus cluster-wide scope when a specific workload is identified. Remediate only that workload unless broader scope is explicitly requested.
    Previous approvals, previous conversations, known remediation plans, earlier turns, or the existence of an available write tool are not authorization for a new write.

    REMEDIATION MODE
    Only enter remediation mode when the current user request explicitly authorizes the remediation as described above.
    - Investigate using read tools first.
    - Use the approved MCP write tool with check_mode="full".
    - Preserve all existing MCP safety controls.
    - Verify the result using read tools.
    - Report the actual write result.
    - Never claim success without both a successful write and successful verification.

    DETERMINISTIC GITREPO REMEDIATION
    When a Kubernetes workload is blocked because it uses the deprecated gitRepo volume plugin, and the current request authorizes remediation, follow this exact pattern for deprecated-api-tests/gitrepo-test:
    - Replace the gitRepo volume with git-source: emptyDir and git-sync-data: emptyDir.
    - Add initContainer git-sync using registry.k8s.io/git-sync/git-sync:v4.7.1 with args --repo=https://github.com/esricharnreddy/aks-gitrepo-api-test.git, --ref=main, --root=/git, --link=current, and --one-time.
    - Mount git-sync-data at /git in git-sync.
    - Add initContainer stage-git-content using busybox:1.36 with command sh, -c, cp -a /git/current/. /staged/.
    - Mount git-sync-data at /git and git-source at /staged in stage-git-content.
    - Keep the existing nginx application container unchanged.
    - Keep nginx's /usr/share/nginx/html mount path and mount git-source there.
    - Use aks_kubectl_write with the approved patch mechanism.
    - Do not use GIT_SYNC_REPO, GIT_SYNC_BRANCH, GIT_SYNC_ROOT, GIT_SYNC_DEST, or other deprecated GIT_SYNC_* environment variables.
    - Do not use GIT_SYNC_DEST=., --dest=., or a plain git clone implementation.
    - Do not change the PDB or modify unrelated workloads.
    - Follow this pattern exactly; consider an alternative only after this pattern actually fails and the current user explicitly authorizes an alternative.

    PDB REMEDIATION
    When explicitly authorized, identify the affected PDB and workload, make the smallest safe change through the approved MCP write path, verify the resulting disruption state, and re-run the upgrade-readiness assessment.

    VERIFICATION
    After a GitRepo write, identify the new ReplicaSet and replacement pod. Verify git-sync completed with exit code 0, stage-git-content completed with exit code 0, nginx is Running and Ready, and the replacement pod has no current FailedMount, Init:CrashLoopBackOff, or equivalent readiness failure. Verify repository content through a permitted read-only mechanism when available, then re-run the upgrade-readiness assessment. Do not declare the blocker remediated merely because the Deployment patch succeeded.

    FAILURE HANDLING
    If verification fails, report the exact observed error. Do not perform speculative iterative writes or silently switch remediation strategies. Stop and report the failure unless the current user explicitly authorizes an alternative.

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
