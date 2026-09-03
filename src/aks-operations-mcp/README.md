# AKS Operations MCP (Phase 2)

This project exposes AKS operational checks as MCP tools over MCP HTTP transports.

In Phase 4, it also includes an Azure Functions entrypoint (`function_app.py`) at `/api/mcp` for remote hosting/deployment.

## Implemented tools

- `aks_get_cluster_details`
- `aks_get_node_pools`
- `aks_get_available_upgrades`
- `aks_check_node_health`
- `aks_check_pod_health`
- `aks_check_pdb`
- `aks_check_storage`
- `aks_check_deprecated_apis`
- `aks_validate_upgrade_readiness`
- `aks_upgrade_node_pool`
- `aks_remediate_pdb`
- `aks_remediate_pods`
- `aks_remediate_node`
- `aks_remediate_storage`
- `aks_remediate_deprecated_apis`
- `aks_generate_deprecated_api_manifests`

## Upgrade guardrails

`aks_upgrade_node_pool` is protected by default:

1. It runs health and safety prechecks (nodes, pods, PDB, optional maintenance window).
	- `check_mode=quick` (default): lightweight gate suitable for frequent calls.
	- `check_mode=full`: runs deep Kubernetes checks (slower, stricter).
2. It defaults to `dry_run=true`.
3. Real writes require `AKS_UPGRADE_ENABLE_WRITE=true`.
4. If `AKS_UPGRADE_APPROVAL_TOKEN` is set, callers must provide matching `approval_token`.
5. Real writes additionally require `check_mode=full`.

Optional env vars:

- `AKS_UPGRADE_ENABLE_WRITE` (default: `false`)
- `AKS_UPGRADE_APPROVAL_TOKEN` (optional second-factor gate)

## PDB remediation guardrails

`aks_remediate_pdb` defaults to `dry_run=true` so an assessment never mutates the cluster.
When the agent is explicitly instructed to remediate, it can call the tool with `dry_run=false`.
Write execution requires:

1. `check_mode=full` (the PDB remediation tool now defaults to `full`).
2. `AKS_REMEDIATION_ENABLE_WRITE=true`.
3. `AKS_REMEDIATION_APPROVAL_TOKEN` must be configured on the MCP server.

The approval token is resolved server-side when the caller omits `approval_token`, so the LLM/agent
never needs to receive the secret. A caller-supplied token is still validated against the same
server-side value. Protected Kubernetes namespaces remain blocked.

Required remediation environment variables for an enabled POC deployment:

- `AKS_REMEDIATION_ENABLE_WRITE=true`
- `AKS_REMEDIATION_APPROVAL_TOKEN=<store as a deployment secret; do not put it in agent instructions>`

## Local run

```bash
pip install -r requirements.txt
python main.py
```

## Function-hosted MCP validation

Once deployed to Azure Functions, validate the endpoint:

```bash
curl -X POST "https://<function-app-name>.azurewebsites.net/api/mcp" \
	-H "Content-Type: application/json" \
	-d '{"jsonrpc":"2.0","id":"1","method":"tools/list","params":{}}'
```

Tool call example:

```bash
curl -X POST "https://<function-app-name>.azurewebsites.net/api/mcp" \
	-H "Content-Type: application/json" \
	-d '{"jsonrpc":"2.0","id":"2","method":"tools/call","params":{"name":"aks_get_cluster_details","arguments":{"subscription_id":"<sub>","resource_group":"<rg>","cluster_name":"<name>"}}}'
```

Optional environment variables:

- `AKS_MCP_HOST` (default: `0.0.0.0`)
- `AKS_MCP_PORT` (default: `8000`)

## Permissions required

The runtime identity needs permission to:

- Read AKS managed cluster and agent pool metadata.
- Execute AKS run command API for Kubernetes health checks and approved remediation commands.
- Have sufficient Kubernetes authorization for the requested remediation (for example, scaling a Deployment/StatefulSet or patching a PDB).

These roles are wired in later phases through infrastructure.
