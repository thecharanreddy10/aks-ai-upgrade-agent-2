# AKS Operations MCP (Phase 2)

This project exposes AKS operational checks as MCP tools over Streamable HTTP.

In Phase 4, it also includes an Azure Functions entrypoint (`function_app.py`) at `/api/mcp` for remote hosting/deployment.

## Implemented tools

- `aks_get_cluster_details`
- `aks_get_node_pools`
- `aks_get_available_upgrades`
- `aks_check_node_health`
- `aks_check_pod_health`
- `aks_check_pdb`
- `aks_validate_upgrade_readiness`
- `aks_upgrade_node_pool`

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
- Execute AKS run command API for Kubernetes health checks.

These roles are wired in later phases through infrastructure.
