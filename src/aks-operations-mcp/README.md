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
4. Real writes additionally require `check_mode=full`.
5. The MCP runtime identity must have sufficient Azure authorization for the requested operation.

Optional env var:

- `AKS_UPGRADE_ENABLE_WRITE` (default: `false`)

## Remediation guardrails

Remediation tools that modify cluster resources default to `dry_run=true` and `check_mode="full"`.

Real remediation writes require:

1. `dry_run=false` explicitly from the caller/agent.
2. `check_mode=full`.
3. `AKS_REMEDIATION_ENABLE_WRITE=true` on the MCP server.
4. The MCP runtime identity must have sufficient Azure/AKS/Kubernetes authorization for the requested operation.
5. Protected cluster-critical namespaces remain blocked.
6. Destructive remediations require their explicit destructive-operation confirmation flag.

There is no application-level approval token for upgrade or remediation operations. The LLM/agent does not receive or provide a secret token. The security boundary is the explicit write-enable setting, remediation-specific confirmation for destructive actions, and the runtime identity's Azure/Kubernetes permissions.

## Local run

```bash
pip install -r requirements.txt
python main.py
```

## Function-hosted MCP validation

Once deployed to Azure Functions, validate the endpoint:

```bash
curl -X POST "https://<function-app-name>.azurewebsites.net/api/mcp" \\
    -H "Content-Type: application/json" \\
    -d '{"jsonrpc":"2.0","id":"1","method":"tools/list","params":{}}'
```

Tool call example:

```bash
curl -X POST "https://<function-app-name>.azurewebsites.net/api/mcp" \\
    -H "Content-Type: application/json" \\
    -d '{"jsonrpc":"2.0","id":"2","method":"tools/call","params":{"name":"aks_get_cluster_details","arguments":{"subscription_id":"<sub>","resource_group":"<rg>","cluster_name":"<name>"}}}'
```

Optional environment variables:

- `AKS_MCP_HOST` (default: `0.0.0.0`)
- `AKS_MCP_PORT` (default: `8000`)

## Permissions required

The runtime identity needs permission to:

- Read AKS managed cluster and agent pool metadata.
- Execute AKS run command API for Kubernetes health checks and remediation commands.
- Have sufficient Kubernetes authorization for the requested remediation (for example, scaling a Deployment/StatefulSet or patching a PDB).

These roles are wired in later phases through infrastructure.
