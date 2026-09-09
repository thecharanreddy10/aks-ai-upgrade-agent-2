#!/usr/bin/env python3
"""Verify aks_execute_confirmed_upgrade schema includes confirmed_scope."""

from tools.registry import ALL_TOOLS
import json

for tool in ALL_TOOLS:
    if tool['name'] == 'aks_execute_confirmed_upgrade':
        params = tool['inputSchema']['properties']
        print('Tool: aks_execute_confirmed_upgrade')
        print('\nParameters:')
        for param in sorted(params.keys()):
            schema = params[param]
            print(f'  - {param}: {schema.get("type", "unknown")}')

        if 'confirmed_scope' in params:
            print('\n✅ confirmed_scope PRESENT in schema')
            scope_param = params['confirmed_scope']
            print(f'   Type: {scope_param.get("type")}')
            print(f'   Default: {scope_param.get("default")}')
            print(f'   Description: {scope_param.get("description")}')
            if 'enum' in scope_param:
                print(f'   Allowed values: {scope_param["enum"]}')
        else:
            print('\n❌ confirmed_scope NOT FOUND in schema')
        break
