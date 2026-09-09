#!/usr/bin/env python3
"""Verify aks_execute_confirmed_upgrade has confirmed_scope parameter."""

import sys
sys.path.insert(0, '.')

from tools.registry import build_input_schema
from tools.upgrade import aks_execute_confirmed_upgrade

schema = build_input_schema(aks_execute_confirmed_upgrade)
params = schema.get('properties', {})

print('=' * 60)
print('Tool Schema Verification: aks_execute_confirmed_upgrade')
print('=' * 60)
print('\nParameters registered:')
for param in sorted(params.keys()):
    param_schema = params[param]
    param_type = param_schema.get('type', 'unknown')
    print(f'  - {param}: {param_type}')

print('\n' + '-' * 60)
if 'confirmed_scope' in params:
    print('✓ SUCCESS: confirmed_scope parameter is present')
    p = params['confirmed_scope']
    print(f'\nDetails:')
    print(f'  Type: {p.get("type")}')
    print(f'  Default: {p.get("default", "none")}')
    print(f'  Description: {p.get("description", "none")}')
else:
    print('✗ FAIL: confirmed_scope parameter NOT FOUND')
print('-' * 60)
