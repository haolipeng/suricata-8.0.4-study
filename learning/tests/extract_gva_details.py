#!/usr/bin/env python3
"""提取 EVE JSON 中 GetVariableAccessAttributes 事务的深度解析字段。

用法: python3 extract_gva_details.py <eve.json>
"""
import json, sys

if len(sys.argv) < 2:
    print("Usage: extract_gva_details.py <eve.json>", file=sys.stderr)
    sys.exit(1)

with open(sys.argv[1]) as f:
    for line in f:
        ev = json.loads(line)
        if ev.get('event_type') != 'iec61850_mms':
            continue
        mms = ev.get('iec61850_mms', {})
        req = mms.get('request', {})
        if req.get('service') == 'get_variable_access_attributes':
            print("=== GetVariableAccessAttributes Transaction ===")
            print(f"  Request:")
            print(f"    invoke_id: {req.get('invoke_id')}")
            print(f"    service:   {req.get('service')}")
            var = req.get('variable', {})
            print(f"    variable.scope:  {var.get('scope', '(absent)')}")
            print(f"    variable.domain: {var.get('domain', '(absent)')}")
            print(f"    variable.item:   {var.get('item', '(absent)')}")
            resp = mms.get('response', {})
            print(f"  Response:")
            print(f"    invoke_id: {resp.get('invoke_id')}")
            print(f"    service:   {resp.get('service')}")
