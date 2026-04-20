#!/usr/bin/env python3
"""提取 EVE JSON 中 GetNamedVariableListAttributes 事务的深度解析字段。

用法: python3 extract_gnvla_details.py <eve.json>
"""
import json, sys

if len(sys.argv) < 2:
    print("Usage: extract_gnvla_details.py <eve.json>", file=sys.stderr)
    sys.exit(1)

with open(sys.argv[1]) as f:
    for line in f:
        ev = json.loads(line)
        if ev.get('event_type') != 'iec61850_mms':
            continue
        mms = ev.get('iec61850_mms', {})
        req = mms.get('request', {})
        if req.get('service') == 'get_named_variable_list_attributes':
            print("=== GetNamedVariableListAttributes Transaction ===")
            print(f"  Request:")
            print(f"    invoke_id: {req.get('invoke_id')}")
            obj = req.get('object_name', {})
            print(f"    object_name.scope:  {obj.get('scope', '(absent)')}")
            print(f"    object_name.domain: {obj.get('domain', '(absent)')}")
            print(f"    object_name.item:   {obj.get('item', '(absent)')}")
            resp = mms.get('response', {})
            print(f"  Response:")
            print(f"    invoke_id:      {resp.get('invoke_id')}")
            print(f"    mms_deletable:  {resp.get('mms_deletable')}")
            print(f"    variable_count: {resp.get('variable_count')}")
            variables = resp.get('variables', [])
            print(f"    variables ({len(variables)} items):")
            for i, v in enumerate(variables[:5]):
                print(f"      [{i}] scope={v.get('scope')}, domain={v.get('domain','')}, item={v.get('item','')}")
            if len(variables) > 5:
                print(f"      ... ({len(variables) - 5} more)")
