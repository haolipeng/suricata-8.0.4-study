#!/usr/bin/env python3
"""提取 EVE JSON 中 GetNameList 事务的深度解析字段。

用法: python3 extract_gnl_details.py <eve.json>
"""
import json, sys

if len(sys.argv) < 2:
    print("Usage: extract_gnl_details.py <eve.json>", file=sys.stderr)
    sys.exit(1)

with open(sys.argv[1]) as f:
    for line in f:
        ev = json.loads(line)
        if ev.get('event_type') != 'iec61850_mms':
            continue
        mms = ev.get('iec61850_mms', {})
        req = mms.get('request', {})
        if req.get('service') == 'get_name_list':
            print("=== GetNameList Transaction ===")
            print(f"  Request:")
            print(f"    pdu_type:     {req.get('pdu_type')}")
            print(f"    invoke_id:    {req.get('invoke_id')}")
            print(f"    service:      {req.get('service')}")
            print(f"    object_class: {req.get('object_class', '(absent)')}")
            print(f"    object_scope: {req.get('object_scope', '(absent)')}")
            print(f"    domain:       {req.get('domain', '(absent)')}")
            print(f"    continue_after: {req.get('continue_after', '(absent)')}")
            resp = mms.get('response', {})
            print(f"  Response:")
            print(f"    pdu_type:     {resp.get('pdu_type')}")
            print(f"    invoke_id:    {resp.get('invoke_id')}")
            identifiers = resp.get('identifiers', [])
            print(f"    identifiers:  {identifiers if identifiers else '(empty or absent)'}")
            more = resp.get('more_follows')
            print(f"    more_follows: {more if more is not None else '(absent)'}")
