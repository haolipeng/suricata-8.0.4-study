#!/usr/bin/env python3
"""提取 EVE JSON 中 Initiate-Request/Response 的深度解析字段。

用法: python3 extract_initiate_details.py <eve.json>
"""
import json, sys

if len(sys.argv) < 2:
    print("Usage: extract_initiate_details.py <eve.json>", file=sys.stderr)
    sys.exit(1)

with open(sys.argv[1]) as f:
    for line in f:
        ev = json.loads(line)
        if ev.get('event_type') != 'iec61850_mms':
            continue
        mms = ev.get('iec61850_mms', {})
        for side in ('request', 'response'):
            pdu = mms.get(side, {})
            pt = pdu.get('pdu_type', '')
            if 'initiate' in pt:
                print(f"=== {pt} ===")
                for key in ('local_detail', 'max_serv_outstanding',
                            'data_structure_nesting_level', 'version_number',
                            'supported_services'):
                    print(f"  {key}: {pdu.get(key, '(absent)')}")
