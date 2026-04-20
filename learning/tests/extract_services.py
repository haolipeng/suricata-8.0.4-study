#!/usr/bin/env python3
"""提取 EVE JSON 中每个 pcap 检出的 MMS 服务类型集合。

用法: python3 extract_services.py <eve.json>
"""
import json, sys

if len(sys.argv) < 2:
    print("Usage: extract_services.py <eve.json>", file=sys.stderr)
    sys.exit(1)

svcs = set()
with open(sys.argv[1]) as f:
    for line in f:
        ev = json.loads(line)
        if ev.get('event_type') == 'iec61850_mms':
            mms = ev.get('iec61850_mms', {})
            for side in ('request', 'response'):
                s = mms.get(side, {}).get('service', '')
                if s and s != 'unknown':
                    svcs.add(s)
print(', '.join(sorted(svcs)) if svcs else '-')
