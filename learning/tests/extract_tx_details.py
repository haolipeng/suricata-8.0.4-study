#!/usr/bin/env python3
"""提取 EVE JSON 中 MMS 事务的 pdu_type/service 详情。

用法: python3 extract_tx_details.py <eve.json>
"""
import json, sys

if len(sys.argv) < 2:
    print("Usage: extract_tx_details.py <eve.json>", file=sys.stderr)
    sys.exit(1)

with open(sys.argv[1]) as f:
    for line in f:
        ev = json.loads(line)
        if ev.get('event_type') == 'iec61850_mms':
            mms = ev.get('iec61850_mms', {})
            req = mms.get('request', {})
            resp = mms.get('response', {})
            parts = []
            if req:
                pdu = req.get('pdu_type', '')
                svc = req.get('service', '')
                s = 'req: pdu_type=' + pdu
                if svc:
                    s += ', service=' + svc
                parts.append(s)
            if resp:
                pdu = resp.get('pdu_type', '')
                svc = resp.get('service', '')
                s = 'resp: pdu_type=' + pdu
                if svc:
                    s += ', service=' + svc
                parts.append(s)
            if parts:
                print('  TX: ' + ' | '.join(parts))
            elif not req and not resp:
                print('  TX: (empty - COTP connection)')
        elif ev.get('event_type') == 'anomaly' and 'malformed' in line:
            print('  ANOMALY: malformed_data tx_id=%s' % ev.get('tx_id'))
