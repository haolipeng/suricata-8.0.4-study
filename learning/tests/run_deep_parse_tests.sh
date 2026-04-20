#!/bin/bash

SURICATA_DIR="${SURICATA_DIR:-/home/work/suricata-8.0.4-study}"
PCAP_DIR="${PCAP_DIR:-/home/work/iec61850_protocol_parser/pcaps_file}"
SURICATA_YAML="${SURICATA_YAML:-$SURICATA_DIR/suricata.yaml}"
DEEP_OUT="/tmp/mms_deep_test"
GNVLA_PCAP="/tmp/test_large_12/session_254_172.20.4.111_38914.pcap"

PASS=0; FAIL=0

check() {
    local desc="$1"; shift
    if "$@" 2>/dev/null; then
        echo "  [PASS] $desc"; PASS=$((PASS + 1))
    else
        echo "  [FAIL] $desc"; FAIL=$((FAIL + 1))
    fi
}

rm -rf "$DEEP_OUT" && mkdir -p "$DEEP_OUT"

# === 运行 pcap ===
echo "=== Running pcaps ==="
for name_pcap in \
    "gva:$PCAP_DIR/iec61850_get_variable_access_attributes.pcap" \
    "gnl:$PCAP_DIR/iec61850_get_name_list.pcap" \
    "gnvla:$GNVLA_PCAP"; do
    name="${name_pcap%%:*}"; pcap="${name_pcap#*:}"
    outdir="$DEEP_OUT/$name"; rm -rf "$outdir" && mkdir -p "$outdir"
    if [ -f "$pcap" ]; then
        suricata -r "$pcap" -S /dev/null -c "$SURICATA_YAML" -l "$outdir" 2>/dev/null
        echo "  done: $name"
    else
        echo "  SKIP: $name (pcap not found: $pcap)"
    fi
done

# === 验证 ===
echo ""; echo "=== Deep Parsing Verification ==="

echo ""; echo "[GetVariableAccessAttributes]"
D="$DEEP_OUT/gva"
mal=$(grep -c 'malformed_data' "$D/eve.json" 2>/dev/null || true)
check "malformed=0" test "${mal:-0}" -eq 0
check "service=get_variable_access_attributes" grep -q '"service":"get_variable_access_attributes"' "$D/eve.json"
check "variable.scope=vmd_specific" grep -q '"scope":"vmd_specific"' "$D/eve.json"
check "variable.item=mu" grep -q '"item":"mu"' "$D/eve.json"

echo ""; echo "[GetNameList]"
D="$DEEP_OUT/gnl"
mal=$(grep -c 'malformed_data' "$D/eve.json" 2>/dev/null || true)
check "malformed=0" test "${mal:-0}" -eq 0
check "service=get_name_list" grep -q '"service":"get_name_list"' "$D/eve.json"
check "object_class=named_variable" grep -q '"object_class":"named_variable"' "$D/eve.json"

echo ""; echo "[Initiate-Request/Response]"
D="$DEEP_OUT/gnl"
check "initiate_request detected" grep -q '"pdu_type":"initiate_request"' "$D/eve.json"
check "initiate_response detected" grep -q '"pdu_type":"initiate_response"' "$D/eve.json"

echo ""; echo "[GetNamedVariableListAttributes]"
D="$DEEP_OUT/gnvla"
if [ -f "$D/eve.json" ]; then
    mal=$(grep -c 'malformed_data' "$D/eve.json" 2>/dev/null || true)
    check "malformed=0" test "${mal:-0}" -eq 0
    check "service=get_named_variable_list_attributes" grep -q '"service":"get_named_variable_list_attributes"' "$D/eve.json"
    check "request domain=PQMR_1000_941" grep -q '"domain":"PQMR_1000_941"' "$D/eve.json"
    check "request item=LLN0\$dsMmtr1" grep -q '"item":"LLN0\$dsMmtr1"' "$D/eve.json"
    check "response mms_deletable=false" grep -q '"mms_deletable":false' "$D/eve.json"
    check "response variable_count=20" grep -q '"variable_count":20' "$D/eve.json"
    check "response variable MMTR1\$MX\$SupWh" grep -q '"item":"MMTR1\$MX\$SupWh"' "$D/eve.json"
else
    echo "  [SKIP] pcap not available"
fi

# === Rust 单元测试 ===
echo ""; echo "[Rust Unit Tests]"
cd "$SURICATA_DIR/rust"
for filter in "get_var_access_attr" "get_name_list" "initiate" "get_named_var_list_attr"; do
    output=$(cargo test --lib iec61850mms -- "$filter" 2>&1)
    result_line=$(echo "$output" | grep "^test result:")
    passed=$(echo "$result_line" | grep -oP '\d+ passed' | grep -oP '\d+' || echo 0)
    failed=$(echo "$result_line" | grep -oP '\d+ failed' | grep -oP '\d+' || echo 0)
    check "cargo test -- $filter: ${passed:-0} passed, ${failed:-0} failed" test "${failed:-0}" -eq 0
done

echo ""; echo "=== Summary ==="
echo "PASSED: $PASS"; echo "FAILED: $FAIL"
[ "$FAIL" -eq 0 ] && echo "ALL DEEP PARSING TESTS PASSED" && exit 0
echo "SOME TESTS FAILED" && exit 1
