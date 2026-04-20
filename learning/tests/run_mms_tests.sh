#!/bin/bash
set -e

# === 配置（可通过环境变量覆盖） ===
SURICATA_DIR="${SURICATA_DIR:-/home/work/suricata-8.0.4-study}"
PCAP_DIR="${PCAP_DIR:-/home/work/iec61850_protocol_parser/pcaps_file}"
TEST_OUT="${TEST_OUT:-/tmp/mms_test}"
SURICATA_YAML="${SURICATA_YAML:-$SURICATA_DIR/suricata.yaml}"

PASS=0
FAIL=0

check() {
    local desc="$1"
    shift
    if "$@"; then
        echo "  [PASS] $desc"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $desc"
        FAIL=$((FAIL + 1))
    fi
}

mkdir -p "$TEST_OUT"

# 辅助函数：直接检查 EVE JSON 应用层日志
get_malformed() {
    local c
    c=$(grep -c 'malformed_data' "$TEST_OUT/$1/eve.json" 2>/dev/null) || c=0
    echo "$c"
}
has_service() {
    grep -q "\"service\":\"$2\"" "$TEST_OUT/$1/eve.json" 2>/dev/null
}
has_pdu_type() {
    grep -q "\"pdu_type\":\"$2\"" "$TEST_OUT/$1/eve.json" 2>/dev/null
}

# === 步骤 1：运行所有 pcap ===
echo "=== Running Suricata against all pcaps ==="
for pcap in "$PCAP_DIR"/*.pcap; do
    fname=$(basename "$pcap" .pcap)
    outdir="$TEST_OUT/$fname"
    rm -rf "$outdir" && mkdir -p "$outdir"
    suricata -r "$pcap" -S /dev/null \
        -c "$SURICATA_YAML" -l "$outdir" 2>/dev/null
    echo "  done: $fname"
done

# === 步骤 2：验证 ===
echo ""
echo "=== Verification ==="

echo ""
echo "[Test Group 1] iec61850_* Session/Presentation layer - malformed check"
for pcap in iec61850_get_name_list iec61850_get_variable_access_attributes iec61850_read iec61850_write iec61850_release; do
    check "$pcap: malformed=0" test "$(get_malformed $pcap)" -eq 0
done

echo ""
echo "[Test Group 2] iec61850_* service detection"
check "iec61850_get_name_list: service=get_name_list" has_service iec61850_get_name_list get_name_list
check "iec61850_get_variable_access_attributes: service=get_variable_access_attributes" has_service iec61850_get_variable_access_attributes get_variable_access_attributes
check "iec61850_read: service=read" has_service iec61850_read read
check "iec61850_write: service=write" has_service iec61850_write write

echo ""
echo "[Test Group 3] Regression: mms-readRequest"
check "mms-readRequest: malformed=0" test "$(get_malformed mms-readRequest)" -eq 0
check "mms-readRequest: service=read" has_service mms-readRequest read
check "mms-readRequest: pdu_type=confirmed_request" has_pdu_type mms-readRequest confirmed_request

echo ""
echo "[Test Group 4] mms-* series - malformed check"
for pcap in mms-cancelRequest mms-deleteProgramInvocation mms-getAlarmSummary mms-getDomainAttributes mms-initiateDownloadSequence mms-initiateUploadSequence mms-terminateUploadSequence mms-killRequest mms-startRequest mms-stopRequest mms-resumeRequest mms-resetRequest mms-relinquishControl mms-takeControl; do
    check "$pcap: malformed=0" test "$(get_malformed $pcap)" -eq 0
done

echo ""
echo "[Test Group 5] Extended services - multi-byte tags"
check "mms-deleteProgramInvocation: service=delete_program_invocation" has_service mms-deleteProgramInvocation delete_program_invocation
check "mms-getAlarmSummary: service=get_alarm_summary" has_service mms-getAlarmSummary get_alarm_summary
check "mms-getDomainAttributes: service=get_domain_attributes" has_service mms-getDomainAttributes get_domain_attributes
check "mms-killRequest: service=kill" has_service mms-killRequest kill
check "mms-startRequest: service=start" has_service mms-startRequest start
check "mms-stopRequest: service=stop" has_service mms-stopRequest stop
check "mms-resumeRequest: service=resume" has_service mms-resumeRequest resume
check "mms-resetRequest: service=reset" has_service mms-resetRequest reset

echo ""
echo "[Test Group 6] Extended services - standard tags"
check "mms-takeControl: service=take_control" has_service mms-takeControl take_control
check "mms-relinquishControl: service=relinquish_control" has_service mms-relinquishControl relinquish_control
check "mms-initiateDownloadSequence: service=initiate_download_sequence" has_service mms-initiateDownloadSequence initiate_download_sequence
check "mms-initiateUploadSequence: service=initiate_upload_sequence" has_service mms-initiateUploadSequence initiate_upload_sequence
check "mms-terminateUploadSequence: service=terminate_upload_sequence" has_service mms-terminateUploadSequence terminate_upload_sequence

echo ""
echo "[Test Group 7] CancelRequest and ConcludeRequest PDU detection"
check "mms-cancelRequest: pdu_type=cancel_request" has_pdu_type mms-cancelRequest cancel_request
check "mms-cancelRequest: pdu_type=conclude_request" has_pdu_type mms-cancelRequest conclude_request
check "mms-deleteProgramInvocation: pdu_type=conclude_request" has_pdu_type mms-deleteProgramInvocation conclude_request

echo ""
echo "=== Summary ==="
echo "PASSED: $PASS"
echo "FAILED: $FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
else
    echo "SOME TESTS FAILED"
    exit 1
fi
