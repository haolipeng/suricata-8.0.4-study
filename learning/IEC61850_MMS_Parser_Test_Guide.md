# IEC 61850 MMS 协议解析器测试指南

本文档提供可直接复制执行的测试步骤。测试方案直接检查 EVE JSON 中的 `event_type: "iec61850_mms"` 应用层日志，无需配置 alert 规则。

## 1. 测试环境准备

### 1.1 设置环境变量

> **注意**：以下环境变量在后续所有步骤中都会引用，每次打开新终端时需重新执行。

```bash
export SURICATA_DIR="/home/work/suricata-8.0.4-study"
export PCAP_DIR="/home/work/iec61850_protocol_parser/pcaps_file"
export TEST_OUT="/tmp/mms_test"
export SURICATA_YAML="$SURICATA_DIR/suricata.yaml"
```

### 1.2 确认 pcap 文件完整

```bash
ls "$PCAP_DIR"/*.pcap | wc -l
```

预期输出：`21`

完整 pcap 列表：

| 类别 | 文件名 | 说明 |
|------|--------|------|
| IEC 61850 完整栈 | `iec61850_get_name_list.pcap` | 带 Session/Presentation 层的 GetNameList |
| IEC 61850 完整栈 | `iec61850_get_variable_access_attributes.pcap` | 带 Session/Presentation 层的 GetVariableAccessAttributes |
| IEC 61850 完整栈 | `iec61850_read.pcap` | 带 Session/Presentation 层的 Read |
| IEC 61850 完整栈 | `iec61850_write.pcap` | 带 Session/Presentation 层的 Write |
| IEC 61850 完整栈 | `iec61850_release.pcap` | 带 Session/Presentation 层的 Release（Conclude） |
| MMS 直连 | `mms-readRequest.pcap` | 直接 MMS 的 Read（回归基准） |
| MMS 直连 | `mms-cancelRequest.pcap` | CancelRequest |
| MMS 直连 | `mms-confirmedRequestPDU.pcap` | ConfirmedRequest 通用 |
| MMS 直连（扩展服务） | `mms-deleteProgramInvocation.pcap` | DeleteProgramInvocation (tag=39) |
| MMS 直连（扩展服务） | `mms-getAlarmSummary.pcap` | GetAlarmSummary (tag=63) |
| MMS 直连（扩展服务） | `mms-getDomainAttributes.pcap` | GetDomainAttributes (tag=37) |
| MMS 直连（扩展服务） | `mms-initiateDownloadSequence.pcap` | InitiateDownloadSequence (tag=26) |
| MMS 直连（扩展服务） | `mms-initiateUploadSequence.pcap` | InitiateUploadSequence (tag=29) |
| MMS 直连（扩展服务） | `mms-terminateUploadSequence.pcap` | TerminateUploadSequence (tag=31) |
| MMS 直连（扩展服务） | `mms-killRequest.pcap` | Kill (tag=44) |
| MMS 直连（扩展服务） | `mms-startRequest.pcap` | Start (tag=40) |
| MMS 直连（扩展服务） | `mms-stopRequest.pcap` | Stop (tag=41) |
| MMS 直连（扩展服务） | `mms-resumeRequest.pcap` | Resume (tag=42) |
| MMS 直连（扩展服务） | `mms-resetRequest.pcap` | Reset (tag=43) |
| MMS 直连（扩展服务） | `mms-relinquishControl.pcap` | RelinquishControl (tag=20) |
| MMS 直连（扩展服务） | `mms-takeControl.pcap` | TakeControl (tag=19) |

### 1.3 编译与安装

```bash
cd "$SURICATA_DIR" && make -j$(nproc) && make install
```

预期：编译无错误，`make install` 成功完成。

### 1.4 运行 Rust 单元测试

```bash
cd "$SURICATA_DIR/rust" && cargo test --lib iec61850mms
```

预期输出（关注最后一行）：

```
test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 552 filtered out
```

如果出现 failed > 0，停止后续测试，先排查单元测试失败原因。

## 2. 执行测试

### 2.1 批量运行所有 pcap

```bash
mkdir -p "$TEST_OUT"
for pcap in "$PCAP_DIR"/*.pcap; do
    fname=$(basename "$pcap" .pcap)
    outdir="$TEST_OUT/$fname"
    rm -rf "$outdir" && mkdir -p "$outdir"
    suricata -r "$pcap" -S /dev/null \
        -c "$SURICATA_YAML" -l "$outdir" 2>/dev/null
    echo "done: $fname"
done
echo "=== ALL DONE ==="
```

预期：逐行输出 `done: <pcap名>`，最后输出 `=== ALL DONE ===`，共 21 个。

### 2.2 提取汇总结果

```bash
echo "pcap_name | mms_events | malformed | services"
echo "----------|------------|-----------|----------"
for pcap in "$PCAP_DIR"/*.pcap; do
    fname=$(basename "$pcap" .pcap)
    outdir="$TEST_OUT/$fname"
    mms_events=$(grep -c '"event_type":"iec61850_mms"' "$outdir/eve.json" 2>/dev/null || echo 0)
    malformed=$(grep -c 'malformed_data' "$outdir/eve.json" 2>/dev/null || echo 0)
    services=$(python3 << PYEOF
import json
svcs = set()
with open('$outdir/eve.json') as f:
    for line in f:
        ev = json.loads(line)
        if ev.get('event_type') == 'iec61850_mms':
            mms = ev.get('iec61850_mms', {})
            for side in ('request', 'response'):
                s = mms.get(side, {}).get('service', '')
                if s and s != 'unknown':
                    svcs.add(s)
print(', '.join(sorted(svcs)) if svcs else '-')
PYEOF
)
    echo "$fname | $mms_events | $malformed | $services"
done
```

将输出与第 3 节的基准表逐行对比，重点关注 `malformed` 和 `services` 两列。

### 2.3 提取 MMS 事务详情

```bash
for pcap in "$PCAP_DIR"/*.pcap; do
    fname=$(basename "$pcap" .pcap)
    outdir="$TEST_OUT/$fname"
    echo "=== $fname ==="
    python3 << PYEOF
import json
with open('$outdir/eve.json') as f:
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
PYEOF
    echo ""
done
```

将每个 pcap 的输出与 3.2 节的事务详情基准逐一对比。

## 3. 预期结果基准

### 3.1 汇总指标基准

| pcap | malformed | 预期检出服务 | 说明 |
|------|-----------|-------------|------|
| iec61850_get_name_list | 0 | get_name_list | Session/Presentation 正确剥离 |
| iec61850_get_variable_access_attributes | 0 | get_variable_access_attributes | Session/Presentation 正确剥离 |
| iec61850_read | 0 | read | Session/Presentation 正确剥离 |
| iec61850_release | 0 | read | Session/Presentation 正确剥离 |
| iec61850_write | 0 | write | Session/Presentation 正确剥离 |
| mms-readRequest | 0 | read | 回归基准 |
| mms-cancelRequest | 0 | - | CancelRequest PDU（非 service） |
| mms-confirmedRequestPDU | 1 | - | pcap 服务端帧格式异常（见说明） |
| mms-deleteProgramInvocation | 0 | delete_program_invocation | 多字节标签 tag=39 |
| mms-getAlarmSummary | 0 | get_alarm_summary | 多字节标签 tag=63 |
| mms-getDomainAttributes | 0 | get_domain_attributes | 多字节标签 tag=37 |
| mms-initiateDownloadSequence | 0 | initiate_download_sequence, take_control | tag=26 |
| mms-initiateUploadSequence | 0 | initiate_upload_sequence | tag=29 |
| mms-terminateUploadSequence | 0 | initiate_upload_sequence, terminate_upload_sequence | 多字节标签 tag=31 |
| mms-killRequest | 0 | kill | 多字节标签 tag=44 |
| mms-startRequest | 0 | start, stop | 多字节标签 tag=40 |
| mms-stopRequest | 0 | start, stop | 多字节标签 tag=41 |
| mms-resumeRequest | 0 | resume | 多字节标签 tag=42 |
| mms-resetRequest | 0 | reset | 多字节标签 tag=43 |
| mms-relinquishControl | 0 | relinquish_control, take_control | tag=20 |
| mms-takeControl | 0 | relinquish_control, take_control | tag=19 |

> **关于 mms-confirmedRequestPDU malformed=1 的说明**：该 pcap 由测试工具生成，服务端响应帧中包含无法识别的数据格式。Wireshark/tshark 也无法解析该帧。此 malformed 为 pcap 数据质量问题，非解析器缺陷。

### 3.2 MMS 事务详情基准

将 2.3 节的实际输出与以下基准逐一对比。每个 pcap 的输出必须**完全一致**（包括行数和顺序）。

#### iec61850_* 系列（Session/Presentation 完整栈）

**iec61850_get_name_list**
```
TX: resp: pdu_type=initiate_response
TX: req: pdu_type=confirmed_request, service=get_name_list | resp: pdu_type=confirmed_response, service=unknown
TX: req: pdu_type=conclude_request
TX: req: pdu_type=initiate_request | resp: pdu_type=confirmed_response, service=unknown
```

**iec61850_get_variable_access_attributes**
```
TX: resp: pdu_type=initiate_response
TX: req: pdu_type=confirmed_request, service=get_variable_access_attributes | resp: pdu_type=confirmed_response, service=unknown
TX: req: pdu_type=conclude_request
TX: req: pdu_type=initiate_request | resp: pdu_type=confirmed_response, service=unknown
```

**iec61850_read**
```
TX: resp: pdu_type=initiate_response
TX: req: pdu_type=confirmed_request, service=read | resp: pdu_type=confirmed_response, service=read
TX: req: pdu_type=conclude_request
TX: req: pdu_type=initiate_request | resp: pdu_type=confirmed_response, service=unknown
```

**iec61850_write**
```
TX: resp: pdu_type=initiate_response
TX: req: pdu_type=confirmed_request, service=write | resp: pdu_type=confirmed_response, service=unknown
TX: req: pdu_type=conclude_request
TX: req: pdu_type=initiate_request | resp: pdu_type=confirmed_response, service=unknown
```

**iec61850_release**
```
TX: resp: pdu_type=initiate_response
TX: req: pdu_type=conclude_request
TX: req: pdu_type=initiate_request | resp: pdu_type=confirmed_response, service=read
```

> **关于 `service=unknown` 响应的说明**：部分测试 pcap 中 MMS ConfirmedResponse 仅包含 invoke_id，不含 service 标签（最小化响应）。解析器对此进行了容错处理，记录为 `unknown` 而非报 malformed。

#### mms-* 系列（直连 MMS，回归基准）

**mms-readRequest** (回归基准 - 验证修改不破坏已有功能)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=read
```

#### mms-* 系列（扩展服务）

**mms-deleteProgramInvocation** (tag=39, 多字节标签)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=delete_program_invocation
```

**mms-getAlarmSummary** (tag=63, 多字节标签)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=get_alarm_summary
```

**mms-getDomainAttributes** (tag=37, 多字节标签)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=get_domain_attributes
```

**mms-initiateDownloadSequence** (tag=26)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=take_control
TX: req: pdu_type=confirmed_request, service=initiate_download_sequence
```

**mms-initiateUploadSequence** (tag=29)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=initiate_upload_sequence
```

**mms-terminateUploadSequence** (tag=31, 多字节标签)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=initiate_upload_sequence
TX: req: pdu_type=confirmed_request, service=terminate_upload_sequence
```

**mms-killRequest** (tag=44, 多字节标签)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=kill
```

**mms-startRequest** (tag=40, 多字节标签)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=stop
TX: req: pdu_type=confirmed_request, service=start
```

**mms-stopRequest** (tag=41, 多字节标签)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=start
TX: req: pdu_type=confirmed_request, service=stop
```

**mms-resumeRequest** (tag=42, 多字节标签)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=resume
```

**mms-resetRequest** (tag=43, 多字节标签)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=reset
```

**mms-relinquishControl** (tag=20)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=take_control
TX: req: pdu_type=confirmed_request, service=relinquish_control
```

**mms-takeControl** (tag=19)
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=take_control
TX: req: pdu_type=confirmed_request, service=relinquish_control
```

**mms-cancelRequest**
```
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=cancel_request
```

**mms-confirmedRequestPDU**
```
ANOMALY: malformed_data tx_id=2
TX: req: pdu_type=conclude_request
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: (empty - COTP connection)
```

## 4. 验证判定标准

### 4.1 必须通过的条件

1. **编译成功**：`make -j$(nproc)` 无错误
2. **单元测试全通过**：`cargo test --lib iec61850mms` 输出 32 passed, 0 failed
3. **iec61850_\* 系列 malformed 为 0**：所有 5 个 iec61850 pcap 的 malformed_data 计数必须为 0
4. **回归测试通过**：`mms-readRequest` 的 malformed=0，EVE 日志中包含 `service: "read"`
5. **扩展服务正确识别**：每个 mms-* 扩展服务 pcap 的 EVE 日志中，`service` 字段必须显示对应的服务名称（非 `"unknown"`）

### 4.2 已知限制（非失败项）

- **mms-confirmedRequestPDU malformed=1**：该 pcap 由测试工具生成，服务端响应帧中包含无法识别的数据格式。Wireshark/tshark 也���法解析该帧。不视为解析器缺陷。
- **ConfirmedResponse 中 `service=unknown`**：部分测试 pcap 的响应仅含 invoke_id 无 service 标签（最小化响应）。解析器容错处理为 `unknown`，不视为缺陷。

## 5. 一键自动化测试

如果不想手动逐步执行第 2 节的命令，可以使用以下自动化脚本一次完成全部测试和验证。

### 5.1 生成脚本

```bash
cat > /tmp/run_mms_tests.sh << 'SCRIPT_EOF'
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
SCRIPT_EOF
chmod +x /tmp/run_mms_tests.sh
echo "脚本已生成: /tmp/run_mms_tests.sh"
```

### 5.2 执行脚本

```bash
/tmp/run_mms_tests.sh
```

预期输出（末尾）：

```
=== Summary ===
PASSED: 42
FAILED: 0
ALL TESTS PASSED
```

## 6. mms-\* 系列 pcap malformed 问题分析与修复记录

### 6.1 问题现象

修复前，16 个 mms-\* 系列 pcap（不含 mms-readRequest）在 Suricata 解析时均产生 `malformed_data` 异常事件：

| pcap 分组 | malformed 数 | 涉及 pcap 数量 |
|-----------|-------------|---------------|
| mms-cancelRequest, mms-confirmedRequestPDU | 各 2 | 2 |
| 其余 14 个 mms-\* 扩展服务 | 各 1 | 14 |
| **合计** | **18** | **16** |

### 6.2 根因分析

以 `mms-deleteProgramInvocation.pcap` 为例，通过逐层排查定位到三个问题。

#### 6.2.1 问题一：pcap 服务端帧 TPKT 长度字段错误

mms-\* 系列 pcap 由测试工具生成。服务端响应帧（源端口 102）的 TPKT 头长度字段比实际 TCP 载荷短 2 字节。

TPKT 协议格式（RFC 1006）：

```
+--------+--------+--------+--------+
|  ver   | rsrvd  |    length       |   ← length 包含 TPKT 头自身的 4 字节
+--------+--------+--------+--------+
|              COTP data ...        |
+--------+--------+--------+--------+
```

示例（Frame 10，initiate-response 帧）：

```
实际 TCP 载荷长度 = 47 字节
TPKT length 字段值 = 45（少了 2 字节）
```

Suricata 的 `parse_tpkt_header` 按 TPKT length 截取载荷，导致后续 COTP/MMS 数据被截断。

#### 6.2.2 问题二：pcap 服务端帧 COTP DT 头字节错误

服务端响应帧的 COTP Data Transfer 头被写成了 `00 0F`，正确值应为 `02 F0`：

```
正确 COTP DT 头:  02 F0 80
                  │  │   └── EOT=1, TPDU-NR=0
                  │  └── PDU type = 0xF0 (Data Transfer)
                  └── LI = 2 (header length indicator)

错误 COTP DT 头:  00 0F
                  │  └── 0x0F 不匹配任何 COTP PDU type（0xF0 的字节翻转）
                  └── LI = 0（无效）
```

Suricata 的 `parse_cotp_header` 通过 `pdu_type_byte & 0xF0` 匹配类型，`0x0F & 0xF0 = 0x00` 不等于 DataTransfer（`0xF0`），导致帧被跳过。

#### 6.2.3 问题三：解析器 `is_direct_mms_pdu()` 不识别 primitive 编码标签

**这是导致 malformed 的核心代码缺陷**。即使修复了 pcap 中的 TPKT/COTP 问题，malformed 仍然存在。

MMS 协议使用 ASN.1 BER 编码，PDU 使用上下文标签 [0]~[13]。BER 标签字节的结构：

```
  bit 7-6    bit 5        bit 4-0
  ┌──────┐  ┌──────────┐  ┌──────────────┐
  │ class │  │constructed│  │  tag number  │
  └──────┘  └──────────┘  └──────────────┘
   10=ctx     0=primitive    0~30
              1=constructed
```

因此同一个上下文标签 [N] 有两种合法编码：

| 编码形式 | 字节值范围 | 适用场景 |
|---------|-----------|---------|
| constructed | `0xA0`~`0xAD` | SEQUENCE 类型（如 confirmed-RequestPDU [0]） |
| primitive | `0x80`~`0x8D` | 简单类型（如 conclude-RequestPDU [11] NULL） |

MMS PDU 中使用 primitive 编码的合法类型：

| PDU 类型 | 标签号 | BER 编码 | ASN.1 类型 |
|---------|--------|---------|-----------|
| cancel-RequestPDU | [5] | `0x85` | INTEGER |
| cancel-ResponsePDU | [6] | `0x86` | INTEGER |
| conclude-RequestPDU | [11] | `0x8B` | NULL |
| conclude-ResponsePDU | [12] | `0x8C` | NULL |

修复前的代码（`rust/src/iec61850mms/mms_pdu.rs:761`）：

```rust
pub fn is_direct_mms_pdu(payload: &[u8]) -> bool {
    if payload.is_empty() { return false; }
    let b = payload[0];
    (0xA0..=0xAD).contains(&b)  // 只检查 constructed 形式
}
```

当 COTP DT 帧载荷首字节为 `0x8B`（conclude-request）时：

1. `is_direct_mms_pdu([0x8B, 0x00])` 返回 `false`（`0x8B` 不在 `0xA0..=0xAD` 范围内）
2. 进入 `extract_mms_from_session()` 尝试按 Session 层解析
3. Session SPDU 类型检查：`0x8B` 不匹配任何已知 SPDU type（0x0D/0x0E/0x09/0x0A/0x01）
4. 返回 `Err(())`
5. 触发 `MalformedData` 事件（`mms.rs:333`）

调用链路：

```
parse_frames()                           ← mms.rs:260
  └─ is_direct_mms_pdu(payload)          ← mms_pdu.rs:761, 返回 false
       └─ extract_mms_from_session()     ← mms_pdu.rs:782, 返回 Err(())
            └─ set_event(MalformedData)  ← mms.rs:333
```

### 6.3 pcap 修复方案

编写 Python 脚本 `/tmp/fix_tpkt_length.py`，对 pcap 文件进行原地字节修复，不改变帧数量和大小：

**修复 1：TPKT length 字段**

遍历服务端响应帧（源端口 102），将 TPKT length 字段修正为实际 TCP 载荷长度：

```python
tpkt_len = struct.unpack_from('!H', data, payload_start + 2)[0]
if tpkt_len != payload_len:
    struct.pack_into('!H', data, payload_start + 2, payload_len)
```

**修复 2：COTP DT 头**

将错误的 `00 0F` 修正为正确的 `02 F0`：

```python
if cotp_li == 0x00 and cotp_pdu == 0x0F:
    data[cotp_start] = 0x02      # LI = 2
    data[cotp_start + 1] = 0xF0  # PDU type = DT
```

以 `mms-deleteProgramInvocation.pcap` 为例，修复效果：

```
Frame 6:  TPKT length 5  -> 7,  COTP header 00 0f -> 02 f0
Frame 10: TPKT length 45 -> 47, COTP header 00 0f -> 02 f0
Frame 14: TPKT length 7  -> 9,  COTP header 00 0f -> 02 f0
Frame 17: TPKT length 5  -> 7
```

> **注意**：仅修复 pcap 不能消除 malformed，还需要配合解析器代码修复（6.4 节）。修复后的 pcap 需配合 `-k none` 参数运行（绕过 TCP 校验和检查），因为修改了载荷字节但未重算校验和。

### 6.4 解析器代码修复

**修改文件**：`rust/src/iec61850mms/mms_pdu.rs`

**修改内容**：扩展 `is_direct_mms_pdu()` 函数，同时接受 primitive（`0x80~0x8D`）和 constructed（`0xA0~0xAD`）两种 BER 编码形式。

修复后代码：

```rust
/// 判断载荷是否直接以 MMS PDU 标签开头（无 Session/Presentation 封装）。
/// MMS PDU 使用 ASN.1 上下文标签 [0]~[13]，BER 编码时：
///   - constructed 形式：0xA0~0xAD（如 confirmed-RequestPDU [0] SEQUENCE）
///   - primitive 形式：0x80~0x8D（如 conclude-RequestPDU [11] NULL → 0x8B）
/// 两种编码均为合法 MMS PDU，需同时识别。
pub fn is_direct_mms_pdu(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    let b = payload[0];
    (0xA0..=0xAD).contains(&b) || (0x80..=0x8D).contains(&b)
}
```

此修复无需改动其他函数。下游的 `parse_mms_pdu()`（`mms_pdu.rs:576`）通过 `parse_ber_tlv()` 提取 tag number 时已自动忽略 constructed/primitive 位，因此 `0x8B` 和 `0xAB` 均被正确解析为 tag 11（conclude-RequestPDU）。

修复后调用链路（以 `0x8B` conclude-request 为例）：

```
parse_frames()                            ← mms.rs:260
  └─ is_direct_mms_pdu([0x8B, 0x00])     ← 返回 true（0x8B 在 0x80..=0x8D 范围内）
       └─ parse_mms_pdu([0x8B, 0x00])    ← mms_pdu.rs:576
            └─ parse_ber_tlv()            ← tag_num=11
                 └─ match 11 => Ok(MmsPdu::ConcludeRequest)
```

### 6.5 修复效果

| 指标 | 修复前 | 仅修复 pcap | 仅修复代码 | 两者都修复 |
|------|--------|------------|-----------|-----------|
| 总 malformed 数 | 18 | 仍 18（需 -k none 才生效） | **1** | **0**（需 -k none） |
| conclude_request 可识别 | 否 | 否 | **是** | **是** |
| cancel_request 可识别 | 否 | 否 | **是** | **是** |
| 服务端响应可解析 | 否 | 是（-k none） | 否 | **是**（-k none） |

**结论**：
- **代码修复是必要的**：仅此一项即可将 malformed 从 18 降至 1，并新增识别 `conclude_request` 和 `cancel_request` PDU 类型。适用于所有原始 pcap，无需修改任何 pcap 文件。
- **pcap 修复是可选的**：修复 pcap 中的 TPKT/COTP 错误可使服务端响应也被解析（如识别 `initiate_response`、`confirmed_response` 等），但需配合 `-k none` 绕过校验和。仅对需要验证双向解析的场景有意义。
- 剩余的 1 个 malformed（`mms-confirmedRequestPDU`）是该 pcap 中服务端帧特有的数据格式问题，非上述两类缺陷。
