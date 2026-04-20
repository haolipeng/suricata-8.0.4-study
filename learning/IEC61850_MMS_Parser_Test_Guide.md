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
test result: ok. 75 passed; 0 failed; 0 ignored; 0 measured; 552 filtered out
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
2. **单元测试全通过**：`cargo test --lib iec61850mms` 输出 75 passed, 0 failed
3. **iec61850_\* 系列 malformed 为 0**：所有 5 个 iec61850 pcap 的 malformed_data 计数必须为 0
4. **回归测试通过**：`mms-readRequest` 的 malformed=0，EVE 日志中包含 `service: "read"`
5. **扩展服务正确识别**：每个 mms-* 扩展服务 pcap 的 EVE 日志中，`service` 字段必须显示对应的服务名称（非 `"unknown"`）

### 4.2 已知限制（非失败项）

- **mms-confirmedRequestPDU malformed=1**：该 pcap 由测试工具生成，服务端响应帧中包含无法识别的数据格式。Wireshark/tshark 也无法解析该帧。不视为解析器缺陷。
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

## 7. GetNameList 三种查询类型专项测试

本节针对 GetNameList 服务的三种核心查询类型（domain / variable / variableList）进行专项验证，涵盖 pcap 集成测试和 Rust 单元测试两个层面。

### 7.1 背景

IEC 61850 中 GetNameList 有三种典型用法：

| 查询类型 | objectClass 值 | 典型 objectScope | 业务含义 |
|---------|---------------|-----------------|---------|
| 列出逻辑设备 | `domain` (9) | vmdSpecific | 发现 IED 上有哪些逻辑设备 |
| 列出变量 | `named_variable` (0) | domainSpecific | 发现某逻辑设备下的数据属性 |
| 列出数据集 | `named_variable_list` (2) | domainSpecific / aaSpecific | 发现数据集（Report/GOOSE 基础） |

代码中三种类型的解析路径完全一致（`parse_get_name_list_request` 中通过整数值映射字符串），区别仅在 `object_class` 字段的取值。

### 7.2 pcap 集成测试 — 使用 iec61850_get_name_list.pcap

#### 7.2.1 运行 Suricata

```bash
export SURICATA_DIR="/home/work/suricata-8.0.4-study"
export PCAP_DIR="/home/work/iec61850_protocol_parser/pcaps_file"
export SURICATA_YAML="$SURICATA_DIR/suricata.yaml"
export GNL_OUT="/tmp/mms_test_gnl"

rm -rf "$GNL_OUT" && mkdir -p "$GNL_OUT"
suricata -r "$PCAP_DIR/iec61850_get_name_list.pcap" \
    -S /dev/null -c "$SURICATA_YAML" -l "$GNL_OUT" 2>/dev/null
echo "done"
```

#### 7.2.2 输出文件位置

| 文件 | 路径 | 说明 |
|-----|------|------|
| EVE JSON 日志 | `/tmp/mms_test_gnl/eve.json` | 主要检查目标，包含 MMS 应用层日志 |
| Suricata 运行日志 | `/tmp/mms_test_gnl/suricata.log` | 排错用，正常运行时无 error |
| Stats 日志 | `/tmp/mms_test_gnl/stats.log` | 性能统计，本测试无需关注 |

#### 7.2.3 提取 GetNameList 事务详情

```bash
python3 learning/tests/extract_gnl_details.py /tmp/mms_test_gnl/eve.json
```

#### 7.2.4 预期输出

```
=== GetNameList Transaction ===
  Request:
    pdu_type:     confirmed_request
    invoke_id:    0
    service:      get_name_list
    object_class: named_variable
    object_scope: (absent)
    domain:       (absent)
    continue_after: (absent)
  Response:
    pdu_type:     confirmed_response
    invoke_id:    0
    identifiers:  (empty or absent)
    more_follows: (absent)
```

> **说明**：该 pcap 中的 GetNameList 请求类型为 `named_variable` + `vmdSpecific`。
> 响应为最小化 PDU（仅含 invokeID，无 service response body），因此 identifiers 和 more_follows 均为空。
> `object_scope` 字段在日志中缺失，是因为当前 `parse_get_name_list_request` 解析了 `vmdSpecific` 并设置了 `object_scope = "vmd_specific"`，但需确认日志输出中是否正确包含。

#### 7.2.5 验证 checklist

```bash
echo "=== GetNameList pcap 验证 ==="

# 1. 无 malformed 事件
mal=$(grep -c 'malformed_data' /tmp/mms_test_gnl/eve.json 2>/dev/null || echo 0)
echo "[$([ "$mal" -eq 0 ] && echo PASS || echo FAIL)] malformed_data 计数 = $mal (预期 0)"

# 2. 检出 get_name_list 服务
gnl=$(grep -c '"service":"get_name_list"' /tmp/mms_test_gnl/eve.json 2>/dev/null || echo 0)
echo "[$([ "$gnl" -ge 1 ] && echo PASS || echo FAIL)] get_name_list 服务检出 = $gnl 次 (预期 >= 1)"

# 3. object_class 为 named_variable
nv=$(grep -c '"object_class":"named_variable"' /tmp/mms_test_gnl/eve.json 2>/dev/null || echo 0)
echo "[$([ "$nv" -ge 1 ] && echo PASS || echo FAIL)] object_class=named_variable 检出 = $nv 次 (预期 >= 1)"

# 4. 有 initiate_request 和 conclude_request（完整 MMS 会话生命周期）
init=$(grep -c '"pdu_type":"initiate_request"' /tmp/mms_test_gnl/eve.json 2>/dev/null || echo 0)
conc=$(grep -c '"pdu_type":"conclude_request"' /tmp/mms_test_gnl/eve.json 2>/dev/null || echo 0)
echo "[$([ "$init" -ge 1 ] && echo PASS || echo FAIL)] initiate_request 检出 = $init 次 (预期 >= 1)"
echo "[$([ "$conc" -ge 1 ] && echo PASS || echo FAIL)] conclude_request 检出 = $conc 次 (预期 >= 1)"
```

预期输出：

```
=== GetNameList pcap 验证 ===
[PASS] malformed_data 计数 = 0 (预期 0)
[PASS] get_name_list 服务检出 = 1 次 (预期 >= 1)
[PASS] object_class=named_variable 检出 = 1 次 (预期 >= 1)
[PASS] initiate_request 检出 = 1 次 (预期 >= 1)
[PASS] conclude_request 检出 = 1 次 (预期 >= 1)
```

### 7.3 Rust 单元测试 — 覆盖全部三种查询类型

pcap 文件仅包含 `named_variable` (objectClass=0) 一种类型。**另外两种类型（domain、named_variable_list）通过 Rust 单元测试覆盖**，位于 `rust/src/iec61850mms/mms_pdu.rs` 的 `#[cfg(test)]` 模块中。

#### 7.3.1 三种类型对应的单元测试

| 查询类型 | objectClass | 测试函数 | 测试内容 |
|---------|------------|---------|---------|
| 列出逻辑设备 | `domain` (9) | `test_get_name_list_request_vmd_specific` | objectClass=9 + vmdSpecific，验证解析为 `"domain"` |
| 列出变量 | `named_variable` (0) | `test_get_name_list_request_domain_specific_with_continue_after` | objectClass=0 + domainSpecific("LD1") + continueAfter("Var100") |
| 列出数据集 | `named_variable_list` (2) | `test_get_name_list_request_aa_specific` | objectClass=2 + aaSpecific，验证解析为 `"named_variable_list"` |

另有 3 个 Response 侧测试：

| 测试函数 | 测试内容 |
|---------|---------|
| `test_get_name_list_response_multiple_identifiers` | 返回 3 个标识符 + moreFollows=true |
| `test_get_name_list_response_empty_list` | 空列表 + moreFollows=false |
| `test_get_name_list_response_truncate_at_64` | 超过 64 条时截断保护 |

#### 7.3.2 运行单元测试

```bash
cd /home/work/suricata-8.0.4-study/rust && cargo test --lib iec61850mms -- get_name_list
```

预期输出：

```
running 6 tests
test iec61850mms::mms_pdu::tests::test_get_name_list_request_aa_specific ... ok
test iec61850mms::mms_pdu::tests::test_get_name_list_request_domain_specific_with_continue_after ... ok
test iec61850mms::mms_pdu::tests::test_get_name_list_request_vmd_specific ... ok
test iec61850mms::mms_pdu::tests::test_get_name_list_response_empty_list ... ok
test iec61850mms::mms_pdu::tests::test_get_name_list_response_multiple_identifiers ... ok
test iec61850mms::mms_pdu::tests::test_get_name_list_response_truncate_at_64 ... ok

test result: ok. 6 passed; 0 failed; 0 ignored
```

#### 7.3.3 各测试用例的报文字节对照

**测试 1：domain (9) + vmdSpecific** — 列出逻辑设备

```
构造的 MMS PDU 字节：
A0 0E 02 01 01 A1 09 A0 03 80 01 09 A1 02 80 00
                                  ↑↑
                              objectClass = 9 → "domain"

验证断言：
  info.object_class  == Some("domain")
  info.object_scope  == Some("vmd_specific")
  info.domain_id     == None
  info.continue_after == None
```

**测试 2：named_variable (0) + domainSpecific("LD1") + continueAfter("Var100")** — 列出变量

```
构造的 MMS PDU 字节：
A0 19 02 01 02 A1 14 A0 03 80 01 00 A1 05 81 03 4C 44 31 82 06 56 61 72 31 30 30
                              ↑↑          ↑↑↑↑↑↑↑↑↑       ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑
                      objectClass=0    domainSpecific     continueAfter="Var100"
                      "named_variable"   "LD1"

验证断言：
  info.object_class   == Some("named_variable")
  info.object_scope   == Some("domain_specific")
  info.domain_id      == Some("LD1")
  info.continue_after == Some("Var100")
```

**测试 3：named_variable_list (2) + aaSpecific** — 列出数据集

```
构造的 MMS PDU 字节：
A0 0E 02 01 03 A1 09 A0 03 80 01 02 A1 02 82 00
                              ↑↑          ↑↑↑↑
                      objectClass=2    aaSpecific (NULL)
                      "named_variable_list"

验证断言：
  info.object_class  == Some("named_variable_list")
  info.object_scope  == Some("aa_specific")
  info.domain_id     == None
```

### 7.4 覆盖度总结

| 验证维度 | pcap 集成测试 | Rust 单元测试 |
|---------|-------------|-------------|
| objectClass = `named_variable` (0) | ✅ iec61850_get_name_list.pcap | ✅ test_..._domain_specific_with_continue_after |
| objectClass = `named_variable_list` (2) | ❌ 无对应 pcap | ✅ test_..._aa_specific |
| objectClass = `domain` (9) | ❌ 无对应 pcap | ✅ test_..._vmd_specific |
| objectScope = vmdSpecific | ✅ pcap 中使用 | ✅ test_..._vmd_specific |
| objectScope = domainSpecific | ❌ 无对应 pcap | ✅ test_..._domain_specific_with_continue_after |
| objectScope = aaSpecific | ❌ 无对应 pcap | ✅ test_..._aa_specific |
| continueAfter 分页 | ❌ 无对应 pcap | ✅ test_..._domain_specific_with_continue_after |
| Response: 多标识符 + moreFollows | ❌ pcap 响应为最小化 PDU | ✅ test_..._multiple_identifiers |
| Response: 空列表 + moreFollows=false | ❌ | ✅ test_..._empty_list |
| Response: 超 64 条截断 | ❌ | ✅ test_..._truncate_at_64 |

**结论**：
- **pcap 集成测试**验证了解析器在完整协议栈（TCP → TPKT → COTP → Session → Presentation → MMS）下对 `named_variable` + `vmdSpecific` 的端到端处理能力。
- **Rust 单元测试**补充覆盖了 `domain`、`named_variable_list` 以及 `domainSpecific`、`aaSpecific`、`continueAfter` 等 pcap 中未出现的场景。
- 若后续获取到包含 domain/variableList 查询的真实 pcap，建议补充集成测试用例。

## 8. 深度解析功能专项测试

本节覆盖四种已实现深度解析的 MMS 服务类型，验证解析器不仅能识别服务类型，还能正确提取内部字段并输出到 EVE JSON 日志。

### 8.1 测试范围

| 服务类型 | Request 深度解析字段 | Response 深度解析字段 | pcap 来源 |
|---------|---------------------|---------------------|-----------|
| GetVariableAccessAttributes | object_name (scope/domain/item) | （当前 pcap 响应为最小化 PDU） | iec61850_get_variable_access_attributes.pcap |
| GetNameList | object_class, object_scope, domain, continue_after | identifiers[], more_follows | iec61850_get_name_list.pcap |
| Initiate-Request/Response | local_detail, max_serv_outstanding, data_structure_nesting_level, version_number, supported_services | 同左 | iec61850_get_name_list.pcap（含 Initiate 握手） |
| GetNamedVariableListAttributes | object_name (scope/domain/item) | mms_deletable, variable_count, variables[] | session_254_172.20.4.111_38914.pcap |

### 8.2 环境准备

```bash
export SURICATA_DIR="/home/work/suricata-8.0.4-study"
export PCAP_DIR="/home/work/iec61850_protocol_parser/pcaps_file"
export SURICATA_YAML="$SURICATA_DIR/suricata.yaml"
export DEEP_OUT="/tmp/mms_deep_test"
rm -rf "$DEEP_OUT" && mkdir -p "$DEEP_OUT"
```

```bash
GNVLA_PCAP="/tmp/test_large_12/session_254_172.20.4.111_38914.pcap"
```

### 8.3 测试一：GetVariableAccessAttributes 深度解析

#### 8.3.1 运行

```bash
OUTDIR="$DEEP_OUT/gva"
rm -rf "$OUTDIR" && mkdir -p "$OUTDIR"
suricata -r "$PCAP_DIR/iec61850_get_variable_access_attributes.pcap" \
    -S /dev/null -c "$SURICATA_YAML" -l "$OUTDIR" 2>/dev/null
echo "done"
```

#### 8.3.2 提取深度解析字段

```bash
python3 learning/tests/extract_gva_details.py /tmp/mms_deep_test/gva/eve.json
```

#### 8.3.3 预期输出

```
=== GetVariableAccessAttributes Transaction ===
  Request:
    invoke_id: 0
    service:   get_variable_access_attributes
    variable.scope:  vmd_specific
    variable.domain: (absent)
    variable.item:   mu
  Response:
    invoke_id: 0
    service:   unknown
```

> **说明**：该 pcap 的 Response 为最小化 PDU（仅含 invokeID），因此 service 为 `unknown`，无深度字段。Request 侧成功提取了 `variable` 对象，scope 为 `vmd_specific`，item 为 `mu`。

#### 8.3.4 验证 checklist

```bash
echo "=== GetVariableAccessAttributes 深度解析验证 ==="
OUTDIR="/tmp/mms_deep_test/gva"

# 1. 无 malformed
mal=$(grep -c 'malformed_data' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$mal" -eq 0 ] && echo PASS || echo FAIL)] malformed = $mal (预期 0)"

# 2. 服务类型正确
svc=$(grep -c '"service":"get_variable_access_attributes"' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$svc" -ge 1 ] && echo PASS || echo FAIL)] service 检出 = $svc (预期 >= 1)"

# 3. variable.scope 深度字段存在
scope=$(grep -c '"scope":"vmd_specific"' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$scope" -ge 1 ] && echo PASS || echo FAIL)] variable.scope=vmd_specific 检出 = $scope (预期 >= 1)"

# 4. variable.item 深度字段正确
item=$(grep -c '"item":"mu"' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$item" -ge 1 ] && echo PASS || echo FAIL)] variable.item=mu 检出 = $item (预期 >= 1)"
```

预期输出：

```
=== GetVariableAccessAttributes 深度解析验证 ===
[PASS] malformed = 0 (预期 0)
[PASS] service 检出 = 1 (预期 >= 1)
[PASS] variable.scope=vmd_specific 检出 = 1 (预期 >= 1)
[PASS] variable.item=mu 检出 = 1 (预期 >= 1)
```

#### 8.3.5 Rust 单元测试

```bash
cd "$SURICATA_DIR/rust" && cargo test --lib iec61850mms -- get_var_access_attr
```

预期输出：

```
running 3 tests
test iec61850mms::mms_pdu::tests::test_get_var_access_attr_aa_specific ... ok
test iec61850mms::mms_pdu::tests::test_get_var_access_attr_domain_specific ... ok
test iec61850mms::mms_pdu::tests::test_get_var_access_attr_vmd_specific ... ok

test result: ok. 3 passed; 0 failed; 0 ignored
```

覆盖 ObjectName 的三种变体（vmd-specific、domain-specific、aa-specific）。

### 8.4 测试二：GetNameList 深度解析

> 本节为第 7 节的补充，聚焦于 Request/Response 内部字段的深度验证。

#### 8.4.1 运行

```bash
OUTDIR="$DEEP_OUT/gnl"
rm -rf "$OUTDIR" && mkdir -p "$OUTDIR"
suricata -r "$PCAP_DIR/iec61850_get_name_list.pcap" \
    -S /dev/null -c "$SURICATA_YAML" -l "$OUTDIR" 2>/dev/null
echo "done"
```

#### 8.4.2 提取深度解析字段

```bash
python3 learning/tests/extract_gnl_details.py /tmp/mms_deep_test/gnl/eve.json
```

#### 8.4.3 预期输出

```
=== GetNameList Transaction ===
  Request:
    invoke_id:      0
    object_class:   named_variable
    object_scope:   (absent)
    domain:         (absent)
    continue_after: (absent)
  Response:
    invoke_id:    0
    identifiers:  (empty or absent)
    more_follows: (absent)
```

> **说明**：该 pcap 中 Request 的 object_class 为 `named_variable`（objectClass=0），Response 为最小化 PDU。

#### 8.4.4 验证 checklist

```bash
echo "=== GetNameList 深度解析验证 ==="
OUTDIR="/tmp/mms_deep_test/gnl"

# 1. 无 malformed
mal=$(grep -c 'malformed_data' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$mal" -eq 0 ] && echo PASS || echo FAIL)] malformed = $mal (预期 0)"

# 2. object_class 深度字段
oc=$(grep -c '"object_class":"named_variable"' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$oc" -ge 1 ] && echo PASS || echo FAIL)] object_class=named_variable 检出 = $oc (预期 >= 1)"

# 3. 服务类型
svc=$(grep -c '"service":"get_name_list"' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$svc" -ge 1 ] && echo PASS || echo FAIL)] service=get_name_list 检出 = $svc (预期 >= 1)"
```

预期输出：

```
=== GetNameList 深度解析验证 ===
[PASS] malformed = 0 (预期 0)
[PASS] object_class=named_variable 检出 = 1 (预期 >= 1)
[PASS] service=get_name_list 检出 = 1 (预期 >= 1)
```

#### 8.4.5 Rust 单元测试

```bash
cd "$SURICATA_DIR/rust" && cargo test --lib iec61850mms -- get_name_list
```

预期输出：

```
running 6 tests
test iec61850mms::mms_pdu::tests::test_get_name_list_request_aa_specific ... ok
test iec61850mms::mms_pdu::tests::test_get_name_list_request_domain_specific_with_continue_after ... ok
test iec61850mms::mms_pdu::tests::test_get_name_list_request_vmd_specific ... ok
test iec61850mms::mms_pdu::tests::test_get_name_list_response_empty_list ... ok
test iec61850mms::mms_pdu::tests::test_get_name_list_response_multiple_identifiers ... ok
test iec61850mms::mms_pdu::tests::test_get_name_list_response_truncate_at_64 ... ok

test result: ok. 6 passed; 0 failed; 0 ignored
```

覆盖三种 objectClass（domain/named_variable/named_variable_list）、三种 objectScope、continueAfter 分页、Response 多标识符/空列表/64 条截断。

### 8.5 测试三：Initiate-Request/Response 深度解析

#### 8.5.1 运行

复用 8.4 的输出（同一 pcap 包含 Initiate 握手）。

#### 8.5.2 提取 Initiate 深度解析字段

```bash
python3 learning/tests/extract_initiate_details.py /tmp/mms_deep_test/gnl/eve.json
```

#### 8.5.3 预期输出

```
initiate_request ===
  local_detail: (absent)
  max_serv_outstanding: (absent)
  data_structure_nesting_level: (absent)
  version_number: (absent)
  supported_services: (absent)
initiate_response ===
  local_detail: (absent)
  max_serv_outstanding: (absent)
  data_structure_nesting_level: (absent)
  version_number: (absent)
  supported_services: (absent)
```

> **说明**：当前可用 pcap 中 Initiate PDU 经 Session/Presentation 层解封后被正确识别为 `initiate_request`/`initiate_response`，但内部详细参数字段在该 pcap 中未被携带（最小化 PDU）。Initiate 参数的深度解析能力通过 Rust 单元测试验证。

#### 8.5.4 验证 checklist

```bash
echo "=== Initiate 深度解析验证 ==="
OUTDIR="/tmp/mms_deep_test/gnl"

# 1. initiate_request 可检出
ir=$(grep -c '"pdu_type":"initiate_request"' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$ir" -ge 1 ] && echo PASS || echo FAIL)] initiate_request 检出 = $ir (预期 >= 1)"

# 2. initiate_response 可检出
is=$(grep -c '"pdu_type":"initiate_response"' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$is" -ge 1 ] && echo PASS || echo FAIL)] initiate_response 检出 = $is (预期 >= 1)"
```

预期输出：

```
=== Initiate 深度解析验证 ===
[PASS] initiate_request 检出 = 1 (预期 >= 1)
[PASS] initiate_response 检出 = 1 (预期 >= 1)
```

#### 8.5.5 Rust 单元测试

```bash
cd "$SURICATA_DIR/rust" && cargo test --lib iec61850mms -- initiate
```

预期输出：

```
running 5 tests
test iec61850mms::mms_pdu::tests::test_parse_initiate_detail_all_fields ... ok
test iec61850mms::mms_pdu::tests::test_parse_initiate_detail_empty ... ok
test iec61850mms::mms_pdu::tests::test_parse_initiate_detail_partial ... ok
test iec61850mms::mms_pdu::tests::test_parse_initiate_request ... ok
test iec61850mms::mms_pdu::tests::test_parse_initiate_response ... ok

test result: ok. 5 passed; 0 failed; 0 ignored
```

单元测试覆盖：
- `test_parse_initiate_detail_all_fields`：完整参数（local_detail=65000, max_serv_outstanding=10, nesting_level=4, version=1, supported_services 位图）
- `test_parse_initiate_detail_partial`：仅部分参数存在
- `test_parse_initiate_detail_empty`：空内容
- `test_parse_initiate_request` / `test_parse_initiate_response`：完整 PDU 级别解析

### 8.6 测试四：GetNamedVariableListAttributes 深度解析

#### 8.6.1 运行

```bash
OUTDIR="$DEEP_OUT/gnvla"
rm -rf "$OUTDIR" && mkdir -p "$OUTDIR"
suricata -r "$GNVLA_PCAP" \
    -S /dev/null -c "$SURICATA_YAML" -l "$OUTDIR" 2>/dev/null
echo "done"
```

#### 8.6.2 提取深度解析字段

```bash
python3 learning/tests/extract_gnvla_details.py /tmp/mms_deep_test/gnvla/eve.json
```

#### 8.6.3 预期输出

```
=== GetNamedVariableListAttributes Transaction ===
  Request:
    invoke_id: 1503081
    object_name.scope:  domain_specific
    object_name.domain: PQMR_1000_941
    object_name.item:   LLN0$dsMmtr1
  Response:
    invoke_id:      1503081
    mms_deletable:  False
    variable_count: 20
    variables (20 items):
      [0] scope=domain_specific, domain=PQMR_1000_941, item=MMTR1$MX$SupWh
      [1] scope=domain_specific, domain=PQMR_1000_941, item=MMTR1$MX$SupVArh
      [2] scope=domain_specific, domain=PQMR_1000_941, item=MMTR1$MX$DmdWh
      [3] scope=domain_specific, domain=PQMR_1000_941, item=MMTR1$MX$DmdVArh
      [4] scope=domain_specific, domain=PQMR_1000_941, item=MMTR2$MX$SupWh
      ... (15 more)
```

> **说明**：Request 成功提取了数据集名称 `LLN0$dsMmtr1`（domain=`PQMR_1000_941`）。Response 提取了 `mms_deletable=false` 和完整的 20 个变量列表，包括 MMTR1~MMTR5 的 SupWh/SupVArh/DmdWh/DmdVArh 共 20 个电能量测量属性。

#### 8.6.4 验证 checklist

```bash
echo "=== GetNamedVariableListAttributes 深度解析验证 ==="
OUTDIR="/tmp/mms_deep_test/gnvla"

# 1. 无 malformed
mal=$(grep -c 'malformed_data' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$mal" -eq 0 ] && echo PASS || echo FAIL)] malformed = $mal (预期 0)"

# 2. 服务类型
svc=$(grep -c '"service":"get_named_variable_list_attributes"' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$svc" -ge 1 ] && echo PASS || echo FAIL)] service 检出 = $svc (预期 >= 1)"

# 3. Request object_name 深度字段
domain=$(grep -c '"domain":"PQMR_1000_941"' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$domain" -ge 1 ] && echo PASS || echo FAIL)] domain=PQMR_1000_941 检出 = $domain (预期 >= 1)"

item=$(grep -c '"item":"LLN0\$dsMmtr1"' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$item" -ge 1 ] && echo PASS || echo FAIL)] item=LLN0\$dsMmtr1 检出 = $item (预期 >= 1)"

# 4. Response mms_deletable 深度字段
del=$(grep -c '"mms_deletable":false' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$del" -ge 1 ] && echo PASS || echo FAIL)] mms_deletable=false 检出 = $del (预期 >= 1)"

# 5. Response variable_count 深度字段
vc=$(grep -c '"variable_count":20' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$vc" -ge 1 ] && echo PASS || echo FAIL)] variable_count=20 检出 = $vc (预期 >= 1)"

# 6. Response variables 数组中的具体变量
v1=$(grep -c '"item":"MMTR1\$MX\$SupWh"' "$OUTDIR/eve.json" 2>/dev/null || echo 0)
echo "[$([ "$v1" -ge 1 ] && echo PASS || echo FAIL)] variable MMTR1\$MX\$SupWh 检出 = $v1 (预期 >= 1)"
```

预期输出：

```
=== GetNamedVariableListAttributes 深度解析验证 ===
[PASS] malformed = 0 (预期 0)
[PASS] service 检出 = 1 (预期 >= 1)
[PASS] domain=PQMR_1000_941 检出 = 1 (预期 >= 1)
[PASS] item=LLN0$dsMmtr1 检出 = 1 (预期 >= 1)
[PASS] mms_deletable=false 检出 = 1 (预期 >= 1)
[PASS] variable_count=20 检出 = 1 (预期 >= 1)
[PASS] variable MMTR1$MX$SupWh 检出 = 1 (预期 >= 1)
```

#### 8.6.5 Rust 单元测试

```bash
cd "$SURICATA_DIR/rust" && cargo test --lib iec61850mms -- get_named_var_list_attr
```

预期输出：

```
running 3 tests
test iec61850mms::mms_pdu::tests::test_parse_get_named_var_list_attr_request_domain_specific ... ok
test iec61850mms::mms_pdu::tests::test_parse_get_named_var_list_attr_request_vmd_specific ... ok
test iec61850mms::mms_pdu::tests::test_parse_get_named_var_list_attr_response ... ok

test result: ok. 3 passed; 0 failed; 0 ignored
```

覆盖：Request 的 domain-specific 和 vmd-specific 两种 ObjectName、Response 的 mmsDeletable + 多变量列表解析（上限 32 条截断）。

### 8.7 一键自动化深度解析测试脚本

```bash
cat > /tmp/run_deep_parse_tests.sh << 'SCRIPT_EOF'
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
SCRIPT_EOF
chmod +x /tmp/run_deep_parse_tests.sh
echo "脚本已生成: /tmp/run_deep_parse_tests.sh"
```

执行：

```bash
/tmp/run_deep_parse_tests.sh
```

预期输出（末尾）：

```
=== Summary ===
PASSED: 20
FAILED: 0
ALL DEEP PARSING TESTS PASSED
```

### 8.8 深度解析覆盖度总结

| 服务类型 | pcap 集成测试 | Rust 单元测试 | 深度字段覆盖 |
|---------|-------------|-------------|------------|
| GetVariableAccessAttributes Request | ✅ vmd_specific | ✅ vmd/domain/aa 三种 | scope, domain, item |
| GetVariableAccessAttributes Response | ❌ 最小化 PDU | ❌ 暂未实现 | - |
| GetNameList Request | ✅ named_variable | ✅ domain/named_variable/named_variable_list 三种 | object_class, object_scope, domain, continue_after |
| GetNameList Response | ❌ 最小化 PDU | ✅ 多标识符/空列表/64条截断 | identifiers[], more_follows |
| Initiate-Request | ✅ PDU 类型识别 | ✅ 全字段/部分字段/空内容 | local_detail, max_serv_outstanding, nesting_level, version, supported_services |
| Initiate-Response | ✅ PDU 类型识别 | ✅ 同上 | 同上 |
| GetNamedVarListAttr Request | ✅ domain_specific | ✅ domain/vmd 两种 | scope, domain, item |
| GetNamedVarListAttr Response | ✅ 完整 20 变量 | ✅ mmsDeletable + 多变量列表 | mms_deletable, variable_count, variables[] |
