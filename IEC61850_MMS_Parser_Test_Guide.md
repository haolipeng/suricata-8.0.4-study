# IEC 61850 MMS 协议解析器测试指南

## 1. 缺陷背景

Suricata 8.0.4 中的 IEC 61850 MMS 协议解析器存在三个缺陷，导致大量 MMS 流量无法正确解析：

### BUG-1：BER 多字节标签解析缺失

ASN.1 BER 编码中，当标签值 >= 31 时，使用多字节编码（首字节低 5 位全 1，后续字节以 base-128 编码实际标签值）。原始实现仅读取首字节低 5 位作为标签值，导致 tag >= 31 的 MMS 服务（如 `DeleteProgramInvocation`=39、`GetAlarmSummary`=63、`ObtainFile`=72 等）全部解析失败。

**受影响的服务**（tag >= 31）：`TerminateUploadSequence`(31)、`RequestDomainDownload`(32)、`GetDomainAttributes`(37)、`DeleteProgramInvocation`(39)、`Start`(40)、`Stop`(41)、`Resume`(42)、`Reset`(43)、`Kill`(44)、`GetAlarmSummary`(63)、`ObtainFile`(72)、`FileOpen`(73)~`FileDirectory`(78)。

### BUG-2：服务枚举映射不完整

`MmsConfirmedService` 枚举缺少 12+ 种服务类型（`Status`、`Rename`、`TakeControl`、`RelinquishControl`、`Start`/`Stop`/`Resume`/`Reset`/`Kill` 等），这些服务即使标签解析正确也会被标记为 `"unknown"`。

### BUG-3：不支持 OSI Session/Presentation 层

符合 IEC 61850 标准的完整协议栈为 `TCP → TPKT → COTP → Session → Presentation → MMS`。原始实现假设 COTP 之后直接是 MMS PDU，不支持 Session/Presentation 层封装，导致所有 `iec61850_*` 系列 pcap 全部解析失败（产生 `malformed_data` 异常）。

### BUG-4：EVE 日志模块注册缺失（已在测试前修复）

`src/output.c` 中缺少 `OutputRegisterTxSubModule` 调用，导致 MMS 事务信息不输出到 EVE JSON 日志。

## 2. 修复概述

| 修复项 | 涉及文件 | 修改内容 |
|--------|----------|----------|
| BER 多字节标签 | `rust/src/iec61850mms/mms_pdu.rs` | `parse_ber_tlv()` 返回类型从 `u8` 改为 `u32`，增加 base-128 多字节标签解码逻辑 |
| 服务枚举扩展 | `rust/src/iec61850mms/mms_pdu.rs` | `MmsConfirmedService` 新增 25 种服务变体，`Unknown(u8)` 改为 `Unknown(u32)`，更新 `from_request_tag`/`from_response_tag`/`as_str` |
| Session/Presentation 剥离 | `rust/src/iec61850mms/mms_pdu.rs` + `rust/src/iec61850mms/mms.rs` | 新增 `is_direct_mms_pdu()`、`extract_mms_from_session()`、`extract_mms_from_presentation()`；`parse_frames()` 增加层检测分支 |
| 响应容错 | `rust/src/iec61850mms/mms_pdu.rs` | `parse_confirmed_response()` 容忍缺少 service 标签的最小化响应 |
| EVE 日志注册 | `src/output.c` | 添加 `OutputRegisterTxSubModule` 调用 |

## 3. 测试环境准备

### 3.1 环境变量定义

```bash
# Suricata 源码目录
export SURICATA_DIR="/home/work/suricata-8.0.4-study"

# pcap 文件目录（包含 21 个测试 pcap）
export PCAP_DIR="/home/work/iec61850_protocol_parser/pcaps_file"

# 测试输出根目录
export TEST_OUT="/tmp/mms_test"

# Suricata 配置文件路径
export SURICATA_YAML="$SURICATA_DIR/suricata.yaml"

# 测试规则文件路径
export RULES_FILE="$TEST_OUT/mms_test.rules"
```

### 3.2 确认 pcap 文件完整

```bash
ls "$PCAP_DIR"/*.pcap | wc -l
# 预期输出：21
```

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

### 3.3 创建测试规则文件

```bash
mkdir -p "$TEST_OUT"
cat > "$RULES_FILE" << 'RULES_EOF'
# === PDU 类型检测规则 ===
alert iec61850-mms any any -> any any (msg:"MMS PDU: confirmed_request"; iec61850_mms.pdu_type; content:"confirmed_request"; sid:1000001; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS PDU: confirmed_response"; iec61850_mms.pdu_type; content:"confirmed_response"; sid:1000002; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS PDU: initiate_request"; iec61850_mms.pdu_type; content:"initiate_request"; sid:1000003; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS PDU: initiate_response"; iec61850_mms.pdu_type; content:"initiate_response"; sid:1000004; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS PDU: cancel_request"; iec61850_mms.pdu_type; content:"cancel_request"; sid:1000005; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS PDU: conclude_request"; iec61850_mms.pdu_type; content:"conclude_request"; sid:1000006; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS PDU: unconfirmed_pdu"; iec61850_mms.pdu_type; content:"unconfirmed_pdu"; sid:1000007; rev:1;)

# === 服务类型检测规则 ===
alert iec61850-mms any any -> any any (msg:"MMS Service: read"; iec61850_mms.service; content:"read"; sid:2000001; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: write"; iec61850_mms.service; content:"write"; sid:2000002; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: get_name_list"; iec61850_mms.service; content:"get_name_list"; sid:2000003; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: get_variable_access_attributes"; iec61850_mms.service; content:"get_variable_access_attributes"; sid:2000004; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: identify"; iec61850_mms.service; content:"identify"; sid:2000005; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: obtain_file"; iec61850_mms.service; content:"obtain_file"; sid:2000006; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: file_open"; iec61850_mms.service; content:"file_open"; sid:2000007; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: file_read"; iec61850_mms.service; content:"file_read"; sid:2000008; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: file_close"; iec61850_mms.service; content:"file_close"; sid:2000009; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: file_rename"; iec61850_mms.service; content:"file_rename"; sid:2000010; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: file_delete"; iec61850_mms.service; content:"file_delete"; sid:2000011; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: file_directory"; iec61850_mms.service; content:"file_directory"; sid:2000012; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: define_named_variable_list"; iec61850_mms.service; content:"define_named_variable_list"; sid:2000013; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: get_named_variable_list_attributes"; iec61850_mms.service; content:"get_named_variable_list_attributes"; sid:2000014; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: delete_named_variable_list"; iec61850_mms.service; content:"delete_named_variable_list"; sid:2000015; rev:1;)
RULES_EOF
```

### 3.4 编译与安装

```bash
cd "$SURICATA_DIR"
make -j$(nproc) && make install
```

### 3.5 运行 Rust 单元测试

```bash
cd "$SURICATA_DIR/rust"
cargo test --lib iec61850mms
```

预期输出：23 个测试全部通过。

```
test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 552 filtered out
```

## 4. 测试执行

### 4.1 批量运行所有 pcap

```bash
for pcap in "$PCAP_DIR"/*.pcap; do
    fname=$(basename "$pcap" .pcap)
    outdir="$TEST_OUT/$fname"
    rm -rf "$outdir" && mkdir -p "$outdir"
    suricata -r "$pcap" -S "$RULES_FILE" \
        -c "$SURICATA_YAML" -l "$outdir" 2>/dev/null
done
```

### 4.2 提取汇总结果

```bash
echo "pcap_name | alerts | malformed"
echo "----------|--------|----------"
for pcap in "$PCAP_DIR"/*.pcap; do
    fname=$(basename "$pcap" .pcap)
    outdir="$TEST_OUT/$fname"
    alerts=$(grep -c '"event_type":"alert"' "$outdir/eve.json" 2>/dev/null || echo 0)
    malformed=$(grep -c 'malformed_data' "$outdir/eve.json" 2>/dev/null || echo 0)
    echo "$fname | $alerts | $malformed"
done
```

### 4.3 提取 MMS 事务详情

```bash
for pcap in "$PCAP_DIR"/*.pcap; do
    fname=$(basename "$pcap" .pcap)
    outdir="$TEST_OUT/$fname"
    echo "=== $fname ==="
    python3 -c "
import json, sys
with open('$outdir/eve.json') as f:
    for line in f:
        ev = json.loads(line)
        if ev.get('event_type') == 'iec61850_mms':
            mms = ev.get('iec61850_mms', {})
            req = mms.get('request', {})
            resp = mms.get('response', {})
            parts = []
            if req:
                pdu = req.get('pdu_type','')
                svc = req.get('service','')
                s = 'req: pdu_type=' + pdu
                if svc: s += ', service=' + svc
                parts.append(s)
            if resp:
                pdu = resp.get('pdu_type','')
                svc = resp.get('service','')
                s = 'resp: pdu_type=' + pdu
                if svc: s += ', service=' + svc
                parts.append(s)
            if parts:
                print('  TX: ' + ' | '.join(parts))
            elif not req and not resp:
                print('  TX: (empty - COTP connection)')
        elif ev.get('event_type') == 'anomaly' and 'malformed' in line:
            print('  ANOMALY: malformed_data tx_id=%s' % ev.get('tx_id'))
"
    echo ""
done
```

### 4.4 提取告警 SID 详情

```bash
for pcap in "$PCAP_DIR"/*.pcap; do
    fname=$(basename "$pcap" .pcap)
    outdir="$TEST_OUT/$fname"
    echo "=== $fname ==="
    python3 -c "
import json
with open('$outdir/eve.json') as f:
    for line in f:
        ev = json.loads(line)
        if ev.get('event_type') == 'alert':
            alert = ev.get('alert', {})
            print('  SID=%s %s' % (alert.get('signature_id',''), alert.get('signature','')))
"
    echo ""
done
```

## 5. 预期结果基准表

### 5.1 汇总指标

| pcap | alerts | malformed | 说明 |
|------|--------|-----------|------|
| iec61850_get_name_list | 7 | 0 | Session/Presentation 正确剥离 |
| iec61850_get_variable_access_attributes | 7 | 0 | Session/Presentation 正确剥离 |
| iec61850_read | 8 | 0 | Session/Presentation 正确剥离 |
| iec61850_release | 5 | 0 | Session/Presentation 正确剥离 |
| iec61850_write | 7 | 0 | Session/Presentation 正确剥离 |
| mms-readRequest | 3 | 0 | 回归基准，Read 服务正常 |
| mms-cancelRequest | 1 | 2 | pcap 服务端帧 TPKT 格式异常 |
| mms-confirmedRequestPDU | 1 | 2 | pcap 服务端帧 TPKT 格式异常 |
| mms-deleteProgramInvocation | 2 | 1 | 多字节标签 tag=39 正确解析 |
| mms-getAlarmSummary | 2 | 1 | 多字节标签 tag=63 正确解析 |
| mms-getDomainAttributes | 2 | 1 | 多字节标签 tag=37 正确解析 |
| mms-initiateDownloadSequence | 3 | 1 | tag=26 正确解析 |
| mms-initiateUploadSequence | 2 | 1 | tag=29 正确解析 |
| mms-terminateUploadSequence | 3 | 1 | 多字节标签 tag=31 正确解析 |
| mms-killRequest | 2 | 1 | 多字节标签 tag=44 正确解析 |
| mms-startRequest | 3 | 1 | 多字节标签 tag=40 正确解析 |
| mms-stopRequest | 3 | 1 | 多字节标签 tag=41 正确解析 |
| mms-resumeRequest | 2 | 1 | 多字节标签 tag=42 正确解析 |
| mms-resetRequest | 2 | 1 | 多字节标签 tag=43 正确解析 |
| mms-relinquishControl | 3 | 1 | tag=20 正确解析 |
| mms-takeControl | 3 | 1 | tag=19 正确解析 |

> **关于 mms-\* 系列 malformed 的说明**：这些 pcap 由测试工具生成，服务端响应帧的 TPKT 头长度字段不正确（如 TPKT length=5 而实际 COTP 需要至少 3 字节），Wireshark/tshark 也无法解析这些帧。此 malformed 为 pcap 数据质量问题，非解析器缺陷。

### 5.2 MMS 事务详情基准

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

#### mms-* 系列（扩展服务 - 验证 BUG-1 和 BUG-2 修复）

**mms-deleteProgramInvocation** (tag=39, 多字节标签)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=delete_program_invocation
TX: (empty - COTP connection)
```

**mms-getAlarmSummary** (tag=63, 多字节标签)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=get_alarm_summary
TX: (empty - COTP connection)
```

**mms-getDomainAttributes** (tag=37, 多字节标签)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=get_domain_attributes
TX: (empty - COTP connection)
```

**mms-initiateDownloadSequence** (tag=26)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=take_control
TX: req: pdu_type=confirmed_request, service=initiate_download_sequence
TX: (empty - COTP connection)
```

**mms-initiateUploadSequence** (tag=29)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=initiate_upload_sequence
TX: (empty - COTP connection)
```

**mms-terminateUploadSequence** (tag=31, 多字节标签)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=initiate_upload_sequence
TX: req: pdu_type=confirmed_request, service=terminate_upload_sequence
TX: (empty - COTP connection)
```

**mms-killRequest** (tag=44, 多字节标签)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=kill
TX: (empty - COTP connection)
```

**mms-startRequest** (tag=40, 多字节标签)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=stop
TX: req: pdu_type=confirmed_request, service=start
TX: (empty - COTP connection)
```

**mms-stopRequest** (tag=41, 多字节标签)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=start
TX: req: pdu_type=confirmed_request, service=stop
TX: (empty - COTP connection)
```

**mms-resumeRequest** (tag=42, 多字节标签)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=resume
TX: (empty - COTP connection)
```

**mms-resetRequest** (tag=43, 多字节标签)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=reset
TX: (empty - COTP connection)
```

**mms-relinquishControl** (tag=20)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=take_control
TX: req: pdu_type=confirmed_request, service=relinquish_control
TX: (empty - COTP connection)
```

**mms-takeControl** (tag=19)
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: req: pdu_type=confirmed_request, service=take_control
TX: req: pdu_type=confirmed_request, service=relinquish_control
TX: (empty - COTP connection)
```

**mms-cancelRequest**
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: (empty - COTP connection)
TX: (empty - COTP connection)
```

**mms-confirmedRequestPDU**
```
TX: (empty - COTP connection)
TX: req: pdu_type=initiate_request
TX: (empty - COTP connection)
TX: (empty - COTP connection)
```

### 5.3 告警 SID 基准

#### iec61850_* 系列

| pcap | 预期 SID 列表 |
|------|---------------|
| iec61850_get_name_list | 1000003, 1000004, 1000001, **2000003**(get_name_list), 1000002, 1000006, 1000002 |
| iec61850_get_variable_access_attributes | 1000003, 1000004, 1000001, **2000004**(get_variable_access_attributes), 1000002, 1000006, 1000002 |
| iec61850_read | 1000003, 1000004, 1000001, **2000001**(read), 1000002, **2000001**(read), 1000006, 1000002 |
| iec61850_write | 1000003, 1000004, 1000001, **2000002**(write), 1000002, 1000006, 1000002 |
| iec61850_release | 1000003, 1000004, 1000006, 1000002, **2000001**(read) |

#### mms-* 系列

| pcap | 预期 SID 列表 |
|------|---------------|
| mms-readRequest | 1000003, 1000001, **2000001**(read) |
| mms-deleteProgramInvocation | 1000003, 1000001 |
| mms-getAlarmSummary | 1000003, 1000001 |
| mms-getDomainAttributes | 1000003, 1000001 |
| mms-initiateDownloadSequence | 1000003, 1000001, 1000001 |
| mms-initiateUploadSequence | 1000003, 1000001 |
| mms-terminateUploadSequence | 1000003, 1000001, 1000001 |
| mms-killRequest | 1000003, 1000001 |
| mms-startRequest | 1000003, 1000001, 1000001 |
| mms-stopRequest | 1000003, 1000001, 1000001 |
| mms-resumeRequest | 1000003, 1000001 |
| mms-resetRequest | 1000003, 1000001 |
| mms-relinquishControl | 1000003, 1000001, 1000001 |
| mms-takeControl | 1000003, 1000001, 1000001 |
| mms-cancelRequest | 1000003 |
| mms-confirmedRequestPDU | 1000003 |

## 6. 验证判定标准

### 6.1 必须通过的条件

1. **编译成功**：`make -j$(nproc)` 无错误
2. **单元测试全通过**：`cargo test --lib iec61850mms` 输出 23 passed, 0 failed
3. **iec61850_\* 系列 malformed 为 0**：所有 5 个 iec61850 pcap 的 malformed_data 计数必须为 0
4. **回归测试通过**：`mms-readRequest` 的 alerts=3、malformed=0，service=read 正确检测
5. **扩展服务正确识别**：每个 mms-* 扩展服务 pcap 的 EVE 日志中，`service` 字段必须显示对应的服务名称（非 `"unknown"`）

### 6.2 已知限制（非失败项）

- **mms-\* 系列 malformed=1~2**：pcap 本身服务端帧 TPKT 格式异常，Wireshark/tshark 也无法解析。不视为解析器缺陷。
- **ConfirmedResponse 中 `service=unknown`**：部分测试 pcap 的响应仅含 invoke_id 无 service 标签（最小化响应）。解析器容错处理为 `unknown`，不视为缺陷。
- **mms-cancelRequest 和 mms-confirmedRequestPDU 的 alerts 较少**：这两个 pcap 的特定 MMS 操作（CancelRequest 和通用 ConfirmedRequest）未在当前规则中设置专用服务匹配规则。

## 7. 自动化验证脚本

将以下脚本保存为 `run_mms_tests.sh` 可一键执行全部测试并自动判定结果：

```bash
#!/bin/bash
set -e

# === 配置 ===
SURICATA_DIR="${SURICATA_DIR:-/home/work/suricata-8.0.4-study}"
PCAP_DIR="${PCAP_DIR:-/home/work/iec61850_protocol_parser/pcaps_file}"
TEST_OUT="${TEST_OUT:-/tmp/mms_test}"
SURICATA_YAML="${SURICATA_YAML:-$SURICATA_DIR/suricata.yaml}"
RULES_FILE="$TEST_OUT/mms_test.rules"

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

# === 步骤 1：创建规则文件 ===
mkdir -p "$TEST_OUT"

# 辅助函数
get_alerts() {
    local c
    c=$(grep -c '"event_type":"alert"' "$TEST_OUT/$1/eve.json" 2>/dev/null) || c=0
    echo "$c"
}
get_malformed() {
    local c
    c=$(grep -c 'malformed_data' "$TEST_OUT/$1/eve.json" 2>/dev/null) || c=0
    echo "$c"
}
has_service() {
    grep -q "\"service\":\"$2\"" "$TEST_OUT/$1/eve.json" 2>/dev/null
}

cat > "$RULES_FILE" << 'RULES_EOF'
alert iec61850-mms any any -> any any (msg:"MMS PDU: confirmed_request"; iec61850_mms.pdu_type; content:"confirmed_request"; sid:1000001; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS PDU: confirmed_response"; iec61850_mms.pdu_type; content:"confirmed_response"; sid:1000002; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS PDU: initiate_request"; iec61850_mms.pdu_type; content:"initiate_request"; sid:1000003; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS PDU: initiate_response"; iec61850_mms.pdu_type; content:"initiate_response"; sid:1000004; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS PDU: cancel_request"; iec61850_mms.pdu_type; content:"cancel_request"; sid:1000005; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS PDU: conclude_request"; iec61850_mms.pdu_type; content:"conclude_request"; sid:1000006; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS PDU: unconfirmed_pdu"; iec61850_mms.pdu_type; content:"unconfirmed_pdu"; sid:1000007; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: read"; iec61850_mms.service; content:"read"; sid:2000001; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: write"; iec61850_mms.service; content:"write"; sid:2000002; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: get_name_list"; iec61850_mms.service; content:"get_name_list"; sid:2000003; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: get_variable_access_attributes"; iec61850_mms.service; content:"get_variable_access_attributes"; sid:2000004; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: identify"; iec61850_mms.service; content:"identify"; sid:2000005; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: obtain_file"; iec61850_mms.service; content:"obtain_file"; sid:2000006; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: file_open"; iec61850_mms.service; content:"file_open"; sid:2000007; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: file_read"; iec61850_mms.service; content:"file_read"; sid:2000008; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: file_close"; iec61850_mms.service; content:"file_close"; sid:2000009; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: file_rename"; iec61850_mms.service; content:"file_rename"; sid:2000010; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: file_delete"; iec61850_mms.service; content:"file_delete"; sid:2000011; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: file_directory"; iec61850_mms.service; content:"file_directory"; sid:2000012; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: define_named_variable_list"; iec61850_mms.service; content:"define_named_variable_list"; sid:2000013; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: get_named_variable_list_attributes"; iec61850_mms.service; content:"get_named_variable_list_attributes"; sid:2000014; rev:1;)
alert iec61850-mms any any -> any any (msg:"MMS Service: delete_named_variable_list"; iec61850_mms.service; content:"delete_named_variable_list"; sid:2000015; rev:1;)
RULES_EOF

# === 步骤 2：运行所有 pcap ===
echo "=== Running Suricata against all pcaps ==="
for pcap in "$PCAP_DIR"/*.pcap; do
    fname=$(basename "$pcap" .pcap)
    outdir="$TEST_OUT/$fname"
    rm -rf "$outdir" && mkdir -p "$outdir"
    suricata -r "$pcap" -S "$RULES_FILE" \
        -c "$SURICATA_YAML" -l "$outdir" 2>/dev/null
done

# === 步骤 3：验证 ===
echo ""
echo "=== Verification ==="

echo ""
echo "[Test Group 1] iec61850_* Session/Presentation layer (BUG-3)"
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
check "mms-readRequest: alerts=3" test "$(get_alerts mms-readRequest)" -eq 3
check "mms-readRequest: service=read" has_service mms-readRequest read

echo ""
echo "[Test Group 4] Extended services - multi-byte tags (BUG-1 + BUG-2)"
check "mms-deleteProgramInvocation: service=delete_program_invocation" has_service mms-deleteProgramInvocation delete_program_invocation
check "mms-getAlarmSummary: service=get_alarm_summary" has_service mms-getAlarmSummary get_alarm_summary
check "mms-getDomainAttributes: service=get_domain_attributes" has_service mms-getDomainAttributes get_domain_attributes
check "mms-killRequest: service=kill" has_service mms-killRequest kill
check "mms-startRequest: service=start" has_service mms-startRequest start
check "mms-stopRequest: service=stop" has_service mms-stopRequest stop
check "mms-resumeRequest: service=resume" has_service mms-resumeRequest resume
check "mms-resetRequest: service=reset" has_service mms-resetRequest reset

echo ""
echo "[Test Group 5] Extended services - standard tags (BUG-2)"
check "mms-takeControl: service=take_control" has_service mms-takeControl take_control
check "mms-relinquishControl: service=relinquish_control" has_service mms-relinquishControl relinquish_control
check "mms-initiateDownloadSequence: service=initiate_download_sequence" has_service mms-initiateDownloadSequence initiate_download_sequence
check "mms-initiateUploadSequence: service=initiate_upload_sequence" has_service mms-initiateUploadSequence initiate_upload_sequence
check "mms-terminateUploadSequence: service=terminate_upload_sequence" has_service mms-terminateUploadSequence terminate_upload_sequence

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
```

使用方法：

```bash
chmod +x run_mms_tests.sh
./run_mms_tests.sh
```
