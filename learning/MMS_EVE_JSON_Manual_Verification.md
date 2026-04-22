# MMS 协议解析 EVE JSON 手动验证指南

本文档用于手动运行 Suricata 解析 pcap，对照 `eve.json` 输出验证 IEC 61850 MMS 协议解析是否正确。

## 1. 前置条件

### 1.1 编译安装

```bash
cd /home/work/suricata-8.0.4-study && make -j$(nproc) && make install
```

### 1.2 设置环境变量

```bash
export PCAP_DIR="/home/work/iec61850_protocol_parser/pcaps_file"
export SURICATA_YAML="/home/work/suricata-8.0.4-study/suricata.yaml"
export OUT="/tmp/mms_manual_verify"
```

### 1.3 通用说明

- 每个 MMS PDU 独立一个事务，不做请求/响应配对
- COTP CR/CC 连接帧不创建事务，里面无MMS内容，对于流量审计和威胁检测无意义
- 每条输出包含 `direction`（`"request"` 或 `"response"`）和 PDU 字段
- 所有 IEC 61850 完整栈 pcap 均以 Initiate 请求/响应开头，以 Conclude 结尾，后续场景仅列出核心事务，省略首尾的 Initiate 和 Conclude
- 场景 1-6 使用真实抓包 pcap，场景 7-12 使用 `tools/generate_test_pcaps.py` 构造的 pcap（覆盖异常路径和深度解析盲区）

---

## 2. 分场景验证

### 场景 1：MMS 综合场景（mms.pcap）

含 Session/Presentation 层，覆盖 GetVariableAccessAttributes + Read + Conclude。

```bash
mkdir -p "$OUT/s1" && rm -rf "$OUT/s1"/*
suricata -r "$PCAP_DIR/mms.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s1" 2>/dev/null
cat "$OUT/s1/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期输出（共 8 条）

```json
{ "direction": "request",  "pdu_type": "initiate_request" }
{ "direction": "response", "pdu_type": "initiate_response" }
{ "direction": "request",  "pdu_type": "confirmed_request",  "invoke_id": 303731, "service": "get_variable_access_attributes", "variable": { "scope": "domain_specific", "domain": "AA1E1Q01FP2LD0", "item": "LLN0$BR$rcb_B02" } }
{ "direction": "response", "pdu_type": "confirmed_error",    "invoke_id": 303731 }
{ "direction": "request",  "pdu_type": "confirmed_request",  "invoke_id": 303732, "service": "read", "variables": [{ "scope": "domain_specific", "domain": "AA1E1Q01FP2LD0", "item": "LLN0$BR$rcb_B02" }] }
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 303732, "service": "read", "result_count": 0, "results": [] }
{ "direction": "request",  "pdu_type": "conclude_request" }
{ "direction": "response", "pdu_type": "conclude_response" }
```

#### 验证要点

- GVAA 服务正确识别，`variable` 含 scope/domain/item
- 服务端返回 `confirmed_error`，解析器正确识别
- Read 响应深度解析出 `result_count` 和 `results`
- 无空事务（COTP CR/CC 不创建事务）

---

### 场景 2：Write（iec61850_write.pcap）

```bash
mkdir -p "$OUT/s2" && rm -rf "$OUT/s2"/*
suricata -r "$PCAP_DIR/iec61850_write.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s2" 2>/dev/null
cat "$OUT/s2/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期核心事务

```json
{ "direction": "request",  "pdu_type": "confirmed_request",  "invoke_id": 0, "service": "write" }
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 0, "service": "unknown" }
```

共 6 条（含 Initiate 2 条 + Conclude 2 条）。该 pcap 的 Write 请求不含可解析的变量规范，故无 `variables` 字段。响应为最小化 PDU，service 为 `unknown`。

---

### 场景 3：GetNameList（iec61850_get_name_list.pcap）

```bash
mkdir -p "$OUT/s3" && rm -rf "$OUT/s3"/*
suricata -r "$PCAP_DIR/iec61850_get_name_list.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s3" 2>/dev/null
cat "$OUT/s3/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期核心事务

```json
{ "direction": "request",  "pdu_type": "confirmed_request",  "invoke_id": 0, "service": "get_name_list", "object_class": "named_variable", "object_scope": "vmd_specific" }
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 0, "service": "unknown" }
```

共 6 条（含 Initiate 2 条 + Conclude 2 条）。

- `object_class = "named_variable"` — 查询类型：列出变量
- `object_scope = "vmd_specific"` — VMD 级别，无 domain
- 本 pcap 仅覆盖 `named_variable`，`domain` 和 `named_variable_list` 两种类型通过 Rust 单元测试覆盖

---

### 场景 4：GetVariableAccessAttributes（iec61850_get_variable_access_attributes.pcap）

```bash
mkdir -p "$OUT/s4" && rm -rf "$OUT/s4"/*
suricata -r "$PCAP_DIR/iec61850_get_variable_access_attributes.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s4" 2>/dev/null
cat "$OUT/s4/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期核心事务

```json
{ "direction": "request",  "pdu_type": "confirmed_request",  "invoke_id": 0, "service": "get_variable_access_attributes", "variable": { "scope": "vmd_specific", "item": "mu" } }
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 0, "service": "unknown" }
```

共 6 条（含 Initiate 2 条 + Conclude 2 条）。`variable.scope = "vmd_specific"` 故无 domain 字段。

---

### 场景 5：GetNamedVariableListAttributes（外部 pcap，可选）

pcap 来自真实抓包，位于 `/tmp/test_large_12/`，不存在则跳过。

```bash
GNVLA_PCAP="/tmp/test_large_12/session_254_172.20.4.111_38914.pcap"
if [ -f "$GNVLA_PCAP" ]; then
    mkdir -p "$OUT/s5" && rm -rf "$OUT/s5"/*
    suricata -r "$GNVLA_PCAP" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s5" 2>/dev/null
    cat "$OUT/s5/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
else
    echo "SKIP: pcap not found"
fi
```

#### 预期核心事务

请求：
```json
{ "direction": "request", "pdu_type": "confirmed_request", "invoke_id": 1503081, "service": "get_named_variable_list_attributes", "object_name": { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "LLN0$dsMmtr1" } }
```

响应（展示前 5 条，实际共 20 个变量）：
```json
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 1503081, "service": "get_named_variable_list_attributes", "mms_deletable": false, "variable_count": 20, "variables": [
  { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR1$MX$SupWh" },
  { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR1$MX$SupVArh" },
  { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR1$MX$DmdWh" },
  { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR1$MX$DmdVArh" },
  { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR2$MX$SupWh" }
] }
```

---

### 场景 6：MMS 直连格式（mms-readRequest.pcap）

无 Session/Presentation 层，解析器通过 `is_direct_mms_pdu` 自动检测。

```bash
mkdir -p "$OUT/s6" && rm -rf "$OUT/s6"/*
suricata -r "$PCAP_DIR/mms-readRequest.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s6" 2>/dev/null
cat "$OUT/s6/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期输出（共 2 条，该 pcap 仅含客户端请求帧）

```json
{ "direction": "request", "pdu_type": "initiate_request", "local_detail": 31, "max_serv_outstanding_calling": 3, "max_serv_outstanding_called": 3, "data_structure_nesting_level": 2056, "version_number": 1, "supported_services": "03ffffffffffffffffffffff" }
{ "direction": "request", "pdu_type": "confirmed_request", "invoke_id": 1, "service": "read", "variables": [{ "scope": "vmd_specific", "item": "$MSG$1$$" }] }
```

- Initiate 协商参数（`local_detail`、`max_serv_outstanding_calling/called`、`version_number`、`supported_services` 等）被深度解析
- 无 COTP CR/CC 空事务

---

### 场景 7：UnconfirmedPDU — InformationReport（unconfirmed_information_report.pcap）

构造 pcap，覆盖 UnconfirmedPDU 的 InformationReport 服务（IEC 61850 实时数据上报）。

```bash
mkdir -p "$OUT/s7" && rm -rf "$OUT/s7"/*
suricata -r "$PCAP_DIR/unconfirmed_information_report.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s7" 2>/dev/null
cat "$OUT/s7/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期核心事务

```json
{ "direction": "response", "pdu_type": "unconfirmed", "service": "information_report" }
```

共 5 条（含 Initiate 2 条 + Conclude 2 条）。`pdu_type = "unconfirmed"` 正确识别非确认 PDU，`service = "information_report"` 正确识别服务类型。Initiate 事务含 `local_detail`、`max_serv_outstanding_calling`/`called`、`data_structure_nesting_level` 等协商参数。

---

### 场景 8：InitiateError（initiate_error.pcap）

构造 pcap，覆盖服务端拒绝 MMS 关联建立的场景。

```bash
mkdir -p "$OUT/s8" && rm -rf "$OUT/s8"/*
suricata -r "$PCAP_DIR/initiate_error.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s8" 2>/dev/null
cat "$OUT/s8/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期输出（共 2 条）

```json
{ "direction": "request",  "pdu_type": "initiate_request", "local_detail": 1024, "max_serv_outstanding_calling": 5, "max_serv_outstanding_called": 5, "data_structure_nesting_level": 4 }
{ "direction": "response", "pdu_type": "initiate_error" }
```

- 客户端发起 Initiate，服务端返回 `initiate_error` 拒绝
- 无后续 MMS 数据交换（关联未建立）

---

### 场景 9：ConcludeError（conclude_error.pcap）

构造 pcap，覆盖服务端拒绝关闭会话的场景。

```bash
mkdir -p "$OUT/s9" && rm -rf "$OUT/s9"/*
suricata -r "$PCAP_DIR/conclude_error.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s9" 2>/dev/null
cat "$OUT/s9/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期核心事务

```json
{ "direction": "request",  "pdu_type": "conclude_request" }
{ "direction": "response", "pdu_type": "conclude_error" }
```

共 4 条（含 Initiate 2 条）。`conclude_error` 表示服务端拒绝了客户端的关闭请求。

---

### 场景 10：CancelRequest + CancelResponse（cancel_response.pcap）

构造 pcap，覆盖取消请求/响应的完整交互。

```bash
mkdir -p "$OUT/s10" && rm -rf "$OUT/s10"/*
suricata -r "$PCAP_DIR/cancel_response.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s10" 2>/dev/null
cat "$OUT/s10/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期核心事务

```json
{ "direction": "request",  "pdu_type": "cancel_request",  "invoke_id": 42 }
{ "direction": "response", "pdu_type": "cancel_response", "invoke_id": 42 }
```

共 6 条（含 Initiate 2 条 + Conclude 2 条）。`invoke_id = 42` 双向一致。

---

### 场景 11：Read Response 含实际数据（read_response_with_data.pcap）

构造 pcap，覆盖 Read 响应包含 floating-point 数据值的场景。

```bash
mkdir -p "$OUT/s11" && rm -rf "$OUT/s11"/*
suricata -r "$PCAP_DIR/read_response_with_data.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s11" 2>/dev/null
cat "$OUT/s11/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期核心事务

请求：
```json
{ "direction": "request", "pdu_type": "confirmed_request", "invoke_id": 1, "service": "read", "variables": [
  { "scope": "domain_specific", "domain": "TestDomain", "item": "MMXU1$MX$TotW$mag$f" },
  { "scope": "domain_specific", "domain": "TestDomain", "item": "MMXU1$MX$TotVAr$mag$f" }
] }
```

响应：
```json
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 1, "service": "read", "result_count": 2, "results": [
  { "success": true, "data_type": "integer", "value": "35510702080" },
  { "success": true, "data_type": "integer", "value": "37648988406" }
] }
```

共 6 条（含 Initiate 2 条 + Conclude 2 条）。

- `variables` 含 2 个 domain_specific 变量，深度解析正确
- `result_count = 2`，每条含 `data_type` 和具体数值
- 注意：该 pcap 由 `tools/generate_test_pcaps.py` 构造，使用的 tag byte `0x85` 在标签修正后对应 MMS Data `[5] integer`（非 floating-point）。如需测试 floating-point，应使用 tag byte `0x87`（[7]）重新生成 pcap
- 对比场景 1 的空结果集，验证了非空 Read 响应的深度解析能力

---

### 场景 12：GetNameList 完整响应（get_name_list_full_response.pcap）

构造 pcap，覆盖 domain_specific 作用域的 GetNameList 请求，以及含 identifiers 和 more_follows 的完整响应。

```bash
mkdir -p "$OUT/s12" && rm -rf "$OUT/s12"/*
suricata -r "$PCAP_DIR/get_name_list_full_response.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s12" 2>/dev/null
cat "$OUT/s12/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期核心事务

请求：
```json
{ "direction": "request", "pdu_type": "confirmed_request", "invoke_id": 10, "service": "get_name_list", "object_class": "named_variable", "object_scope": "domain_specific", "domain": "TestDomain" }
```

响应：
```json
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 10, "service": "get_name_list", "identifiers": ["MMXU1$MX$TotW", "MMXU1$MX$TotVAr", "MMXU1$MX$Hz"], "more_follows": true }
```

共 6 条（含 Initiate 2 条 + Conclude 2 条）。

- 对比场景 3 的 vmd_specific，本场景验证了 `object_scope = "domain_specific"` + `domain` 字段
- 响应含 `identifiers` 列表和 `more_follows = true`（分页标记），对比场景 3 的 `service: "unknown"` 空响应

---

## 3. 已知正常现象

| 现象 | 说明 |
|------|------|
| 响应中 `service = "unknown"` | 部分 pcap 的 ConfirmedResponse 仅含 invokeID，无 service body，解析器容错记录为 `unknown` |
| `mms-confirmedRequestPDU.pcap` 出现 malformed=1 | pcap 数据质量问题，Wireshark 也无法解析该帧 |

---

## 4. EVE JSON 字段参考

来源：`rust/src/iec61850mms/logger.rs`

### 顶层结构

```json
{ "iec61850_mms": { "direction": "request", "pdu_type": "...", ... } }
```

### 通用字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `direction` | string | `"request"`（to_server）或 `"response"`（to_client） |
| `pdu_type` | string | `confirmed_request`、`confirmed_response`、`confirmed_error`、`initiate_request`、`initiate_response`、`initiate_error`、`conclude_request`、`conclude_response`、`conclude_error`、`cancel_request`、`cancel_response`、`cancel_error`、`reject`、`unconfirmed` |
| `invoke_id` | uint | Confirmed 类 PDU 的事务 ID（Initiate/Conclude 无此字段） |
| `service` | string | `read`、`write`、`get_name_list`、`get_variable_access_attributes`、`get_named_variable_list_attributes`、`unknown` 等 |

### 各服务专有字段

| 服务 | 方向 | 字段 |
|------|------|------|
| Read | request | `variables[]` — 每项含 `scope`、`domain`（可选）、`item` |
| Read | response | `result_count`、`results[]` — 每项含 `success`、`data_type`（可选）、`value`（可选） |
| Write | request | `variables[]`（同 Read） |
| GetNameList | request | `object_class`、`object_scope`、`domain`（可选）、`continue_after`（可选） |
| GetNameList | response | `identifiers[]`、`more_follows` |
| GetVariableAccessAttributes | request | `variable` — 含 `scope`、`domain`（可选）、`item` |
| GetVariableAccessAttributes | response | `mms_deletable`、`type_description` |
| GetNamedVariableListAttributes | request | `object_name` — 含 `scope`、`domain`（可选）、`item` |
| GetNamedVariableListAttributes | response | `mms_deletable`、`variable_count`、`variables[]` |
| Initiate | request/response | `local_detail`、`max_serv_outstanding_calling`、`max_serv_outstanding_called`、`data_structure_nesting_level`、`version_number`、`supported_services`（hex） |
