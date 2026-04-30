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
{ "direction": "request",  "pdu_type": "initiate_request",  "local_detail": 64000, "max_serv_outstanding_calling": 10, "max_serv_outstanding_called": 10, "data_structure_nesting_level": 5, "version_number": 1, "supported_services": "a00000000000000000e110" }
{ "direction": "response", "pdu_type": "initiate_response", "local_detail": 32000, "max_serv_outstanding_calling": 10, "max_serv_outstanding_called": 8, "data_structure_nesting_level": 5, "version_number": 1, "supported_services": "ee0800000400000001ed18" }
{ "direction": "request",  "pdu_type": "confirmed_request",  "invoke_id": 303731, "service": "get_variable_access_attributes", "variable": { "scope": "domain_specific", "domain": "AA1E1Q01FP2LD0", "item": "LLN0$BR$rcb_B02" } }
{ "direction": "response", "pdu_type": "confirmed_error",    "invoke_id": 303731, "error_class": "access", "error_code": "object-non-existent" }
{ "direction": "request",  "pdu_type": "confirmed_request",  "invoke_id": 303732, "service": "read", "variables": [{ "scope": "domain_specific", "domain": "AA1E1Q01FP2LD0", "item": "LLN0$BR$rcb_B02" }] }
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 303732, "service": "read", "result_count": 0, "results": [] }
{ "direction": "request",  "pdu_type": "conclude_request" }
{ "direction": "response", "pdu_type": "conclude_response" }
```

#### 验证要点

- Initiate 请求/响应包含完整协商参数（`local_detail`、`version_number`、`supported_services` 等）
- `supported_services` 为纯位图 hex，不含 BIT STRING 的 unused bits 前缀字节
- GVAA 服务正确识别，`variable` 含 scope/domain/item
- 服务端返回 `confirmed_error`，含 `error_class` 和 `error_code` 名称
- Read 响应深度解析出 `result_count` 和 `results`
- 无空事务（COTP CR/CC 不创建事务）

---

### 场景 2：Write（iec61850_write.pcap）

```bash
mkdir -p "$OUT/s2" && rm -rf "$OUT/s2"/*
suricata -r "$PCAP_DIR/iec61850_write.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s2" 2>/dev/null
cat "$OUT/s2/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期输出（共 6 条）

```json
{ "direction": "request",  "pdu_type": "initiate_request",  "local_detail": 30000, "max_serv_outstanding_calling": 1000, "max_serv_outstanding_called": 1000, "data_structure_nesting_level": 5, "version_number": 1, "supported_services": "ffffffffffffffffffffff00" }
{ "direction": "response", "pdu_type": "initiate_response" }
{ "direction": "request",  "pdu_type": "confirmed_request",  "invoke_id": 0, "service": "write" }
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 0, "service": "unknown" }
{ "direction": "request",  "pdu_type": "conclude_request" }
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 0, "service": "unknown" }
```

该 pcap 的 Write 请求不含可解析的变量规范，故无 `variables` 字段。Initiate 响应为最小化 PDU，无协商参数。最后一条为 `confirmed_response`（pcap 原始数据如此，非标准 Conclude 响应）。

---

### 场景 3：GetNameList（iec61850_get_name_list.pcap）

```bash
mkdir -p "$OUT/s3" && rm -rf "$OUT/s3"/*
suricata -r "$PCAP_DIR/iec61850_get_name_list.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s3" 2>/dev/null
cat "$OUT/s3/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期输出（共 6 条）

```json
{ "direction": "request",  "pdu_type": "initiate_request",  "local_detail": 30000, "max_serv_outstanding_calling": 1000, "max_serv_outstanding_called": 1000, "data_structure_nesting_level": 5, "version_number": 1, "supported_services": "ffffffffffffffffffffff00" }
{ "direction": "response", "pdu_type": "initiate_response" }
{ "direction": "request",  "pdu_type": "confirmed_request",  "invoke_id": 0, "service": "get_name_list", "object_class": "named_variable", "object_scope": "vmd_specific" }
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 0, "service": "unknown" }
{ "direction": "request",  "pdu_type": "conclude_request" }
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 0, "service": "unknown" }
```

共 6 条。

- `object_class = "named_variable"` — 查询类型：列出变量
- `object_scope = "vmd_specific"` — VMD 级别，无 domain
- 本 pcap 仅覆盖 `named_variable`，`domain` 和 `named_variable_list` 两种类型通过 Rust 单元测试覆盖
- 最后一条为 `confirmed_response`（同场景 2）

---

### 场景 4：GetVariableAccessAttributes（iec61850_get_variable_access_attributes.pcap）

```bash
mkdir -p "$OUT/s4" && rm -rf "$OUT/s4"/*
suricata -r "$PCAP_DIR/iec61850_get_variable_access_attributes.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s4" 2>/dev/null
cat "$OUT/s4/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期输出（共 6 条）

```json
{ "direction": "request",  "pdu_type": "initiate_request",  "local_detail": 30000, "max_serv_outstanding_calling": 1000, "max_serv_outstanding_called": 1000, "data_structure_nesting_level": 5, "version_number": 1, "supported_services": "ffffffffffffffffffffff00" }
{ "direction": "response", "pdu_type": "initiate_response" }
{ "direction": "request",  "pdu_type": "confirmed_request",  "invoke_id": 0, "service": "get_variable_access_attributes", "variable": { "scope": "vmd_specific", "item": "mu" } }
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 0, "service": "unknown" }
{ "direction": "request",  "pdu_type": "conclude_request" }
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 0, "service": "unknown" }
```

共 6 条。`variable.scope = "vmd_specific"` 故无 domain 字段。最后一条为 `confirmed_response`（同场景 2）。

---

### 场景 5：GetNamedVariableListAttributes（iec61850_get_named_variableList_attributes.pcap）

含 Session/Presentation 层，覆盖 GetNamedVariableListAttributes + GetVariableAccessAttributes。pcap 来自真实抓包。

> **注意**：该 pcap 文件版本为 4.2，部分旧版 Suricata 可能无法直接读取，需先用 `editcap -F pcap` 转换。

```bash
mkdir -p "$OUT/s5" && rm -rf "$OUT/s5"/*
editcap -F pcap "$PCAP_DIR/iec61850_get_named_variableList_attributes.pcap" /tmp/gnvla_fixed.pcap 2>/dev/null
suricata -r /tmp/gnvla_fixed.pcap -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s5" 2>/dev/null
cat "$OUT/s5/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期输出（共 46 条）

Initiate 请求/响应（2 条）：
```json
{ "direction": "request",  "pdu_type": "initiate_request",  "local_detail": 32000, "max_serv_outstanding_calling": 10, "max_serv_outstanding_called": 10, "data_structure_nesting_level": 5, "version_number": 1, "supported_services": "6e1c00000002000040ed10" }
{ "direction": "response", "pdu_type": "initiate_response", "local_detail": 30000, "max_serv_outstanding_calling": 1,  "max_serv_outstanding_called": 5,  "data_structure_nesting_level": 5, "version_number": 1, "supported_services": "ee1c00000000000000e518" }
```

GNVLA 请求：
```json
{ "direction": "request", "pdu_type": "confirmed_request", "invoke_id": 1503081, "service": "get_named_variable_list_attributes", "object_name": { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "LLN0$dsMmtr1" } }
```

GNVLA 响应（含 20 个变量的完整列表）：
```json
{
  "direction": "response",
  "pdu_type": "confirmed_response",
  "invoke_id": 1503081,
  "service": "get_named_variable_list_attributes",
  "mms_deletable": false,
  "variable_count": 20,
  "variables": [
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR1$MX$SupWh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR1$MX$SupVArh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR1$MX$DmdWh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR1$MX$DmdVArh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR2$MX$SupWh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR2$MX$SupVArh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR2$MX$DmdWh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR2$MX$DmdVArh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR3$MX$SupWh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR3$MX$SupVArh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR3$MX$DmdWh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR3$MX$DmdVArh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR4$MX$SupWh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR4$MX$SupVArh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR4$MX$DmdWh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR4$MX$DmdVArh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR5$MX$SupWh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR5$MX$SupVArh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR5$MX$DmdWh" },
    { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR5$MX$DmdVArh" }
  ]
}
```

后续 GVAA 请求/响应（40 条，invoke_id 1503082-1503101）：

对数据集中的每个变量逐一查询 GetVariableAccessAttributes，共 20 对请求/响应。示例（第 1 对）：
```json
{ "direction": "request",  "pdu_type": "confirmed_request",  "invoke_id": 1503082, "service": "get_variable_access_attributes", "variable": { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR1$MX$SupWh" } }
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 1503082, "service": "get_variable_access_attributes", "mms_deletable": false, "type_description": "structure" }
```

所有 20 对 GVAA 响应的 `type_description` 均为 `"structure"`。

Conclude（2 条）：
```json
{ "direction": "request",  "pdu_type": "conclude_request" }
{ "direction": "response", "pdu_type": "conclude_response" }
```

#### 验证要点

- GNVLA 请求正确解析 `object_name`（domain_specific + domain + item）
- GNVLA 响应完整提取 20 个变量（未触发 32 条截断上限）
- `mms_deletable = false` 正确解析
- 后续 20 对 GVAA 查询逐一解析了每个变量的类型属性
- Initiate 请求/响应含完整协商参数（双方 supported_services 不同）

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
{ "direction": "request", "pdu_type": "initiate_request", "local_detail": 31, "max_serv_outstanding_calling": 3, "max_serv_outstanding_called": 3, "data_structure_nesting_level": 2056, "version_number": 1, "supported_services": "ffffffffffffffffffffff" }
{ "direction": "request", "pdu_type": "confirmed_request", "invoke_id": 1, "service": "read", "variables": [{ "scope": "vmd_specific", "item": "$MSG$1$$" }] }
```

- Initiate 协商参数（`local_detail`、`max_serv_outstanding_calling/called`、`version_number`、`supported_services` 等）被深度解析
- `supported_services` 为纯位图 hex，不含 BIT STRING unused bits 前缀字节
- 无 COTP CR/CC 空事务

---

### 场景 7：UnconfirmedPDU — InformationReport（unconfirmed_information_report.pcap）

构造 pcap，覆盖 UnconfirmedPDU 的 InformationReport 服务（IEC 61850 实时数据上报）。

```bash
mkdir -p "$OUT/s7" && rm -rf "$OUT/s7"/*
suricata -r "$PCAP_DIR/unconfirmed_information_report.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s7" 2>/dev/null
cat "$OUT/s7/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期输出（共 5 条）

```json
{ "direction": "request",  "pdu_type": "initiate_request",  "local_detail": 1024, "max_serv_outstanding_calling": 5, "max_serv_outstanding_called": 5, "data_structure_nesting_level": 4 }
{ "direction": "response", "pdu_type": "initiate_response", "local_detail": 1024, "max_serv_outstanding_calling": 5, "max_serv_outstanding_called": 5, "data_structure_nesting_level": 4 }
{ "direction": "response", "pdu_type": "unconfirmed", "service": "information_report" }
{ "direction": "request",  "pdu_type": "conclude_request" }
{ "direction": "response", "pdu_type": "conclude_response" }
```

`pdu_type = "unconfirmed"` 正确识别非确认 PDU，`service = "information_report"` 正确识别服务类型。

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

- 客户端发起 Initiate（含协商参数），服务端返回 `initiate_error` 拒绝
- 无后续 MMS 数据交换（关联未建立）

---

### 场景 9：ConcludeError（conclude_error.pcap）

构造 pcap，覆盖服务端拒绝关闭会话的场景。

```bash
mkdir -p "$OUT/s9" && rm -rf "$OUT/s9"/*
suricata -r "$PCAP_DIR/conclude_error.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s9" 2>/dev/null
cat "$OUT/s9/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期输出（共 4 条）

```json
{ "direction": "request",  "pdu_type": "initiate_request",  "local_detail": 1024, "max_serv_outstanding_calling": 5, "max_serv_outstanding_called": 5, "data_structure_nesting_level": 4 }
{ "direction": "response", "pdu_type": "initiate_response", "local_detail": 1024, "max_serv_outstanding_calling": 5, "max_serv_outstanding_called": 5, "data_structure_nesting_level": 4 }
{ "direction": "request",  "pdu_type": "conclude_request" }
{ "direction": "response", "pdu_type": "conclude_error" }
```

`conclude_error` 表示服务端拒绝了客户端的关闭请求。

---

### 场景 10：CancelRequest + CancelResponse（cancel_response.pcap）

构造 pcap，覆盖取消请求/响应的完整交互。

```bash
mkdir -p "$OUT/s10" && rm -rf "$OUT/s10"/*
suricata -r "$PCAP_DIR/cancel_response.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s10" 2>/dev/null
cat "$OUT/s10/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期输出（共 6 条）

```json
{ "direction": "request",  "pdu_type": "initiate_request",  "local_detail": 1024, "max_serv_outstanding_calling": 5, "max_serv_outstanding_called": 5, "data_structure_nesting_level": 4 }
{ "direction": "response", "pdu_type": "initiate_response", "local_detail": 1024, "max_serv_outstanding_calling": 5, "max_serv_outstanding_called": 5, "data_structure_nesting_level": 4 }
{ "direction": "request",  "pdu_type": "cancel_request",  "invoke_id": 42 }
{ "direction": "response", "pdu_type": "cancel_response", "invoke_id": 42 }
{ "direction": "request",  "pdu_type": "conclude_request" }
{ "direction": "response", "pdu_type": "conclude_response" }
```

`invoke_id = 42` 双向一致。

---

### 场景 11：Read Response 含实际数据（read_response_with_data.pcap）

构造 pcap，覆盖 Read 响应包含 floating-point 数据值的场景。

```bash
mkdir -p "$OUT/s11" && rm -rf "$OUT/s11"/*
suricata -r "$PCAP_DIR/read_response_with_data.pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/s11" 2>/dev/null
cat "$OUT/s11/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

#### 预期输出（共 6 条）

请求：
```json
{ "direction": "request",  "pdu_type": "initiate_request",  "local_detail": 1024, "max_serv_outstanding_calling": 5, "max_serv_outstanding_called": 5, "data_structure_nesting_level": 4 }
{ "direction": "response", "pdu_type": "initiate_response", "local_detail": 1024, "max_serv_outstanding_calling": 5, "max_serv_outstanding_called": 5, "data_structure_nesting_level": 4 }
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
{ "direction": "request",  "pdu_type": "conclude_request" }
{ "direction": "response", "pdu_type": "conclude_response" }
```

共 6 条。

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

#### 预期输出（共 6 条）

请求：
```json
{ "direction": "request",  "pdu_type": "initiate_request",  "local_detail": 1024, "max_serv_outstanding_calling": 5, "max_serv_outstanding_called": 5, "data_structure_nesting_level": 4 }
{ "direction": "response", "pdu_type": "initiate_response", "local_detail": 1024, "max_serv_outstanding_calling": 5, "max_serv_outstanding_called": 5, "data_structure_nesting_level": 4 }
{ "direction": "request", "pdu_type": "confirmed_request", "invoke_id": 10, "service": "get_name_list", "object_class": "named_variable", "object_scope": "domain_specific", "domain": "TestDomain" }
```

响应：
```json
{ "direction": "response", "pdu_type": "confirmed_response", "invoke_id": 10, "service": "get_name_list", "identifiers": ["MMXU1$MX$TotW", "MMXU1$MX$TotVAr", "MMXU1$MX$Hz"], "more_follows": true }
{ "direction": "request",  "pdu_type": "conclude_request" }
{ "direction": "response", "pdu_type": "conclude_response" }
```

共 6 条。

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

---

## 5. 各 PDU 类型 MMS 字段详解

### 5.1 initiate_request

MMS 会话建立请求，客户端向服务端发起关联协商。

```json
{
  "direction": "request",
  "pdu_type": "initiate_request",
  "local_detail": 64000,
  "max_serv_outstanding_calling": 10,
  "max_serv_outstanding_called": 10,
  "data_structure_nesting_level": 5,
  "version_number": 1,
  "supported_services": "a00000000000000000e110"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `local_detail` | uint | 最大 PDU 大小（字节），客户端能接收的最大 MMS PDU 长度 |
| `max_serv_outstanding_calling` | uint | 主叫方（客户端）允许的最大并发未完成请求数 |
| `max_serv_outstanding_called` | uint | 被叫方（服务端）允许的最大并发未完成请求数 |
| `data_structure_nesting_level` | uint | 数据结构最大嵌套层级，限制 structure/array 递归深度 |
| `version_number` | uint | MMS 协议版本号（通常为 1） |
| `supported_services` | string | 服务支持位图（hex），每一位对应一种 MMS 服务是否支持 |

> 所有字段均为 `Option`，当 BER 编码中对应标签不存在时不输出。

### 5.2 initiate_response

MMS 会话建立响应，服务端返回协商后的参数。字段含义同 `initiate_request`，但值为服务端协商后的结果（可能小于或等于客户端提议值）。

```json
{
  "direction": "response",
  "pdu_type": "initiate_response",
  "local_detail": 32000,
  "max_serv_outstanding_calling": 10,
  "max_serv_outstanding_called": 8,
  "data_structure_nesting_level": 5,
  "version_number": 1,
  "supported_services": "ee0800000400000001ed18"
}
```

### 5.3 confirmed_request

确认请求 PDU，包含 `invoke_id` 和具体服务内容。不同服务类型携带的字段不同，见下方 5.7-5.9 各服务说明。

```json
{
  "direction": "request",
  "pdu_type": "confirmed_request",
  "invoke_id": 303731,
  "service": "get_variable_access_attributes",
  "variable": { "scope": "domain_specific", "domain": "LD1", "item": "LLN0$Mod" }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `invoke_id` | uint | 事务 ID，用于将请求与响应/错误配对 |
| `service` | string | 服务类型名，如 `read`、`write`、`get_name_list`、`get_variable_access_attributes`、`get_named_variable_list_attributes` 等 |
| *(服务专有字段)* | — | 见下方 5.7-5.9 |

### 5.4 confirmed_response

确认响应 PDU，与 `confirmed_request` 通过 `invoke_id` 配对。不同服务类型携带的字段不同。

```json
{
  "direction": "response",
  "pdu_type": "confirmed_response",
  "invoke_id": 303732,
  "service": "read",
  "result_count": 2,
  "results": [
    { "success": true, "data_type": "integer", "value": "42" },
    { "success": true, "data_type": "structure", "value": "3 items" }
  ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `invoke_id` | uint | 事务 ID，与对应请求的 `invoke_id` 一致 |
| `service` | string | 服务类型名，部分最小化响应无法识别服务类型时为 `unknown` |
| *(服务专有字段)* | — | 见下方 5.7-5.9 |

### 5.5 confirmed_error

确认错误 PDU，表示服务端拒绝了某个确认请求。包含错误类别和具体错误码。

```json
{
  "direction": "response",
  "pdu_type": "confirmed_error",
  "invoke_id": 303731,
  "error_class": "access",
  "error_code": "object-non-existent"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `invoke_id` | uint | 事务 ID，标识被拒绝的请求 |
| `error_class` | string | 错误类别，13 种取值见下表 |
| `error_code` | string | 具体错误码名称，各类别下含义不同；未知码回退为数字字符串 |

**error_class 取值：**

| error_class | 说明 | 常见 error_code 示例 |
|-------------|------|---------------------|
| `vmd-state` | VMD 状态错误 | `vmd-state-conflict`、`vmd-operational-problem` |
| `application-reference` | 应用引用错误 | `connection-lost`、`application-reference-invalid` |
| `definition` | 定义错误 | `object-undefined`、`type-unsupported`、`object-exists` |
| `resource` | 资源错误 | `memory-unavailable`、`capability-unavailable` |
| `service` | 服务错误 | `object-state-conflict`、`pdu-size`、`continuation-invalid` |
| `service-preempt` | 服务抢占 | `timeout`、`deadlock` |
| `time-resolution` | 时间精度 | `unsupportable-time-resolution` |
| `access` | 访问错误 | `object-non-existent`、`object-access-denied`、`object-invalidated` |
| `initiate` | 初始化错误 | `version-incompatible`、`max-segment-insufficient` |
| `conclude` | 结束错误 | `further-communication-required` |
| `cancel` | 取消错误 | `invoke-id-unknown`、`cancel-not-possible` |
| `file` | 文件错误 | `file-non-existent`、`file-access-denied`、`filename-ambiguous` |
| `others` | 其他 | `other` |

> 注意：`error_class=access` 下的错误码与 Read 响应中 `AccessResult.failure` 的 `DataAccessError` 枚举是**不同的定义**，值与含义不能混用。

### 5.6 GetNameList 服务

**请求字段：**

```json
{
  "service": "get_name_list",
  "object_class": "named_variable",
  "object_scope": "domain_specific",
  "domain": "LD1",
  "continue_after": "Var100"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `service` | string | 解析结果：服务为 `"get_name_list"` |
| `object_class` | string | 查询的对象类别：`named_variable`、`scattered_access`、`named_variable_list`、`named_type`、`semaphore`、`event_condition`、`event_action`、`event_enrollment`、`journal`、`domain`、`program_invocation`、`operator_station` |
| `object_scope` | string | 查询范围：`vmd_specific`（全局）、`domain_specific`（域内）、`aa_specific`（关联内） |
| `domain` | string | 域名，仅 `object_scope = "domain_specific"` 时存在 |
| `continue_after` | string | 分页续传标识符，首次查询无此字段 |

**响应字段：**

```json
{
  "service": "get_name_list",
  "identifiers": ["MMXU1$MX$TotW", "MMXU1$MX$TotVAr", "MMXU1$MX$Hz"],
  "more_follows": true
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `service` | string | 解析结果：服务为 `"get_name_list"` |
| `identifiers` | string[] | 返回的名称列表（上限 64 条，超出截断） |
| `more_follows` | bool | `true` 表示还有后续数据需分页获取 |

### 5.7 GetVariableAccessAttributes 服务

**请求字段：**

```json
{
  "service": "get_variable_access_attributes",
  "variable": {
    "scope": "domain_specific",
    "domain": "LD1",
    "item": "LLN0$Mod"
  }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `service` | string | 解析结果：服务为 `"get_variable_access_attributes"` |
| `variable` | object | 查询的变量名引用 |
| `variable.scope` | string | 变量作用域：`vmd_specific`（全局）、`domain_specific`（域内）、`aa_specific`（关联内） |
| `variable.domain` | string | 域名，仅 `scope = "domain_specific"` 时存在 |
| `variable.item` | string | 变量名 |

**响应字段：**

```json
{
  "service": "get_variable_access_attributes",
  "mms_deletable": false,
  "type_description": "structure"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `service` | string | 解析结果：服务为 `"get_variable_access_attributes"` |
| `mms_deletable` | bool | 该变量是否可被 MMS DeleteVariableAccess 删除 |
| `type_description` | string | 变量的顶层类型名：`array`、`structure`、`boolean`、`bit-string`、`integer`、`unsigned`、`floating-point`、`octet-string`、`visible-string`、`generalized-time`、`binary-time`、`bcd`、`obj-id`、`mms-string`、`utc-time` |

### 5.8 GetNamedVariableListAttributes 服务

**请求字段：**

```json
{
  "service": "get_named_variable_list_attributes",
  "object_name": {
    "scope": "domain_specific",
    "domain": "LD1",
    "item": "dataset01"
  }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `service` | string | 解析结果：服务为 `"get_named_variable_list_attributes"` |
| `object_name` | object | 查询的数据集名称引用 |
| `object_name.scope` | string | 作用域：`vmd_specific`、`domain_specific`、`aa_specific` |
| `object_name.domain` | string | 域名，仅 `scope = "domain_specific"` 时存在 |
| `object_name.item` | string | 数据集名称 |

**响应字段：**

```json
{
  "service": "get_named_variable_list_attributes",
  "mms_deletable": false,
  "variable_count": 3,
  "variables": [
    { "scope": "domain_specific", "domain": "LD1", "item": "MMXU1$MX$TotW" },
    { "scope": "domain_specific", "domain": "LD1", "item": "MMXU1$MX$TotVAr" },
    { "scope": "domain_specific", "domain": "LD1", "item": "MMXU1$MX$Hz" }
  ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `service` | string | 解析结果：服务为 `"get_named_variable_list_attributes"` |
| `mms_deletable` | bool | 该数据集是否可被 MMS 删除 |
| `variable_count` | uint | 数据集中包含的变量数量 |
| `variables` | object[] | 数据集中的变量列表（上限 32 条，超出截断） |
| `variables[].scope` | string | 变量作用域：`vmd_specific`、`domain_specific`、`aa_specific` |
| `variables[].domain` | string | 域名，仅 `scope = "domain_specific"` 时存在 |
| `variables[].item` | string | 变量名 |

### 5.9 Read 服务

**请求字段：**

```json
{
  "service": "read",
  "variables": [
    { "scope": "domain_specific", "domain": "LD1", "item": "LLN0$Mod" },
    { "scope": "domain_specific", "domain": "LD1", "item": "MMXU1$MX$TotW" }
  ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `service` | string | 解析结果：服务为 `"read"` |
| `variables` | object[] | 读取请求中引用的变量列表 |
| `variables[].scope` | string | 变量作用域：`vmd_specific`（全局）、`domain_specific`（域内）、`aa_specific`（关联内） |
| `variables[].domain` | string | 域名，仅 `scope = "domain_specific"` 时存在 |
| `variables[].item` | string | 变量名（IEC 61850 中通常为 `$` 分隔的路径，如 `MMXU1$MX$TotW$mag$f`） |

**响应字段：**

```json
{
  "service": "read",
  "result_count": 2,
  "results": [
    { "success": true, "data_type": "integer", "value": "42" },
    { "success": true, "data_type": "floating-point", "value": "3.14" },
    { "success": true, "data_type": "structure", "value": "5 items" },
    { "success": false }
  ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `service` | string | 解析结果为： `"read"` |
| `result_count` | uint | 结果数量 |
| `results` | object[] | AccessResult 列表（上限 64 条，超出截断） |
| `results[].success` | bool | `true` 表示成功读取数据，`false` 表示该变量读取失败 |
| `results[].data_type` | string | 数据类型名（仅 `success=true` 时），取值：`array`、`structure`、`boolean`、`bit-string`、`integer`、`unsigned`、`floating-point`、`octet-string`、`visible-string`、`binary-time`、`mms-string`、`utc-time` |
| `results[].value` | string | 数据值的字符串表示（仅 `success=true` 时）。structure/array 不递归展开，显示为 `"N items"`；浮点数显示为十进制；整数显示为十进制；字符串原样输出；bit-string/binary-time/utc-time 显示为 hex |
