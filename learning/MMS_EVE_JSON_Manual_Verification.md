# MMS 协议解析 EVE JSON 手动验证指南

本文档指导程序员通过 Linux 命令行手动运行 Suricata 解析 pcap 文件，检查 `eve.json` 中的实际输出，逐场景验证 IEC 61850 MMS 协议解析是否正确。

> 与 `IEC61850_MMS_Parser_Test_Guide.md`（自动化测试脚本）定位不同，本文档面向**动手验证**，每个场景均包含：执行命令 → 预期 eve.json 输出 → 关键字段解读。

---

## 1. 前置条件

### 1.1 编译安装 Suricata

```bash
cd /home/work/suricata-8.0.4-study && make -j$(nproc) && make install
```

确认自定义构建的 suricata 已安装到 PATH 中，或使用完整路径：

```bash
suricata --build-info | grep -i "iec61850\|version"
```

### 1.2 设置环境变量

每次打开新终端时执行：

```bash
export SURICATA_DIR="/home/work/suricata-8.0.4-study"
export PCAP_DIR="/home/work/iec61850_protocol_parser/pcaps_file"
export SURICATA_YAML="$SURICATA_DIR/suricata.yaml"
export OUT="/tmp/mms_manual_verify"
```

### 1.3 pcap 文件位置

| 类别 | 文件 | 说明 |
|------|------|------|
| IEC 61850 完整栈 | `$PCAP_DIR/iec61850_read.pcap` | 带 Session/Presentation 层 |
| IEC 61850 完整栈 | `$PCAP_DIR/iec61850_write.pcap` | 带 Session/Presentation 层 |
| IEC 61850 完整栈 | `$PCAP_DIR/iec61850_get_name_list.pcap` | 带 Session/Presentation 层 |
| IEC 61850 完整栈 | `$PCAP_DIR/iec61850_get_variable_access_attributes.pcap` | 带 Session/Presentation 层 |
| IEC 61850 完整栈 | `$PCAP_DIR/iec61850_release.pcap` | 含 Conclude |
| MMS 直连 | `$PCAP_DIR/mms-readRequest.pcap` | 无 Session/Presentation 层 |

---

## 2. 基本操作流程

### 2.1 运行 Suricata 解析 pcap

```bash
mkdir -p "$OUT/read" && rm -rf "$OUT/read"/*
suricata -r "$PCAP_DIR/iec61850_read.pcap" \
    -S /dev/null -c "$SURICATA_YAML" -l "$OUT/read" 2>/dev/null
echo "done"
```

- `-S /dev/null`：不加载告警规则（仅需应用层日志）
- `-c "$SURICATA_YAML"`：使用项目自带配置
- `-l "$OUT/read"`：指定日志输出目录

### 2.2 用 jq 提取 MMS 事件

```bash
cat "$OUT/read/eve.json" | jq 'select(.event_type == "iec61850_mms") | .iec61850_mms'
```

### 2.3 用 grep 快速过滤

```bash
grep '"event_type":"iec61850_mms"' "$OUT/read/eve.json" | python3 -m json.tool
```

### 2.4 辅助函数（可选）

将以下函数加入当前 shell，后续场景可直接调用：

```bash
run_pcap() {
    local name="$1" pcap="$2"
    mkdir -p "$OUT/$name" && rm -rf "$OUT/$name"/*
    suricata -r "$pcap" -S /dev/null -c "$SURICATA_YAML" -l "$OUT/$name" 2>/dev/null
    echo "done: $name"
}

show_mms() {
    local name="$1"
    python3 -c "
import json, sys
with open('$OUT/$name/eve.json') as f:
    for line in f:
        ev = json.loads(line)
        if ev.get('event_type') == 'iec61850_mms':
            print(json.dumps(ev['iec61850_mms'], indent=2, ensure_ascii=False))
"
}
```

---

## 3. 分场景验证

### 场景 1：Read 请求/响应

**pcap**: `iec61850_read.pcap`（IEC 61850 完整栈，含 Session/Presentation 层）

#### 执行

```bash
run_pcap read "$PCAP_DIR/iec61850_read.pcap"
show_mms read
```

#### 预期 eve.json 输出

事务 1 — Initiate 握手响应：
```json
{
  "response": {
    "pdu_type": "initiate_response"
  }
}
```

事务 2 — Read 请求/响应对：
```json
{
  "request": {
    "pdu_type": "confirmed_request",
    "invoke_id": 0,
    "service": "read",
    "variables": [
      { "scope": "domain_specific", "domain": "...", "item": "..." }
    ]
  },
  "response": {
    "pdu_type": "confirmed_response",
    "invoke_id": 0,
    "service": "read",
    "result_count": 1,
    "results": [
      { "success": true, "data_type": "...", "value": "..." }
    ]
  }
}
```

事务 3 — Conclude：
```json
{
  "request": {
    "pdu_type": "conclude_request"
  }
}
```

事务 4 — Initiate 请求（TCP 反向）：
```json
{
  "request": {
    "pdu_type": "initiate_request"
  },
  "response": {
    "pdu_type": "confirmed_response",
    "invoke_id": 0,
    "service": "unknown"
  }
}
```

#### 关键字段解读

| 字段 | 含义 |
|------|------|
| `request.service = "read"` | 解析器正确识别 Read 服务类型 |
| `request.variables[]` | 深度解析出被读取的变量列表（scope/domain/item） |
| `response.service = "read"` | 响应侧也识别为 Read |
| `response.results[]` | 深度解析出读取结果（success、data_type、value） |
| `response.service = "unknown"` | 最小化 PDU（仅含 invokeID），非错误 |

---

### 场景 2：Write 请求/响应

**pcap**: `iec61850_write.pcap`

#### 执行

```bash
run_pcap write "$PCAP_DIR/iec61850_write.pcap"
show_mms write
```

#### 预期 eve.json 输出

事务 2（核心）：
```json
{
  "request": {
    "pdu_type": "confirmed_request",
    "invoke_id": 0,
    "service": "write",
    "variables": [
      { "scope": "...", "domain": "...", "item": "..." }
    ]
  },
  "response": {
    "pdu_type": "confirmed_response",
    "invoke_id": 0,
    "service": "unknown"
  }
}
```

#### 关键字段解读

| 字段 | 含义 |
|------|------|
| `request.service = "write"` | 正确识别 Write 服务 |
| `request.variables[]` | 深度解析出被写入的变量列表 |
| `response.service = "unknown"` | 该 pcap 的 Response 为最小化 PDU，容错处理 |

---

### 场景 3：GetNameList 深度解析

**pcap**: `iec61850_get_name_list.pcap`

#### 执行

```bash
run_pcap gnl "$PCAP_DIR/iec61850_get_name_list.pcap"
show_mms gnl
```

#### 预期 eve.json 输出

事务 2（核心）：
```json
{
  "request": {
    "pdu_type": "confirmed_request",
    "invoke_id": 0,
    "service": "get_name_list",
    "object_class": "named_variable",
    "object_scope": "vmd_specific"
  },
  "response": {
    "pdu_type": "confirmed_response",
    "invoke_id": 0,
    "service": "unknown"
  }
}
```

#### 关键字段解读

| 字段 | 含义 |
|------|------|
| `object_class = "named_variable"` | 查询类型 = 列出变量（objectClass=0） |
| `object_scope = "vmd_specific"` | 查询范围 = VMD 级别 |
| `domain`（缺失） | vmdSpecific 不需要 domain 限定 |
| `continue_after`（缺失） | 非分页请求 |

> GetNameList 三种查询类型：`domain`（列出逻辑设备）、`named_variable`（列出变量）、`named_variable_list`（列出数据集）。本 pcap 仅覆盖 `named_variable`，其余两种通过 Rust 单元测试覆盖。

---

### 场景 4：GetVariableAccessAttributes 深度解析

**pcap**: `iec61850_get_variable_access_attributes.pcap`

#### 执行

```bash
run_pcap gva "$PCAP_DIR/iec61850_get_variable_access_attributes.pcap"
show_mms gva
```

#### 预期 eve.json 输出

事务 2（核心）：
```json
{
  "request": {
    "pdu_type": "confirmed_request",
    "invoke_id": 0,
    "service": "get_variable_access_attributes",
    "variable": {
      "scope": "vmd_specific",
      "item": "mu"
    }
  },
  "response": {
    "pdu_type": "confirmed_response",
    "invoke_id": 0,
    "service": "unknown"
  }
}
```

#### 关键字段解读

| 字段 | 含义 |
|------|------|
| `variable.scope = "vmd_specific"` | ObjectName 变体为 VMD 级别 |
| `variable.item = "mu"` | 查询的变量名为 "mu" |
| `variable.domain`（缺失） | vmd_specific 不含 domain |

---

### 场景 5：GetNamedVariableListAttributes 深度解析

**pcap**: `session_254_172.20.4.111_38914.pcap`

> 此 pcap 来自真实抓包，位于 `/tmp/test_large_12/` 目录。如果文件不存在，可跳过本场景。

#### 执行

```bash
GNVLA_PCAP="/tmp/test_large_12/session_254_172.20.4.111_38914.pcap"
if [ -f "$GNVLA_PCAP" ]; then
    run_pcap gnvla "$GNVLA_PCAP"
    show_mms gnvla
else
    echo "SKIP: pcap not found at $GNVLA_PCAP"
fi
```

#### 预期 eve.json 输出

Request 侧：
```json
{
  "request": {
    "pdu_type": "confirmed_request",
    "invoke_id": 1503081,
    "service": "get_named_variable_list_attributes",
    "object_name": {
      "scope": "domain_specific",
      "domain": "PQMR_1000_941",
      "item": "LLN0$dsMmtr1"
    }
  }
}
```

Response 侧：
```json
{
  "response": {
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
      { "scope": "domain_specific", "domain": "PQMR_1000_941", "item": "MMTR2$MX$SupWh" }
    ]
  }
}
```

> 以上仅展示前 5 条，实际共 20 个变量（MMTR1~MMTR5 × SupWh/SupVArh/DmdWh/DmdVArh）。

#### 关键字段解读

| 字段 | 含义 |
|------|------|
| `object_name.item = "LLN0$dsMmtr1"` | 请求查询的数据集名称 |
| `mms_deletable = false` | 数据集不可删除（IED 配置定义） |
| `variable_count = 20` | 数据集包含 20 个变量 |
| `variables[]` | 每个变量的 scope/domain/item 三元组 |

---

### 场景 6：MMS 直连格式

**pcap**: `mms-readRequest.pcap`（无 Session/Presentation 层）

#### 执行

```bash
run_pcap mms_direct "$PCAP_DIR/mms-readRequest.pcap"
show_mms mms_direct
```

#### 预期 eve.json 输出

```json
{}
```
（空事务 — COTP 连接建立）

```json
{
  "request": {
    "pdu_type": "initiate_request"
  }
}
```

```json
{
  "request": {
    "pdu_type": "confirmed_request",
    "invoke_id": 1,
    "service": "read",
    "variables": [
      { "scope": "domain_specific", "domain": "S1C1", "item": "LLN0$DC$NamPlt$vendor" }
    ]
  }
}
```

#### 关键字段解读

| 字段 | 含义 |
|------|------|
| 无 Session/Presentation 嵌套 | 解析器自动检测 MMS 直连格式（`is_direct_mms_pdu`） |
| 空事务 `{}` | COTP 连接阶段，无 MMS 数据 |
| `variables[0].domain = "S1C1"` | 直连格式下变量引用也能正确深度解析 |

---

### 场景 7：Initiate/Conclude 会话生命周期

本场景复用 `iec61850_get_name_list.pcap`，聚焦 MMS 会话生命周期。

#### 执行

```bash
run_pcap lifecycle "$PCAP_DIR/iec61850_get_name_list.pcap"
python3 -c "
import json
with open('$OUT/lifecycle/eve.json') as f:
    for line in f:
        ev = json.loads(line)
        if ev.get('event_type') == 'iec61850_mms':
            mms = ev['iec61850_mms']
            parts = []
            for side in ('request', 'response'):
                if side in mms:
                    pdu = mms[side].get('pdu_type', '?')
                    svc = mms[side].get('service', '')
                    s = f'{side}: {pdu}'
                    if svc:
                        s += f' ({svc})'
                    parts.append(s)
            print(' | '.join(parts) if parts else '(empty - COTP)')
"
```

#### 预期输出

```
response: initiate_response
request: confirmed_request (get_name_list) | response: confirmed_response (unknown)
request: conclude_request
request: initiate_request | response: confirmed_response (unknown)
```

#### 关键字段解读

完整的 MMS 会话生命周期：

```
initiate_request  →  initiate_response     (MMS 关联建立)
       ↓
confirmed_request →  confirmed_response    (业务数据交换)
       ↓
conclude_request  →  conclude_response     (MMS 关联释放)
```

> 本 pcap 中 `initiate_request` 和 `initiate_response` 分属不同事务（TCP 双向各有一次关联建立），因此输出中 request 和 response 混合出现。

---

## 4. 常用 jq 过滤技巧

### 4.1 提取特定服务类型

```bash
# 提取所有 Read 请求
cat "$OUT/read/eve.json" | jq '
  select(.event_type == "iec61850_mms")
  | .iec61850_mms
  | select(.request.service == "read")
  | .request'

# 提取所有包含 variables 数组的请求
cat "$OUT/read/eve.json" | jq '
  select(.event_type == "iec61850_mms")
  | .iec61850_mms.request
  | select(.variables != null)'
```

### 4.2 统计事件数

```bash
# 统计 MMS 事件总数
grep -c '"event_type":"iec61850_mms"' "$OUT/read/eve.json"

# 按 pdu_type 分组统计
cat "$OUT/read/eve.json" | jq -r '
  select(.event_type == "iec61850_mms")
  | .iec61850_mms
  | [.request.pdu_type, .response.pdu_type]
  | map(select(. != null))[]' | sort | uniq -c | sort -rn
```

### 4.3 检查 malformed

```bash
# 检查是否存在 malformed 异常事件
grep -c 'malformed_data' "$OUT/read/eve.json" && echo "有异常" || echo "无异常"

# 查看 malformed 事件详情
cat "$OUT/read/eve.json" | jq 'select(.event_type == "anomaly")'
```

### 4.4 按 invoke_id 关联请求/响应

```bash
cat "$OUT/read/eve.json" | jq '
  select(.event_type == "iec61850_mms")
  | .iec61850_mms
  | select(.request.invoke_id != null)
  | { invoke_id: .request.invoke_id,
      req_service: .request.service,
      resp_service: .response.service }'
```

### 4.5 提取深度解析字段

```bash
# 提取 GetNameList 的 object_class
cat "$OUT/gnl/eve.json" | jq '
  select(.event_type == "iec61850_mms")
  | .iec61850_mms.request
  | select(.object_class != null)
  | { service, object_class, object_scope, domain, continue_after }'

# 提取 GetVariableAccessAttributes 的 variable 对象
cat "$OUT/gva/eve.json" | jq '
  select(.event_type == "iec61850_mms")
  | .iec61850_mms.request
  | select(.variable != null)
  | .variable'
```

---

## 5. 判断标准

### 5.1 什么算解析成功

| 条件 | 验证方法 |
|------|---------|
| **eve.json 中存在 `event_type: "iec61850_mms"` 事件** | `grep -c '"event_type":"iec61850_mms"' eve.json` 输出 > 0 |
| **malformed_data 为 0** | `grep -c 'malformed_data' eve.json` 输出 0 |
| **service 字段非空** | 请求侧的 `service` 字段为具体服务名（非 `unknown`） |
| **pdu_type 正确** | `confirmed_request`、`confirmed_response`、`initiate_request`、`initiate_response`、`conclude_request` 等 |
| **深度字段存在**（对应服务） | Read 有 `variables[]`/`results[]`，GetNameList 有 `object_class`，等 |

### 5.2 常见异常及排查

#### 异常 1：eve.json 中无 `iec61850_mms` 事件

```bash
# 检查 app_proto 识别情况
cat "$OUT/xxx/eve.json" | jq 'select(.event_type == "flow") | .app_proto'
```

如果输出 `"failed"`：
- 确认使用的是项目编译的 Suricata（非系统自带的）
- 确认 `suricata.yaml` 中启用了 iec61850-mms 协议检测
- 检查 pcap 是否使用标准端口 102

#### 异常 2：出现 malformed_data

```bash
# 查看具体是哪个事务出了问题
cat "$OUT/xxx/eve.json" | jq 'select(.event_type == "anomaly") | { tx_id, anomaly }'
```

已知的合理 malformed：
- `mms-confirmedRequestPDU.pcap` 的 malformed=1：pcap 数据质量问题，服务端帧格式异常，Wireshark 也无法解析

#### 异常 3：response 中 service="unknown"

这是**正常现象**。部分测试 pcap 的 ConfirmedResponse 仅包含 invokeID，不含 service response body（最小化 PDU）。解析器对此进行了容错处理，记录为 `unknown` 而非报 malformed。

#### 异常 4：空事务 `{}`

COTP 连接建立阶段（CR/CC 帧）不包含 MMS 数据，解析器创建空事务记录连接事件。这是正常行为。

---

## 6. EVE JSON 字段参考

完整的 `iec61850_mms` 对象字段列表（来源：`rust/src/iec61850mms/logger.rs`）：

### 顶层结构

```json
{
  "iec61850_mms": {
    "request": { ... },
    "response": { ... }
  }
}
```

### 通用字段（所有 PDU 类型）

| 字段 | 类型 | 说明 |
|------|------|------|
| `pdu_type` | string | PDU 类型：`confirmed_request`、`confirmed_response`、`initiate_request`、`initiate_response`、`conclude_request`、`conclude_response`、`cancel_request`、`cancel_response` |
| `invoke_id` | uint | 事务 ID（Initiate/Conclude 无此字段） |
| `service` | string | 服务名称：`read`、`write`、`get_name_list`、`get_variable_access_attributes`、`get_named_variable_list_attributes`、`unknown` 等 |

### Read 专有字段

**Request**:
| 字段 | 类型 | 说明 |
|------|------|------|
| `variables[]` | array | 被读取的变量列表 |
| `variables[].scope` | string | `vmd_specific`、`domain_specific`、`aa_specific` |
| `variables[].domain` | string | 域名（仅 domain_specific） |
| `variables[].item` | string | 变量名 |

**Response**:
| 字段 | 类型 | 说明 |
|------|------|------|
| `result_count` | uint | 结果数量 |
| `results[]` | array | 读取结果列表 |
| `results[].success` | bool | 是否成功 |
| `results[].data_type` | string | 数据类型 |
| `results[].value` | string | 数据值 |

### Write 专有字段

**Request**: 同 Read 的 `variables[]`。

### GetNameList 专有字段

**Request**:
| 字段 | 类型 | 说明 |
|------|------|------|
| `object_class` | string | `domain`、`named_variable`、`named_variable_list` |
| `object_scope` | string | `vmd_specific`、`domain_specific`、`aa_specific` |
| `domain` | string | 域名（仅 domain_specific） |
| `continue_after` | string | 分页续传标识 |

**Response**:
| 字段 | 类型 | 说明 |
|------|------|------|
| `identifiers[]` | array[string] | 名称列表（上限 64 条） |
| `more_follows` | bool | 是否有后续分页 |

### GetVariableAccessAttributes 专有字段

**Request**:
| 字段 | 类型 | 说明 |
|------|------|------|
| `variable.scope` | string | ObjectName 的 scope |
| `variable.domain` | string | 域名 |
| `variable.item` | string | 变量名 |

**Response**:
| 字段 | 类型 | 说明 |
|------|------|------|
| `mms_deletable` | bool | 是否可删除 |
| `type_description` | string | 类型描述 |

### GetNamedVariableListAttributes 专有字段

**Request**:
| 字段 | 类型 | 说明 |
|------|------|------|
| `object_name.scope` | string | ObjectName 的 scope |
| `object_name.domain` | string | 域名 |
| `object_name.item` | string | 数据集名 |

**Response**:
| 字段 | 类型 | 说明 |
|------|------|------|
| `mms_deletable` | bool | 是否可删除 |
| `variable_count` | uint | 变量数量 |
| `variables[]` | array | 变量列表（上限 32 条） |
| `variables[].scope` | string | 变量 scope |
| `variables[].domain` | string | 变量域名 |
| `variables[].item` | string | 变量名 |

### Initiate 专有字段

**Request/Response 共用**:
| 字段 | 类型 | 说明 |
|------|------|------|
| `local_detail` | uint | 本地最大 PDU 大小 |
| `max_serv_outstanding` | uint | 最大并发服务数 |
| `data_structure_nesting_level` | uint | 数据结构嵌套深度 |
| `version_number` | uint | 协议版本号 |
| `supported_services` | string | 支持服务位图（hex 编码） |
