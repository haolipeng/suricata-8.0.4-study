# IEC 61850 MMS PDU 深度解析能力说明

本文档描述当前 Suricata IEC 61850 MMS 解析器对各 PDU 类型的解析深度，涵盖已解析的字段、ASN.1 标签、数据结构及日志输出。

> 源码位置：`rust/src/iec61850mms/mms_pdu.rs`（解析）、`rust/src/iec61850mms/logger.rs`（日志）

---

## 1. Initiate-Request / Initiate-Response

### ASN.1 结构

```
Initiate-RequestPDU ::= SEQUENCE {
    localDetailCalling              [0] IMPLICIT Integer32 OPTIONAL,
    proposedMaxServOutstanding      [1] IMPLICIT Integer16,
    proposedDataStructureNesting    [2] IMPLICIT Integer8 OPTIONAL,
    initRequestDetail               [3] IMPLICIT SEQUENCE {
        proposedVersionNumber       [0] IMPLICIT Integer16,
        proposedParameterCBB        [1] IMPLICIT ParameterSupportOptions,
        servicesSupportedCalling    [2] IMPLICIT ServiceSupportOptions
    }
}
```

Initiate-ResponsePDU 结构相同，字段名为 negotiated 版本。

### BER 标签映射

| 层级 | 字段 | 标签 | 编码 |
|------|------|------|------|
| 外层 | localDetail | `0x80` | context[0], primitive |
| 外层 | maxServOutstanding | `0x81` | context[1], primitive |
| 外层 | dataStructureNestingLevel | `0x82` | context[2], primitive |
| 外层 | initDetail 容器 | `0xA3` | context[3], constructed |
| 内层 | versionNumber | `0x80` | context[0], primitive |
| 内层 | parameterCBB | `0x81` | context[1], primitive（跳过） |
| 内层 | supportedServices | `0x82` | context[2], primitive |

### 解析字段（`MmsInitDetail`）

| 字段 | 类型 | 说明 |
|------|------|------|
| `local_detail` | `Option<u32>` | 最大 PDU 大小（字节） |
| `max_serv_outstanding` | `Option<u32>` | 最大并发未完成请求数 |
| `data_structure_nesting_level` | `Option<u32>` | 数据结构最大嵌套层级 |
| `version_number` | `Option<u32>` | MMS 协议版本号 |
| `supported_services` | `Option<Vec<u8>>` | 服务支持位图（BIT STRING 原始字节） |

**解析深度：2 层嵌套**（外层 SEQUENCE → initDetail 内层 SEQUENCE）

### 日志输出示例

```json
{
  "pdu_type": "initiate_request",
  "local_detail": 65000,
  "max_serv_outstanding": 5,
  "data_structure_nesting_level": 4,
  "version_number": 1,
  "supported_services": "ee1c00"
}
```

### 未解析内容

- `parameterCBB`（内层 `0x81`）：跳过不解析

---

## 2. GetNameList Confirmed-Request / Confirmed-Response

### ASN.1 结构

```
GetNameList-Request ::= SEQUENCE {
    objectClass   [0] ObjectClass,
    objectScope   [1] ObjectScope,
    continueAfter [2] IMPLICIT Identifier OPTIONAL
}

ObjectClass ::= CHOICE {
    basicObjectClass [0] IMPLICIT INTEGER {0..11}
}

ObjectScope ::= CHOICE {
    vmdSpecific    [0] IMPLICIT NULL,
    domainSpecific [1] IMPLICIT Identifier,
    aaSpecific     [2] IMPLICIT NULL
}

GetNameList-Response ::= SEQUENCE {
    listOfIdentifier [0] IMPLICIT SEQUENCE OF Identifier,
    moreFollows      [1] IMPLICIT BOOLEAN DEFAULT TRUE
}
```

### BER 标签映射

**Request：**

| 层级 | 字段 | 标签 |
|------|------|------|
| 1 | objectClass 容器 | `0xA0` |
| 2 | basicObjectClass | `0x80`（INTEGER） |
| 1 | objectScope 容器 | `0xA1` |
| 2 | vmdSpecific | `0x80`（NULL） |
| 2 | domainSpecific | `0x81`（VisibleString） |
| 2 | aaSpecific | `0x82`（NULL） |
| 1 | continueAfter | `0x82`（VisibleString） |

**Response：**

| 层级 | 字段 | 标签 |
|------|------|------|
| 1 | listOfIdentifier 容器 | `0xA0` |
| 2 | 每个 Identifier | `0x1A`（VisibleString） |
| 1 | moreFollows | `0x81`（BOOLEAN） |

### 解析字段

**Request（`MmsGetNameListRequest`）：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `object_class` | `Option<String>` | 对象类别（见下方映射表） |
| `object_scope` | `Option<String>` | 查询范围 |
| `domain_id` | `Option<String>` | 域名（仅 domainSpecific 时有值） |
| `continue_after` | `Option<String>` | 分页续传标识符 |

**objectClass 值映射：**

| 值 | 字符串 | 含义 |
|----|--------|------|
| 0 | `named_variable` | 命名变量 |
| 1 | `scattered_access` | 分散访问 |
| 2 | `named_variable_list` | 命名变量列表（数据集） |
| 3 | `named_type` | 命名类型 |
| 4 | `semaphore` | 信号量 |
| 5 | `event_condition` | 事件条件 |
| 6 | `event_action` | 事件动作 |
| 7 | `event_enrollment` | 事件注册 |
| 8 | `journal` | 日志 |
| 9 | `domain` | 域（逻辑设备） |
| 10 | `program_invocation` | 程序调用 |
| 11 | `operator_station` | 操作员站 |

**Response（`MmsGetNameListResponse`）：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `identifiers` | `Vec<String>` | 返回的名称列表（**上限 64 条**） |
| `more_follows` | `bool` | 是否有后续数据（默认 true） |

**解析深度：3 层嵌套**（service → objectClass/objectScope 容器 → 内部值）

### 日志输出示例

Request：
```json
{
  "pdu_type": "confirmed_request",
  "service": "get_name_list",
  "object_class": "named_variable",
  "object_scope": "domain_specific",
  "domain": "LD1",
  "continue_after": "Var100"
}
```

Response：
```json
{
  "pdu_type": "confirmed_response",
  "service": "get_name_list",
  "identifiers": ["LLN0$Mod", "LLN0$Beh", "MMXU1$MX$TotW"],
  "more_follows": true
}
```

### 容限保护

- identifiers 列表截断上限：**64 条**

---

## 3. GetVariableAccessAttributes Confirmed-Request / Confirmed-Response

### ASN.1 结构

```
GetVariableAccessAttributes-Request ::= ObjectName

ObjectName ::= CHOICE {
    vmdSpecific    [0] IMPLICIT Identifier,
    domainSpecific [1] IMPLICIT SEQUENCE { domainId Identifier, itemId Identifier },
    aaSpecific     [2] IMPLICIT Identifier
}
```

### BER 标签映射

| 层级 | 字段 | 标签 |
|------|------|------|
| 1 | name 容器 | `0xA0` |
| 2 | vmdSpecific | `0x80`（VisibleString） |
| 2 | domainSpecific 容器 | `0xA1`（constructed） |
| 3 | domainId | `0x1A`（VisibleString） |
| 3 | itemId | `0x1A`（VisibleString） |
| 2 | aaSpecific | `0x82`（VisibleString） |

### 解析字段（`MmsGetVarAccessAttrRequest`）

| 字段 | 类型 | 说明 |
|------|------|------|
| `object_name` | `Option<ObjectNameRef>` | 请求查询的变量名 |

**`ObjectNameRef` 枚举三种变体：**

| 变体 | 字段 | 说明 |
|------|------|------|
| `VmdSpecific(String)` | item | VMD 范围的变量名 |
| `DomainSpecific { domain_id, item_id }` | domain + item | 域限定变量名 |
| `AaSpecific(String)` | item | AA 范围的变量名 |

**解析深度：2~3 层嵌套**（name 容器 → ObjectName CHOICE → domainSpecific 时 SEQUENCE 内两个字符串）

### 日志输出示例

```json
{
  "pdu_type": "confirmed_request",
  "service": "get_variable_access_attributes",
  "variable": {
    "scope": "domain_specific",
    "domain": "LD1",
    "item": "LLN0$Mod"
  }
}
```

### Response 解析

**已实现。** 解析字段（`MmsGetVarAccessAttrResponse`）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `mms_deletable` | `bool` | 是否可被 MMS 删除 |
| `type_description` | `Option<String>` | 顶层类型名（如 "structure"、"boolean"、"integer" 等） |

TypeDescription tag 映射：`[1]`=array, `[2]`=structure, `[3]`=boolean, `[4]`=bit-string, `[5]`=integer, `[6]`=unsigned, `[7]`=floating-point, `[9]`=octet-string, `[10]`=visible-string, `[11]`=generalized-time, `[12]`=binary-time, `[13]`=bcd, `[15]`=obj-id, `[16]`=mms-string, `[17]`=utc-time（注：`[0]` 为 typeName 引用，`[8]` 保留未实现）

日志输出示例：
```json
{
  "pdu_type": "confirmed_response",
  "service": "get_variable_access_attributes",
  "mms_deletable": false,
  "type_description": "structure"
}
```

---

## 4. GetNamedVariableListAttributes Confirmed-Request / Confirmed-Response

### ASN.1 结构

```
GetNamedVariableListAttributes-Request ::= ObjectName

GetNamedVariableListAttributes-Response ::= SEQUENCE {
    mmsDeletable   [0] IMPLICIT BOOLEAN,
    listOfVariable [1] IMPLICIT SEQUENCE OF SEQUENCE {
        variableSpecification VariableSpecification,
        alternateAccess       [5] IMPLICIT AlternateAccess OPTIONAL
    }
}
```

### BER 标签映射

**Request：** 同 ObjectName（见第 3 节）

**Response：**

| 层级 | 字段 | 标签 |
|------|------|------|
| 1 | mmsDeletable | `0x80`（BOOLEAN） |
| 1 | listOfVariable 容器 | `0xA1`（constructed） |
| 2 | 每个变量 SEQUENCE | `0x30` |
| 3 | name 容器 | `0xA0` |
| 4 | ObjectName（三种变体） | `0x80`/`0xA1`/`0x82` |

### 解析字段

**Request（`MmsGetNamedVarListAttrRequest`）：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `object_name` | `Option<ObjectNameRef>` | 查询的数据集名称 |

**Response（`MmsGetNamedVarListAttrResponse`）：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `mms_deletable` | `bool` | 该数据集是否可被 MMS 删除 |
| `variables` | `Vec<ObjectNameRef>` | 数据集包含的变量列表（**上限 32 条**） |

**解析深度：4 层嵌套**（listOfVariable → SEQUENCE → name → ObjectName → domainSpecific SEQUENCE）

### 日志输出示例

Request：
```json
{
  "pdu_type": "confirmed_request",
  "service": "get_named_variable_list_attributes",
  "object_name": {
    "scope": "domain_specific",
    "domain": "LD1",
    "item": "dataset01"
  }
}
```

Response：
```json
{
  "pdu_type": "confirmed_response",
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

### 容限保护

- variables 列表截断上限：**32 条**

---

## 5. Read Confirmed-Request / Confirmed-Response

### ASN.1 结构

```
Read-Request ::= SEQUENCE {
    specificationWithResult      [0] IMPLICIT BOOLEAN DEFAULT FALSE,
    variableAccessSpecification  [1] VariableAccessSpecification
}

VariableAccessSpecification ::= CHOICE {
    listOfVariable [0] IMPLICIT SEQUENCE OF SEQUENCE {
        variableSpecification VariableSpecification,
        alternateAccess       [5] IMPLICIT AlternateAccess OPTIONAL
    }
}

VariableSpecification ::= CHOICE {
    name [0] ObjectName,
    ...
}
```

### BER 标签映射

| 层级 | 字段 | 标签 |
|------|------|------|
| 1 | variableAccessSpecification 容器 | `0xA1`（constructed） |
| 2 | listOfVariable | `0xA0`（constructed） |
| 3 | 每个变量 SEQUENCE | `0x30` |
| 4 | name 容器 | `0xA0` |
| 5 | ObjectName（三种变体） | `0x80`/`0xA1`/`0x82` |

### 解析字段（`MmsReadRequest`）

| 字段 | 类型 | 说明 |
|------|------|------|
| `variable_specs` | `Vec<ObjectNameRef>` | 读取请求中引用的变量列表 |

每个 `ObjectNameRef` 可为 `VmdSpecific`、`DomainSpecific`、`AaSpecific` 三种变体。

**解析深度：4~5 层嵌套**（variableAccessSpec → listOfVariable → SEQUENCE → name → ObjectName → domainSpecific SEQUENCE）

### 日志输出示例

Request：
```json
{
  "pdu_type": "confirmed_request",
  "service": "read",
  "variables": [
    { "scope": "domain_specific", "domain": "LD1", "item": "LLN0$Mod" },
    { "scope": "domain_specific", "domain": "LD1", "item": "MMXU1$MX$TotW" }
  ]
}
```

### Response 解析

**已实现。** 解析字段（`MmsReadResponse`）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `results` | `Vec<MmsAccessResult>` | AccessResult 列表（**上限 64 条**） |

每个 `MmsAccessResult`：

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | `bool` | true=数据，false=错误 |
| `data_type` | `Option<String>` | 类型名（如 "boolean"、"integer"、"structure" 等） |
| `value` | `Option<String>` | 值的字符串表示（structure/array 不递归展开，标注 "N items"） |

Data tag 映射（`data_tag_name()` 函数实际支持）：`[1]`=array, `[2]`=structure, `[3]`=boolean, `[4]`=bit-string, `[5]`=integer, `[6]`=unsigned, `[7]`=floating-point, `[9]`=octet-string, `[10]`=visible-string, `[12]`=binary-time, `[16]`=mms-string, `[17]`=utc-time（注：`[8]` 保留，`[11]` generalized-time、`[13]` bcd、`[14]` boolean-array、`[15]` obj-id 在代码中暂未映射）

日志输出示例：
```json
{
  "pdu_type": "confirmed_response",
  "service": "read",
  "result_count": 2,
  "results": [
    { "success": true, "data_type": "integer", "value": "42" },
    { "success": true, "data_type": "structure", "value": "3 items" }
  ]
}
```

### 容限保护

- results 列表截断上限：**64 条**

---

## 6. Write Confirmed-Request

### ASN.1 结构

```
Write-Request ::= SEQUENCE {
    variableAccessSpecification VariableAccessSpecification,
    listOfData [0] IMPLICIT SEQUENCE OF Data
}
```

### 解析字段（`MmsWriteRequest`）

| 字段 | 类型 | 说明 |
|------|------|------|
| `variable_specs` | `Vec<ObjectNameRef>` | 写入请求中引用的变量列表 |

解析器仅提取 `variableAccessSpecification` 中的变量名引用列表，不解析 `listOfData` 中的写入数据值。

**解析深度：4~5 层嵌套**（与 Read Request 相同的变量访问规格路径）

### 日志输出示例

```json
{
  "pdu_type": "confirmed_request",
  "service": "write",
  "variables": [
    { "scope": "domain_specific", "domain": "LD1", "item": "CSWI1$Oper$ctlVal" }
  ]
}
```

### 未解析内容

- `listOfData`：写入数据值未提取（仅提取变量引用）

---

## 7. UnconfirmedPdu

### ASN.1 结构

```
Unconfirmed-PDU ::= SEQUENCE {
    unconfirmedService UnconfirmedService
}

UnconfirmedService ::= CHOICE {
    informationReport  [0] InformationReport,
    unsolicitedStatus  [1] UnsolicitedStatus,
    eventNotification  [2] EventNotification
}
```

### 解析字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `service` | `MmsUnconfirmedService` | 未确认服务类型 |

**`MmsUnconfirmedService` 枚举：**

| Tag | 值 | 说明 |
|-----|----|----|
| `[0]` | `InformationReport` | 信息报告（IED 主动上报数据） |
| `[1]` | `UnsolicitedStatus` | 主动状态上报 |
| `[2]` | `EventNotification` | 事件通知 |

**解析深度：1 层**（仅解析到服务类型标签，不深入解析服务内容）

### 日志输出示例

```json
{
  "pdu_type": "unconfirmed",
  "service": "information_report"
}
```

### 未解析内容

- InformationReport 内部的变量引用和数据值未深度解析
- UnsolicitedStatus / EventNotification 内部字段未解析

---

## 总览对比

| PDU 类型 | 方向 | 最大嵌套深度 | 解析字段数 | 列表上限 | Response 深度解析 |
|----------|------|-------------|-----------|---------|-----------------|
| Initiate | Req/Resp | 2 层 | 5 | — | ✅ 同 Request |
| GetNameList | Request | 3 层 | 4 | — | — |
| GetNameList | Response | 1 层 | 2 | 64 条 | ✅ |
| GetVarAccessAttr | Request | 3 层 | 1 (ObjectName) | — | — |
| GetVarAccessAttr | Response | 1 层 | 2 | — | ✅ |
| GetNamedVarListAttr | Request | 3 层 | 1 (ObjectName) | — | — |
| GetNamedVarListAttr | Response | 4 层 | 2 + 变量列表 | 32 条 | ✅ |
| Read | Request | 5 层 | 变量列表 | — | — |
| Read | Response | 1 层 | 结果列表 | 64 条 | ✅ |
| Write | Request | 5 层 | 变量列表 | — | — |
| Write | Response | — | — | — | ⚠️ 不解析数据值 |
| UnconfirmedPdu | — | 1 层 | 服务类型 | — | ⚠️ 仅识别服务类型 |
| ConfirmedError | — | 1 层 | invoke_id | — | — |
| RejectPdu | — | 1 层 | invoke_id (optional) | — | — |
| Cancel (Req/Resp) | — | 1 层 | invoke_id | — | — |
| CancelError / InitiateError / ConcludeReq/Resp/Error | — | 0 层 | 无字段 | — | — |

### 共享基础组件

所有涉及变量引用的 PDU 类型共用 `ObjectNameRef` 枚举和 `parse_object_name()` 函数，支持三种 ObjectName 变体的统一解析。DomainSpecific 变体通过 `parse_domain_specific_sequence()` 提取 `domainId` + `itemId` 二元组。

### 容限保护汇总

| 容限项 | 上限值 | 说明 |
|--------|--------|------|
| GetNameList 响应标识符数 | 64 条 | 防止超长列表占用过多内存 |
| GetNamedVarListAttr 响应变量数 | 32 条 | 数据集变量列表截断 |
| Read 响应结果数 | 64 条 | AccessResult 列表截断 |
| BER 递归解析深度 (`MAX_BER_DEPTH`) | 16 层 | 防止恶意嵌套导致栈溢出 |
| COTP 分片重组缓冲区 | 1 MB | 防止内存耗尽 |
| 流中最大事务数 | 256 个 | 限制单连接并发状态 |

### 确认服务识别范围

解析器可识别 **38 种确认服务类型**（`MmsConfirmedService` 枚举），其中 6 种有深度解析（GetNameList、Read、Write、GetVariableAccessAttributes、GetNamedVariableListAttributes + Initiate），其余服务仅记录服务类型名称和 invoke_id。

完整确认服务列表：Status、GetNameList、Identify、Rename、Read、Write、GetVariableAccessAttributes、GetCapabilityList、DefineNamedVariableList、GetNamedVariableListAttributes、DeleteNamedVariableList、TakeControl、RelinquishControl、InitiateDownloadSequence、DownloadSegment、TerminateDownloadSequence、InitiateUploadSequence、UploadSegment、TerminateUploadSequence、RequestDomainDownload、RequestDomainUpload、LoadDomainContent、StoreDomainContent、DeleteDomain、GetDomainAttributes、CreateProgramInvocation、DeleteProgramInvocation、Start、Stop、Resume、Reset、Kill、GetProgramInvocationAttributes、GetAlarmSummary、ObtainFile、FileOpen、FileRead、FileClose、FileRename、FileDelete、FileDirectory。
