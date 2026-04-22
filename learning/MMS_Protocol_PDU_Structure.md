# MMS 协议 PDU 结构（ISO 9506-2）

本文档记录 IEC 61850 MMS（Manufacturing Message Specification）的 PDU 结构和数据类型定义，重点记录在解析器开发中容易出错的标签编号映射。

## 1. 顶层 MMS-PDU CHOICE

MMS PDU 是一个 ASN.1 CHOICE 类型，使用 context-specific 标签：

```asn1
MMS-PDU ::= CHOICE {
    confirmed-RequestPDU      [0] IMPLICIT Confirmed-RequestPDU,
    confirmed-ResponsePDU     [1] IMPLICIT Confirmed-ResponsePDU,
    confirmed-ErrorPDU        [2] IMPLICIT Confirmed-ErrorPDU,
    unconfirmed-PDU           [3] IMPLICIT Unconfirmed-PDU,
    rejectPDU                 [4] IMPLICIT RejectPDU,
    cancel-RequestPDU         [5] IMPLICIT INTEGER,
    cancel-ResponsePDU        [6] IMPLICIT INTEGER,
    cancel-ErrorPDU           [7] IMPLICIT Cancel-ErrorPDU,
    initiate-RequestPDU       [8] IMPLICIT Initiate-RequestPDU,
    initiate-ResponsePDU      [9] IMPLICIT Initiate-ResponsePDU,
    initiate-ErrorPDU         [10] IMPLICIT Initiate-ErrorPDU,
    conclude-RequestPDU       [11] IMPLICIT ConcludeRequestPDU,
    conclude-ResponsePDU      [12] IMPLICIT ConcludeResponsePDU,
    conclude-ErrorPDU         [13] IMPLICIT Conclude-ErrorPDU,
}
```

BER 编码示例：
- `[0]` Confirmed-Request (constructed) → tag_byte = `0xA0`
- `[8]` Initiate-Request (constructed) → tag_byte = `0xA8`
- `[11]` Conclude-Request (primitive NULL) → tag_byte = `0xAB`

## 2. Data CHOICE — 标签编号权威映射

Data 类型是 Read/Write 响应中携带的实际数据值。**这是解析器中最容易出错的映射表。**

### ASN.1 定义（ISO 9506-2）

```asn1
Data ::= CHOICE {
    -- [0] reserved for AccessResult failure
    array              [1] IMPLICIT SEQUENCE OF Data,
    structure          [2] IMPLICIT SEQUENCE OF Data,
    boolean            [3] IMPLICIT BOOLEAN,
    bit-string         [4] IMPLICIT BIT STRING,
    integer            [5] IMPLICIT INTEGER,
    unsigned           [6] IMPLICIT INTEGER,
    floating-point     [7] IMPLICIT FloatingPoint,
    -- [8] reserved
    octet-string       [9] IMPLICIT OCTET STRING,
    visible-string     [10] IMPLICIT VisibleString,
    -- [11] generalized-time (可选，部分实现不支持)
    binary-time        [12] IMPLICIT TimeOfDay,
    -- [13] bcd (可选)
    -- [14] boolean-array (可选)
    -- [15] obj-id (可选)
    mms-string         [16] IMPLICIT UTF8String,
    utc-time           [17] IMPLICIT UtcTime,
}
```

### BER Tag Byte 对照表

此表经 libiec61850 v1.6 源码（`mms_access_result.c`）逐行验证：

| Tag Number | Tag Byte (P) | Tag Byte (C) | 类型名 | libiec61850 枚举 | 值编码 |
|:---:|:---:|:---:|---|---|---|
| [0] | 0x80 | — | failure (DataAccessError) | MMS_DATA_ACCESS_ERROR | INTEGER |
| [1] | — | **0xA1** | array | MMS_ARRAY | SEQUENCE OF Data（递归） |
| [2] | — | **0xA2** | structure | MMS_STRUCTURE | SEQUENCE OF Data（递归） |
| [3] | **0x83** | — | boolean | MMS_BOOLEAN | 0x00=false, 非0=true |
| [4] | **0x84** | — | bit-string | MMS_BIT_STRING | 首字节=padding bits, 后续=bit data |
| [5] | **0x85** | — | integer | MMS_INTEGER | 有符号大端整数 |
| [6] | **0x86** | — | unsigned | MMS_UNSIGNED | 无符号大端整数 |
| [7] | **0x87** | — | floating-point | MMS_FLOAT | 见下方 FloatingPoint 编码 |
| [8] | — | — | *(reserved)* | — | — |
| [9] | **0x89** | — | octet-string | MMS_OCTET_STRING | 原始字节 |
| [10] | **0x8A** | — | visible-string | MMS_VISIBLE_STRING | ASCII 字符串 |
| [12] | **0x8C** | — | binary-time | MMS_BINARY_TIME | 4 或 6 字节时间 |
| [16] | **0x90** | — | mms-string | MMS_STRING | UTF-8 字符串 |
| [17] | **0x91** | — | utc-time | MMS_UTC_TIME | 8 字节（4s + 3μs + 1quality） |

> **注意**：tag [1] array 和 [2] structure 是 constructed 类型，tag byte 的 bit 6=1，所以分别是 0xA1 和 0xA2，而不是 0x81 和 0x82。

### 常见错误：标签号偏移

由于 `[0]` 被 failure 占用，Data CHOICE 的实际数据类型从 `[1]` 开始。手工编写映射表时容易误将 `[1]=array` 写成 `1="boolean"`，导致整个表偏移 2 位。

libiec61850 的内部枚举（`MMS_ARRAY=0, MMS_STRUCTURE=1, MMS_BOOLEAN=2, ...`）是 **C 枚举序号**（从 0 开始），与 ASN.1 tag number 不同。不能直接用枚举值作为 tag 映射。

## 3. FloatingPoint 编码

MMS 的 FloatingPoint 不是裸 IEEE 754，而是封装了一个额外的指数宽度字节：

```
FloatingPoint ::= OCTET STRING
  -- byte 0: exponent width (单精度=8, 双精度=11)
  -- bytes 1-N: IEEE 754 浮点数
```

| 格式 | 总长度 | 指数宽度 | IEEE 754 部分 |
|------|--------|----------|---------------|
| 单精度 | 5 字节 | 8 | 4 字节 float |
| 双精度 | 9 字节 | 11 | 8 字节 double |

解析时需要跳过第一个字节（exponent width），从 `content[1..]` 开始读取 IEEE 754 字节。

## 4. TypeSpecification CHOICE

用于 GetVariableAccessAttributes 响应中描述变量的类型结构。

```asn1
TypeSpecification ::= CHOICE {
    typeName           [0] ObjectName,
    array              [1] IMPLICIT SEQUENCE { ... },
    structure          [2] IMPLICIT SEQUENCE { ... },
    boolean            [3] IMPLICIT NULL,
    bit-string         [4] IMPLICIT INTEGER,
    integer            [5] IMPLICIT INTEGER,
    unsigned           [6] IMPLICIT INTEGER,
    floating-point     [7] IMPLICIT SEQUENCE { formatWidth, exponentWidth },
    -- [8] reserved (real)
    octet-string       [9] IMPLICIT INTEGER,
    visible-string     [10] IMPLICIT INTEGER,
    generalized-time   [11] IMPLICIT NULL,
    binary-time        [12] IMPLICIT BOOLEAN,
    bcd                [13] IMPLICIT INTEGER,
    -- [14] reserved
    obj-id             [15] IMPLICIT NULL,
    mms-string         [16] IMPLICIT INTEGER,
    utc-time           [17] IMPLICIT NULL,
}
```

tag 编号与 Data CHOICE 基本一致（都从 [1] 开始），但多了 `[0] typeName` 选项。

## 5. ConfirmedServiceRequest/Response CHOICE

标签号对应 ISO 9506-2 中各服务的 CHOICE 编号：

| Tag | 服务名 | 说明 |
|:---:|--------|------|
| 0 | Status | 设备状态查询 |
| 1 | GetNameList | 获取名称列表 |
| 2 | Identify | 设备标识 |
| 4 | Read | 读变量 |
| 5 | Write | 写变量 |
| 6 | GetVariableAccessAttributes | 获取变量访问属性 |
| 12 | GetNamedVariableListAttributes | 获取命名变量列表属性 |
| 72-78 | File 系列 | 文件操作 |

完整映射见代码 `mms_types.rs` 中的 `MmsConfirmedService::from_request_tag()`。

## 6. AccessResult 结构

Read 响应中每个变量的结果：

```asn1
AccessResult ::= CHOICE {
    failure  [0] IMPLICIT DataAccessError,   -- tag_byte = 0x80
    success  Data                            -- tag_byte 取决于具体 Data 类型
}
```

`failure` 使用 tag `[0]`（0x80），与 Data CHOICE 不冲突（Data 从 `[1]` 开始）。

## 参考

- ISO 9506-1: MMS 服务定义
- ISO 9506-2: MMS 协议规范（ASN.1 模块）
- libiec61850 v1.6 源码: `src/mms/iso_mms/server/mms_access_result.c`
- libiec61850 v1.6 源码: `src/mms/iso_mms/asn1c/TypeSpecification.c`
- OpenIEC61850 ASN.1 模块: `mms.asn`
