# OSI 协议栈封装与 MMS 传输

本文档记录 IEC 61850 MMS 在 OSI 协议栈中的传输封装结构，涵盖从 TCP 到 MMS PDU 的完整解封装路径。

## 1. 协议栈总览

IEC 61850 MMS 使用完整的 OSI 上三层协议栈。**建链阶段与数据传输阶段的封装路径不同：**

```
┌──────────────────────────────────────────────────────────────┐
│ 阶段         │ 建链（Initiate）       │ 数据传输（Data）         │
├──────────────┼────────────────────────┼──────────────────────┤
│ 应用层       │ ACSE (ISO 8650-1)      │ MMS (ISO 9506)        │
│              │  └── MMS Initiate PDU  │                      │
├──────────────┼────────────────────────┼──────────────────────┤
│ 表示层       │ Presentation CP-type   │ Presentation          │
│              │ (ISO 8823)             │ fully-encoded-data   │
├──────────────┼────────────────────────┼──────────────────────┤
│ 会话层       │ Session CONNECT/ACCEPT │ Session GT + DT       │
│              │ (ISO 8327)             │ (ISO 8327)           │
├──────────────┼────────────────────────┼──────────────────────┤
│ 传输层       │ COTP (ISO 8073)        │ COTP (ISO 8073)       │
├──────────────┼────────────────────────┼──────────────────────┤
│ 适配层       │ TPKT (RFC 1006)        │ TPKT (RFC 1006)       │
├──────────────┼────────────────────────┼──────────────────────┤
│              │ TCP                    │ TCP                  │
└──────────────┴────────────────────────┴──────────────────────┘
```

关键区别：
- **建链阶段**：MMS Initiate PDU 被 ACSE（关联控制）包裹后再经 Presentation → Session
- **数据传输阶段**：MMS PDU 直接放在 Presentation 的 PDV-list 中，无 ACSE 封装

## 2. TPKT 层（RFC 1006）

### 帧格式

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    version    |   reserved    |          length               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     COTP payload ...                          |
```

| 字段 | 大小 | 值 | 说明 |
|------|------|----|------|
| version | 1 字节 | 固定 0x03 | 协议版本 |
| reserved | 1 字节 | 固定 0x00 | 保留字段 |
| length | 2 字节 | 大端 | 总长度（含 4 字节 TPKT 头） |

### 探测条件

用于协议识别（probe function）：
- version == 3
- reserved == 0
- length >= 7（最小：4 TPKT + 3 COTP DT）
- length < 65530

## 3. COTP 层（ISO 8073）

### PDU 类型

| 类型 | 代码（高 4 位） | Tag Byte 示例 | 说明 |
|------|:---:|:---:|------|
| CR (Connection Request) | 0xE | 0xE0 | 连接请求 |
| CC (Connection Confirm) | 0xD | 0xD0 | 连接确认 |
| DR (Disconnect Request) | 0x8 | 0x80 | 断连请求 |
| DT (Data Transfer) | 0xF | 0xF0 | 数据传输 |

类型判断取 tag byte 的高 4 位（`byte & 0xF0`），低 4 位含 CDT（信用值）等信息。

### DT 帧格式

```
┌──────────┬───────────┬──────────────┬────────────┐
│ length   │ pdu_type  │ nr_and_eot   │ payload... │
│ (1 byte) │ (1 byte)  │ (1 byte)     │            │
└──────────┴───────────┴──────────────┴────────────┘
```

| 字段 | 说明 |
|------|------|
| length | COTP 头部长度（不含 length 字段自身），DT 帧通常为 2 |
| pdu_type | 0xF0 |
| nr_and_eot | bit 7=EOT 标志，bit 6-0=TPDU 序号 |

**EOT（End of TSDU）标志**：
- `0x80`（EOT=1）：本帧是 TSDU 的最后一个分片，可以开始解析上层 PDU
- `0x00`（EOT=0）：后续还有分片，当前数据需要缓冲

### CR/CC/DR 帧

这些帧的 `length` 字段后续全部是 COTP 头部参数（源/目的 reference、选项等），解析时直接跳过 `length - 1` 字节即可到达帧末尾。这些帧通常不携带上层数据载荷。

### COTP 分片重组

当一个 MMS PDU 过大时，会被拆分为多个 COTP DT 帧：

```
DT(EOT=0, payload=part1) → 缓冲
DT(EOT=0, payload=part2) → 追加缓冲
DT(EOT=1, payload=part3) → 追加缓冲 → 拼接完整 PDU → 解析
```

实现要点：
- 请求方向（to_server）和响应方向（to_client）的缓冲区完全独立
- TCP gap 发生时必须清空对应方向的缓冲区（残留数据不可靠）
- 缓冲区应设置大小上限（防止恶意分片导致 OOM）

## 4. Session 层（ISO 8327-1）

### SPDU 类型

| 类型 | Tag Byte | 说明 |
|------|:---:|------|
| CONNECT (CN) | 0x0D | 会话连接请求 |
| ACCEPT (AC) | 0x0E | 会话连接确认 |
| GIVE TOKENS (GT) | 0x01 | 令牌传递 |
| DATA TRANSFER (DT) | 0x01 | 数据传输（紧跟 GT 后） |
| FINISH (FN) | 0x09 | 会话正常终止 |
| DISCONNECT (DN) | 0x0A | 会话断开 |

### 长度编码

Session 层有自己的长度编码规则，**不同于 BER**：

| 第一字节 | 含义 |
|----------|------|
| 0x00 - 0xFE | 单字节，直接表示长度（0-254） |
| 0xFF | 长格式：后续 2 字节大端表示长度 |

对比 BER 长度编码：

| BER | Session |
|-----|---------|
| 0x00-0x7F: 短格式 | 0x00-0xFE: 短格式 |
| 0x80: 不定长 | — |
| 0x81-0x84: 长格式（1-4 字节后续） | 0xFF: 长格式（2 字节后续） |

### 数据传输模式

MMS 数据传输使用 Give Tokens + Data Transfer 的组合模式：

```
┌──────────────┬──────────────┬──────────────────────┐
│ GT: 01 00    │ DT: 01 00    │ Presentation data... │
└──────────────┴──────────────┴──────────────────────┘
```

- Give Tokens SPDU：type=0x01, length=0x00（固定 2 字节）
- Data Transfer SPDU：type=0x01, length=0x00（固定 2 字节）
- 之后是 Presentation 层数据

### 连接阶段

Session CONNECT/ACCEPT SPDU 的 Presentation 层数据**不在 Session 头部之后**，而是**嵌套在 Session 参数列表的 User Data (0xC1) 参数内部**。

```
┌──────────────────────────────────────────────────────────────────┐
│ CN/AC: type(1) + length(1~3) + 参数列表                           │
│   ├── Connect Accept Item (05) : 协议选项、版本号                    │
│   ├── Session Requirement (14) : 功能单元协商                        │
│   ├── Calling Session Selector (33)                               │
│   ├── Called Session Selector (34)                                │
│   └── Session User Data (C1) : ← Presentation 层数据在这里         │
│         └── CP-type (0x31) → Presentation 层                      │
└──────────────────────────────────────────────────────────────────┘
```

Session 参数列表是 TLV 序列（type 1 字节 + length + value），需逐个遍历查找 `0xC1`。

> **常见错误**：将 Session SPDU 的 length 字段理解为"头部参数长度"，然后假设 Presentation 数据紧跟参数之后。实际上 length 覆盖了全部参数（包含 User Data），Presentation 数据在 `0xC1` 参数的 value 内部。

## 5. Presentation 层（ISO 8823）

Presentation 层在建链阶段和数据传输阶段使用**不同的封装格式**。

### 5.1 数据传输阶段：fully-encoded-data

数据传输阶段使用 `fully-encoded-data [APPLICATION 1]`（tag byte = `0x61`）封装 PDV-list，MMS PDU 直接在 context-id=3 的条目中：

```
fully-encoded-data [APPLICATION 1] (0x61)
  └── PDV-list: SEQUENCE (0x30)
        ├── presentation-context-identifier: INTEGER (0x02) = 3
        └── single-ASN1-type [0] (0xA0)
              └── MMS PDU data（直接是 Confirmed-Request/Response 等）
```

### 5.2 建链阶段：CP-type / CPA-type

建链阶段使用 `CP-type` (CONNECT) 或 `CPA-type` (ACCEPT)，外层标签为 SET (0x31)，结构更复杂：

```
CP-type / CPA-type: SET (0x31)
  ├── mode-selector [0] (0xA0)
  │     └── mode-value: INTEGER = 1 (normal-mode)
  └── normal-mode-parameters [2] (0xA2)
        ├── calling-presentation-selector [1] (0x81)
        ├── called-presentation-selector [2] (0x82)
        ├── presentation-context-definition-list [4] (0xA4)    ← 上下文协商
        │     ├── Context-list item: ctx-id=1, abstract-syntax=id-as-acse
        │     └── Context-list item: ctx-id=3, abstract-syntax=mms-abstract-syntax
        ├── presentation-requirements [8] (0x88)
        └── user-data: fully-encoded-data [APPLICATION 1] (0x61)
              └── PDV-list: SEQUENCE (0x30)
                    ├── context-id = 1 (ACSE)     ← 建链阶段走这里
                    └── single-ASN1-type [0] (0xA0)
                          └── ACSE AARQ/AARE PDU   ← 不是直接的 MMS PDU！
```

> **关键区别**：数据传输阶段的 PDV-list 中 context-id=3 直接包含 MMS PDU；建链阶段的 PDV-list 中 context-id=1 包含 ACSE PDU，MMS Initiate PDU 嵌套在 ACSE 的 user-information 中。

### presentation-context-id

PDV-list 中每个条目携带一个 `presentation-context-id`（INTEGER），标识数据属于哪个应用上下文：

- **context-id = 1**：ACSE 上下文（建链阶段使用）
- **context-id = 3**：MMS 上下文（数据传输阶段使用）

这个 ID 在 Session CONNECT/ACCEPT 阶段通过 Presentation 层的 Context Definition List 协商确定。严格实现应该解析协商结果，但实际中硬编码 `3 || 1` 是常见的简化做法。

### 解封装流程（数据传输阶段）

```
Presentation data
  │
  ├─ 验证顶层标签 == 0x61 (APPLICATION 1)
  │
  ├─ 遍历 PDV-list 条目 (SEQUENCE 0x30)
  │    │
  │    ├─ 读取 context-id (INTEGER 0x02)
  │    │
  │    ├─ 如果 context-id == 3 或 1:
  │    │    ├─ 读取 single-ASN1-type wrapper (tag 0xA0)
  │    │    └─ 内部就是 MMS PDU 数据
  │    │
  │    └─ 否则跳过该条目
  │
  └─ 未找到 MMS context → 错误
```

## 6. ACSE 层（ISO 8650-1）— 仅建链阶段

ACSE（Association Control Service Element）仅在建链阶段使用，负责建立和释放应用关联。MMS Initiate PDU 嵌套在 ACSE 的 user-information 字段中。

### AARQ / AARE 结构

```
AARQ [APPLICATION 0] (0x60)  — 关联请求（对应 MMS Initiate-Request）
AARE [APPLICATION 1] (0x61)  — 关联响应（对应 MMS Initiate-Response）
  ├── protocol-version [0] (0x80)
  ├── aSO-context-name [1] (0xA1): OID = 1.0.9506.2.3 (MMS)
  ├── ... (其他可选字段)
  └── user-information [30] IMPLICIT (0xBE)
        └── EXTERNAL: SEQUENCE (0x28)
              ├── direct-reference: INTEGER = 3 (MMS context)
              └── single-ASN1-type [0] (0xA0)
                    └── MMS Initiate-Request/Response PDU  ← 最终目标
```

### 建链阶段完整解封装路径

```
Session CONNECT/ACCEPT SPDU
  → 遍历参数列表，找到 Session User Data (0xC1)
    → Presentation CP-type SET (0x31)
      → normal-mode-parameters [2] (0xA2)
        → user-data: fully-encoded-data (0x61)
          → PDV-list: context-id=1
            → single-ASN1-type [0] (0xA0)
              → ACSE AARQ [APPLICATION 0] (0x60) / AARE (0x61)
                → user-information [30] (0xBE)
                  → EXTERNAL (0x28)
                    → single-ASN1-type [0] (0xA0)
                      → MMS Initiate-Request / Initiate-Response PDU
```

> **嵌套深度**：从 COTP payload 到 MMS Initiate PDU 共经过 **8 层**解封装。这是 OSI 协议栈的固有开销，也是 IEC 61850 MMS 解析器实现难度的主要来源。

## 7. 完整解封装示例

### 7.1 数据传输阶段示例

一个 MMS Conclude-Request 通过 Give Tokens + Data Transfer 模式传输：

```hex
03 00 00 16          TPKT: version=3, length=22
02 F0 80             COTP DT: length=2, type=0xF0, EOT=1
01 00                Session Give Tokens
01 00                Session Data Transfer
61 09                Presentation fully-encoded-data, length=9
  30 07              PDV-list SEQUENCE, length=7
    02 01 03         INTEGER context-id=3 (MMS)
    A0 02            [0] single-ASN1-type wrapper, length=2
      AB 00          MMS Conclude-Request (tag [11], empty)
```

解析顺序：
1. TPKT: 提取 22 字节帧（含头部 4 字节）
2. COTP: DT 帧，EOT=1，提取 15 字节载荷
3. Session: 跳过 GT(2) + DT(2) = 4 字节
4. Presentation: 0x61 → PDV-list → context-id=3 → wrapper 0xA0
5. MMS: tag_byte=0xAB → tag_num=11 → ConcludeRequest

### 7.2 建链阶段示例

MMS Initiate-Request 经 Session CONNECT → Presentation CP-type → ACSE AARQ 传输（摘自 mms.pcap 第 7 包）：

```hex
03 00 00 A7          TPKT: version=3, length=167
02 F0 80             COTP DT: length=2, type=0xF0, EOT=1
0D 9E                Session CONNECT, length=158
  05 06 ...          Session 参数: Connect Accept Item, Requirement 等
  C1 88              Session User Data (type=0xC1, length=136)
    31 81 85           Presentation CP-type SET, length=133
      A0 03 ...          mode-selector: normal-mode (1)
      A2 7E              normal-mode-parameters, length=126
        81 04 ...          calling-presentation-selector
        82 04 ...          called-presentation-selector
        A4 23              context-definition-list
          30 0F ...          ctx-id=1: id-as-acse (ACSE 上下文)
          30 10 ...          ctx-id=3: mms-abstract-syntax (MMS 上下文)
        88 02 06 00        presentation-requirements
        61 47              user-data: fully-encoded-data, length=71
          30 45              PDV-list SEQUENCE
            02 01 01           context-id=1 (ACSE)
            A0 40              single-ASN1-type wrapper
              60 3E              ACSE AARQ [APPLICATION 0], length=62
                80 02 07 80          protocol-version
                A1 07 ...            aSO-context-name = 1.0.9506.2.3 (MMS)
                BE 2F                user-information, length=47
                  28 2D                EXTERNAL SEQUENCE
                    02 01 03             direct-reference = 3
                    A0 28                single-ASN1-type wrapper, length=40
                      A8 26              ★ MMS Initiate-Request [8], length=38
                        80 03 00 FA 00     localDetailCalling = 64000
                        81 01 0A           maxServOutstandingCalling = 10
                        82 01 0A           maxServOutstandingCalled = 10
                        83 01 05           dataStructureNestingLevel = 5
                        A4 16              initRequestDetail
                          80 01 01           versionNumber = 1
                          81 03 ...          parameterCBB
                          82 0C ...          servicesSupportedCalling
```

解析顺序：
1. TPKT → COTP DT(EOT=1) → 160 字节 COTP payload
2. Session: CONNECT(0x0D) → 遍历参数找 User Data(0xC1) → 136 字节
3. Presentation: CP-type(0x31) → normal-mode(0xA2) → user-data(0x61) → PDV-list
4. PDV-list: context-id=1 → single-ASN1-type(0xA0) → ACSE AARQ(0x60)
5. ACSE: user-information(0xBE) → EXTERNAL(0x28) → single-ASN1-type(0xA0)
6. MMS: Initiate-Request(0xA8) → 解析协商参数

## 8. 连接状态机

MMS 会话从建立到关闭的完整流程：

```
           COTP CR         COTP CC         MMS Init-Req     MMS Init-Resp
  Idle ──────────→ CotpPending ──→ CotpEstablished ──→ AwaitInitResponse ──→ MmsAssociated
                                                                                │
                                                        MMS Data (循环) ←───────┤
                                                                                │
                                                        MMS Conclude-Req ──→ Concluding
                                                                                │
                                                        MMS Conclude-Resp ──→ Closed

  任意状态 ──── COTP DR ──→ Closed
```

直连兼容模式允许从 Idle 直接发送 MMS Init-Req（跳过 COTP 握手）。

## 参考

- RFC 1006: ISO Transport over TCP
- ISO 8073: OSI Connection-Oriented Transport Protocol (COTP)
- ISO 8327-1: OSI Session Protocol
- ISO 8823: OSI Presentation Protocol (Connection-Oriented)
- ISO 8650-1: OSI Association Control Service Element (ACSE)
- IEC 61850-8-1: 通信网络和系统的通信映射
