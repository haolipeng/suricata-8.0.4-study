# OSI 协议栈封装与 MMS 传输

本文档记录 IEC 61850 MMS 在 OSI 协议栈中的传输封装结构，涵盖从 TCP 到 MMS PDU 的完整解封装路径。

## 1. 协议栈总览

```
┌────────────────────────────┐
│       MMS (ISO 9506)       │  ← 应用层：MMS PDU
├────────────────────────────┤
│  Presentation (ISO 8823)   │  ← 表示层：fully-encoded-data 封装
├────────────────────────────┤
│    Session (ISO 8327)      │  ← 会话层：SPDU（连接管理 + 数据传输）
├────────────────────────────┤
│    COTP (ISO 8073)         │  ← 传输层：连接管理 + 分片重组
├────────────────────────────┤
│    TPKT (RFC 1006)         │  ← 适配层：在 TCP 上模拟 OSI 传输
├────────────────────────────┤
│         TCP                │
└────────────────────────────┘
```

在 IEC 61850 环境中，实际网络使用 TCP/IP，通过 TPKT 适配层映射到 OSI 传输服务。

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

Session CONNECT/ACCEPT 携带会话参数，之后可能跟 Presentation 层数据（含 MMS Initiate PDU）：

```
┌─────────────────────────┬──────────────────────────────┐
│ CN/AC: type + len + params │ Presentation data (可选)    │
└─────────────────────────┴──────────────────────────────┘
```

## 5. Presentation 层（ISO 8823）

### fully-encoded-data 结构

Presentation 层使用 `fully-encoded-data [APPLICATION 1]`（tag byte = `0x61`）封装 PDV-list：

```
fully-encoded-data [APPLICATION 1] (0x61)
  └── PDV-list: SEQUENCE (0x30)
        ├── presentation-context-identifier: INTEGER (0x02)
        └── single-ASN1-type [0] (0xA0)
              └── MMS PDU data
```

### presentation-context-id

PDV-list 中每个条目携带一个 `presentation-context-id`（INTEGER），标识数据属于哪个应用上下文：

- **context-id = 3**：MMS 上下文（最常见）
- **context-id = 1**：MMS 上下文（部分实现）

这个 ID 在 Session CONNECT/ACCEPT 阶段通过 Presentation 层的 Context Definition List 协商确定。严格实现应该解析协商结果，但实际中硬编码 `3 || 1` 是常见的简化做法。

### 解封装流程

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

## 6. 完整解封装示例

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

## 7. 连接状态机

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
- IEC 61850-8-1: 通信网络和系统的通信映射
