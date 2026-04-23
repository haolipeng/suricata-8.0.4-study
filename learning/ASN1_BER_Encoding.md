# ASN.1 BER 编码规则

本文档记录在 IEC 61850 MMS 解析器开发中涉及的 ASN.1 BER（Basic Encoding Rules）核心知识。

## 1. TLV 三元组

BER 将每个数据元素编码为 **Tag-Length-Value** 三段：

```
┌──────┬──────────┬──────────────┐
│ Tag  │  Length   │    Value     │
└──────┴──────────┴──────────────┘
```

- **Tag**：标识数据类型（1 或多字节）
- **Length**：Value 部分的字节长度
- **Value**：实际数据内容

## 2. Tag 字节结构

单字节 tag 的位布局（ITU-T X.690 §8.1.2）：

```
 bit:  8   7   6   5   4   3   2   1
      ├─class─┤ P/C ├───tag number──┤
```

### Class（bit 8-7）

| 值 | 含义 | 说明 |
|----|------|------|
| 00 | UNIVERSAL | ASN.1 内建类型（INTEGER=0x02, BOOLEAN=0x01, SEQUENCE=0x30 等） |
| 01 | APPLICATION | 应用级标签，整个应用唯一 |
| 10 | CONTEXT-SPECIFIC | 上下文标签，仅在当前结构体内有意义 |
| 11 | PRIVATE | 私有标签 |

MMS PDU 和 Data CHOICE 大量使用 **CONTEXT-SPECIFIC** 标签。

### P/C（bit 6）

| 值 | 含义 | 说明 |
|----|------|------|
| 0 | Primitive | 值是原子的（如 INTEGER, BOOLEAN） |
| 1 | Constructed | 值内部包含嵌套的 TLV（如 SEQUENCE, SET） |

### Tag Number（bit 5-1）

- 0-30：直接编码在低 5 位
- 31（全 1）：使用多字节标签，后续字节以 base-128 编码，最高位为延续标志

### 编码示例

```
context-specific [3] primitive:
  class=10, P/C=0, tag_num=00011
  → 1000_0011 = 0x83

context-specific [2] constructed:
  class=10, P/C=1, tag_num=00010
  → 1010_0010 = 0xA2

context-specific [16] primitive:
  class=10, P/C=0, tag_num=10000
  → 1001_0000 = 0x90
```

## 3. Length 编码

### 短格式（1 字节）

当长度 ≤ 127 时，直接用 1 字节表示：

```
Length=5  → 0x05
Length=127 → 0x7F
```

### 长格式（多字节）

当长度 > 127 时，第一字节的最高位为 1，低 7 位表示后续长度字段的字节数：

```
Length=128 → 0x81 0x80       (1 字节后续)
Length=256 → 0x82 0x01 0x00  (2 字节后续)
```

### 不定长格式

`0x80` 表示不定长编码，需要在 Value 末尾用 `0x00 0x00` 作为终止标记。MMS 实现通常不使用此格式。

## 4. IMPLICIT vs EXPLICIT 标签

ASN.1 中对 CHOICE/SEQUENCE 成员的标签有两种模式：

### IMPLICIT（替换标签）

```asn1
boolean [3] IMPLICIT BOOLEAN
```

编码时用 context tag `[3]` 直接替换 UNIVERSAL BOOLEAN tag，**不嵌套**：

```
83 01 FF    ← tag=0x83([3] context, primitive), length=1, value=0xFF(true)
```

### EXPLICIT（嵌套标签）

```asn1
boolean [3] EXPLICIT BOOLEAN
```

编码时 context tag `[3]` 包裹原始 UNIVERSAL tag，**嵌套一层**：

```
A3 03       ← tag=0xA3([3] context, constructed), length=3
  01 01 FF  ← tag=0x01(UNIVERSAL BOOLEAN), length=1, value=0xFF
```

MMS ASN.1 定义中几乎全部使用 **IMPLICIT**，因此解析时 tag byte 后面直接是值内容，无需再剥一层。

## 5. 常见陷阱

### tag_num 不等于 tag_byte

`parse_ber_tlv` 返回的 `tag_num` 是 tag byte 的低 5 位（去掉 class 和 P/C）。同一个 `tag_num` 可以对应两个不同的 tag_byte：

```
tag_num=2, primitive:    tag_byte = 0x82
tag_num=2, constructed:  tag_byte = 0xA2
```

在 MMS Data CHOICE 中：
- `[2] structure` 是 constructed → tag_byte=**0xA2**
- `[4] bit-string` 是 primitive → tag_byte=**0x84**

两者的 tag_num 不同（2 vs 4），不会混淆。但如果映射表偏移，tag_num=2 可能被错误地映射为 "bit-string"。

### 映射表必须对照标准

ASN.1 CHOICE 中的 tag number 是协议标准定义的，不是从 0 递增的序号。MMS Data CHOICE 的 tag 从 `[1]` 开始（`[0]` 保留给 AccessResult failure），中间有跳号（`[8]` reserved）。手工编写映射表时极易出错。

## 参考

- ITU-T X.690: ASN.1 BER/CER/DER 编码规则
- ITU-T X.680: ASN.1 基本符号
