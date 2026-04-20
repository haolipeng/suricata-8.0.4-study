# MMS GetNameList 深度协议解析 — 理论基础与报文拆解

> 本文围绕 Suricata IEC 61850 MMS 解析器中 **GetNameList** 服务的深度解析功能，
> 梳理所需的协议理论知识，并以实际报文字节逐字段拆解。

---

## 1. 业务语义速览

在 IEC 61850 变电站通信中，客户端（如 SCADA 主站）连接到 IED（智能电子设备）后，
通常第一步就是发送 **GetNameList** 请求来"发现"服务器上有哪些对象。

典型交互时序：

```
客户端                              IED 服务器
  │                                    │
  │── Initiate-Request ──────────────>│  建立 MMS 关联
  │<── Initiate-Response ─────────────│
  │                                    │
  │── GetNameList(domain) ───────────>│  "你有哪些逻辑设备？"
  │<── GetNameList-Response ──────────│  ["LD1","LD2",...]
  │                                    │
  │── GetNameList(variable,LD1) ─────>│  "LD1 下有哪些变量？"
  │<── GetNameList-Response ──────────│  ["LLN0$Mod","XCBR1$Pos",...]
  │                                    │
  │── GetNameList(variableList,LD1) ─>│  "LD1 下有哪些数据集？"
  │<── GetNameList-Response ──────────│  ["dsGENA","dsMEAS",...]
  │                                    │
  │── Read(LD1, LLN0$Mod) ──────────>│  读取具体变量值
  │<── Read-Response ─────────────────│
```

一句话：**GetNameList 是 MMS 的"目录浏览"服务**。

### 1.1 三种核心查询类型对比

| 查询类型 | objectClass | objectScope | 用途 | 典型返回内容 |
|----------|-------------|-------------|------|-------------|
| 列出逻辑设备 | `domain` (9) | vmdSpecific | 发现 IED 上有哪些逻辑设备 | `["LD1","LD2"]` |
| 列出变量 | `named_variable` (0) | domainSpecific("LD1") | 发现某个逻辑设备下的所有数据属性 | `["LLN0$Mod","XCBR1$Pos$stVal"]` |
| 列出数据集 | `named_variable_list` (2) | domainSpecific("LD1") | 发现某个逻辑设备下的所有数据集 | `["dsGENA","dsMEAS","dsALRM"]` |

### 1.2 数据集（VariableList）的作用

在 IEC 61850 中，**数据集（Dataset）** 是一组变量的逻辑分组，对应 MMS 中的
`named_variable_list`。它是报告（Report）和 GOOSE 的基础：

```
数据集 "dsMEAS"
  ├─ MMXU1$MX$TotW$mag$f     (有功功率)
  ├─ MMXU1$MX$TotVAr$mag$f   (无功功率)
  └─ MMXU1$MX$Hz$mag$f       (频率)
```

客户端通过以下步骤使用数据集：

```
客户端                                    IED 服务器
  │                                          │
  │── GetNameList(variableList,LD1) ────────>│  ① 发现 LD1 有哪些数据集
  │<── ["dsMEAS","dsALRM"] ─────────────────│
  │                                          │
  │── GetNamedVarListAttributes ────────────>│  ② 查看 dsMEAS 包含哪些变量
  │    (LD1, "dsMEAS")                       │
  │<── [MMXU1$MX$TotW, ...] ───────────────│
  │                                          │
  │── Report/GOOSE 订阅 ───────────────────>│  ③ 基于数据集订阅实时数据推送
  │<── 数据变化时自动上报 ──────────────────│
```

简而言之：
- **`named_variable` (0)** — 查单个变量名，粒度最细
- **`named_variable_list` (2)** — 查数据集名，是变量的逻辑分组
- **`domain` (9)** — 查逻辑设备名，粒度最粗

---

## 2. ASN.1 / BER 编码基础

### 2.1 TLV 三元组

BER（Basic Encoding Rules）将每个数据元素编码为 **Tag-Length-Value** 结构：

```
┌──────────┬──────────┬──────────────────────┐
│   Tag    │  Length  │        Value          │
│ (1+ 字节) │(1+ 字节) │   (Length 个字节)      │
└──────────┴──────────┴──────────────────────┘
```

### 2.2 Tag 字节结构

单字节 tag（最常见情况）的 8 位含义：

```
  bit:  7   6   5   4   3   2   1   0
       ├───┤   │   ├───────────────────┤
       class  C/P     tag number

  class (2 bit):
    00 = Universal      (如 INTEGER, BOOLEAN, SEQUENCE)
    01 = Application
    10 = Context-specific  ← MMS 大量使用
    11 = Private

  C/P (1 bit):
    0 = Primitive    (值是叶子节点)
    1 = Constructed  (值内部还有嵌套 TLV)

  tag number (5 bit):
    0–30 = 直接表示
    31   = 后续字节用 base-128 编码（多字节 tag）
```

**常见 tag 对照表**（MMS GetNameList 解析中会遇到的）：

| 字节 | 二进制 | class | C/P | tag | 含义 |
|------|--------|-------|-----|-----|------|
| `0x02` | `0000 0010` | Universal | P | 2 | INTEGER |
| `0x01` | `0000 0001` | Universal | P | 1 | BOOLEAN |
| `0x1A` | `0001 1010` | Universal | P | 26 | VisibleString |
| `0x30` | `0011 0000` | Universal | C | 16 | SEQUENCE |
| `0x80` | `1000 0000` | Context | P | 0 | [0] IMPLICIT 原始类型 |
| `0x81` | `1000 0001` | Context | P | 1 | [1] IMPLICIT 原始类型 |
| `0x82` | `1000 0010` | Context | P | 2 | [2] IMPLICIT 原始类型 |
| `0xA0` | `1010 0000` | Context | C | 0 | [0] 构造类型 |
| `0xA1` | `1010 0001` | Context | C | 1 | [1] 构造类型 |

### 2.3 IMPLICIT 标签替换

这是理解 GetNameList 编码的关键。ASN.1 中 `IMPLICIT` 意味着**用上下文标签替换原始标签**。

```asn1
-- 定义
objectScope CHOICE {
    vmdSpecific    [0] IMPLICIT NULL,
    domainSpecific [1] IMPLICIT Identifier,   -- Identifier = VisibleString
    aaSpecific     [2] IMPLICIT NULL
}
```

编码效果：

| 选项 | 原始类型 | 原始 tag | IMPLICIT 替换后 tag | 编码示例 |
|------|----------|----------|---------------------|----------|
| vmdSpecific | NULL | `0x05` | **`0x80`** (context[0] primitive) | `80 00` |
| domainSpecific | VisibleString | `0x1A` | **`0x81`** (context[1] primitive) | `81 03 4C 44 31` = "LD1" |
| aaSpecific | NULL | `0x05` | **`0x82`** (context[2] primitive) | `82 00` |

注意 **`0x80` vs `0xA0`** 的区别：
- `0x80` = context[0] **primitive** — 用于 IMPLICIT 替换原始类型（如 NULL、INTEGER）
- `0xA0` = context[0] **constructed** — 用于包含嵌套结构的字段

### 2.4 Length 编码

| 形式 | 条件 | 格式 | 示例 |
|------|------|------|------|
| 短格式 | 长度 ≤ 127 | 1 字节直接表示 | `0x09` = 9 字节 |
| 长格式 | 长度 > 127 | 首字节 `0x80 + N`，后 N 字节大端 | `0x81 0x80` = 128 字节 |

### 2.5 DEFAULT 语义

```asn1
moreFollows [1] IMPLICIT BOOLEAN DEFAULT TRUE
```

含义：如果报文中**不出现** `[1]` 字段，则取默认值 `TRUE`。
代码中对应 `let mut more_follows = true;`，只在解析到 `0x81` 时才覆盖。

---

## 3. GetNameList ASN.1 完整定义

来自 ISO 9506-2（MMS 协议定义）：

### 3.1 Request

```asn1
GetNameListRequest ::= SEQUENCE {
    objectClass  [0] ObjectClass,
    objectScope  [1] ObjectScope,
    continueAfter [2] IMPLICIT Identifier OPTIONAL
}

ObjectClass ::= CHOICE {
    basicObjectClass [0] IMPLICIT INTEGER {
        namedVariable       (0),
        scatteredAccess     (1),
        namedVariableList   (2),
        namedType           (3),
        semaphore            (4),
        eventCondition      (5),
        eventAction         (6),
        eventEnrollment     (7),
        journal             (8),
        domain              (9),
        programInvocation   (10),
        operatorStation     (11)
    },
    csObjectClass [1] IMPLICIT INTEGER
}

ObjectScope ::= CHOICE {
    vmdSpecific      [0] IMPLICIT NULL,
    domainSpecific   [1] IMPLICIT Identifier,
    aaSpecific       [2] IMPLICIT NULL
}
```

### 3.2 Response

```asn1
GetNameListResponse ::= SEQUENCE {
    listOfIdentifier [0] IMPLICIT SEQUENCE OF Identifier,
    moreFollows      [1] IMPLICIT BOOLEAN DEFAULT TRUE
}
```

### 3.3 字段含义

#### objectClass — "查什么类型的对象"

| 值 | 名称 | 说明 | IEC 61850 中的用途 |
|----|------|------|--------------------|
| 0 | `named_variable` | 命名变量 | 查询逻辑节点下的数据属性（如 `XCBR1$Pos`） |
| 1 | `scattered_access` | 分散访问 | 较少使用 |
| 2 | `named_variable_list` | 命名变量列表 | 查询数据集（Dataset） |
| 3 | `named_type` | 命名类型 | 类型定义 |
| 4 | `semaphore` | 信号量 | MMS 并发控制 |
| 5 | `event_condition` | 事件条件 | 报告触发条件 |
| 6 | `event_action` | 事件动作 | 事件响应 |
| 7 | `event_enrollment` | 事件注册 | 报告订阅 |
| 8 | `journal` | 日志 | MMS 日志对象 |
| 9 | `domain` | 域 | **查询逻辑设备列表**（IEC 61850 最常见用法之一） |
| 10 | `program_invocation` | 程序调用 | 程序对象 |
| 11 | `operator_station` | 操作站 | 操作员站 |

**IEC 61850 中最常见的三种查询：**
- `objectClass=9 (domain)` + `vmdSpecific` → 列出所有逻辑设备
- `objectClass=0 (named_variable)` + `domainSpecific("LD1")` → 列出 LD1 下所有变量
- `objectClass=2 (named_variable_list)` + `domainSpecific("LD1")` → 列出 LD1 下所有数据集

#### objectScope — "在哪个范围内查"

| 选项 | 含义 | 参数 |
|------|------|------|
| `vmdSpecific` | 在整个虚拟制造设备（VMD，即整个 IED）范围查 | 无（NULL） |
| `domainSpecific` | 在指定域（逻辑设备）内查 | 域名称（Identifier） |
| `aaSpecific` | 在当前应用关联范围内查 | 无（NULL） |

#### continueAfter — 分页机制

当服务器返回的对象太多无法一次返回时，响应中 `moreFollows=true`。
客户端在下一次请求中设置 `continueAfter` 为上次收到的最后一个标识符名称，
服务器从该名称之后继续返回。

```
请求1: GetNameList(variable, LD1)
响应1: ["Var001"..."Var100"], moreFollows=true

请求2: GetNameList(variable, LD1, continueAfter="Var100")
响应2: ["Var101"..."Var150"], moreFollows=false
```

---

## 4. 实际报文抓包分析

> 以下分析基于 `iec61850_get_name_list.pcap` 抓包文件。

### 4.0 整体交互时序（pcap 帧号对照）

```
帧号  方向              协议层           说明
────  ────              ──────           ────
 1    Client → Server   TCP SYN          三次握手
 2    Server → Client   TCP SYN+ACK
 3    Client → Server   TCP ACK
 4    Client → Server   COTP CR          COTP 连接请求 (src-ref: 0x0006)
 6    Server → Client   COTP CC          COTP 连接确认 (src-ref: 0x0004)
 8    Client → Server   MMS              Initiate-RequestPDU (MMS 关联建立)
10    Server → Client   SES/MMS          Initiate-ResponsePDU (AC SPDU)
12    Client → Server   MMS              ★ GetNameList Request
                                           objectClass=named_variable(0)
                                           objectScope=vmdSpecific
14    Server → Client   MMS              ★ GetNameList Response (invokeID=0)
16    Client → Server   MMS              Conclude-RequestPDU
18    Server → Client   MMS              Conclude-ResponsePDU
20    Client → Server   TCP RST          连接关闭
```

这是一个完整的 MMS 会话生命周期：TCP 握手 → COTP 建连 → MMS 关联 → GetNameList 查询 → 关闭。

### 4.1 GetNameList Request — 实际报文（Frame 12）

**完整 TCP payload（36 字节）：**

```
03 00 00 24 02 f0 80 01 00 01 00 61 17 30 15 02
01 03 a0 10 a0 0e 02 01 00 a1 09 a0 03 80 01 00
a1 02 80 00
```

**逐层拆解：**

```
03 00 00 24                   ← TPKT: version=3, length=36
02 f0 80                      ← COTP DT: length=2, type=0xF0(DT), EOT=1
01 00                         ← Session: Give Tokens SPDU
01 00                         ← Session: DT SPDU
61 17                         ← Presentation: user-data, length=23
30 15                         ← SEQUENCE, length=21
02 01 03                      ← presentation-context-id = 3 (mms-abstract-syntax)
a0 10                         ← [0] single-ASN1-type, length=16
```

**MMS PDU 层（16 字节）：**

```
a0 0e                         ← [0] ConfirmedRequest, constructed, length=14
│
├─ 02 01 00                   ← INTEGER, length=1, value=0 → invokeID=0
│
└─ a1 09                      ← [1] GetNameList service, constructed, length=9
   │
   ├─ a0 03                   ← [0] objectClass, constructed, length=3
   │  └─ 80 01 00             ← [0] basicObjectClass, IMPLICIT INTEGER
   │                             length=1, value=0 → "named_variable"
   │
   └─ a1 02                   ← [1] objectScope, constructed, length=2
      └─ 80 00                ← [0] vmdSpecific, IMPLICIT NULL (length=0)
```

**tag 解读要点：**
- `a0`（ConfirmedRequest）= `1010 0000` → class=context, constructed, tag=0
- `a1`（GetNameList）= `1010 0001` → class=context, constructed, tag=1
- `80`（basicObjectClass）= `1000 0000` → class=context, **primitive**, tag=0
  - 之所以是 primitive，因为 `[0] IMPLICIT INTEGER`，替换了 INTEGER 的原始 tag `0x02`
- `80`（vmdSpecific）= `1000 0000` → class=context, **primitive**, tag=0
  - `[0] IMPLICIT NULL`，替换了 NULL 的原始 tag `0x05`，长度为 0

**本报文的业务含义：** 客户端查询整个 VMD（IED）范围内所有 `named_variable` 类型的对象名。这通常是 MMS 关联建立后的第一个操作。

### 4.2 GetNameList Response — 实际报文（Frame 14）

**完整 TCP payload（25 字节）：**

```
03 00 00 19 02 f0 80 01 00 01 00 61 0c 30 0a 02
01 03 a0 05 a1 03 02 01 00
```

**逐层拆解：**

```
03 00 00 19                   ← TPKT: version=3, length=25
02 f0 80                      ← COTP DT: length=2, type=0xF0(DT), EOT=1
01 00                         ← Session: Give Tokens SPDU
01 00                         ← Session: DT SPDU
61 0c                         ← Presentation: user-data, length=12
30 0a                         ← SEQUENCE, length=10
02 01 03                      ← presentation-context-id = 3
a0 05                         ← [0] single-ASN1-type, length=5
```

**MMS PDU 层（5 字节）：**

```
a1 03                         ← [1] ConfirmedResponse, constructed, length=3
│
└─ 02 01 00                   ← INTEGER, length=1, value=0 → invokeID=0
                                 (无 confirmedServiceResponse 数据)
```

**注意：** 该响应 PDU 极其精简——仅含 invokeID，没有 service response body。这表明服务器返回了一个最小化的响应（可能是空的 GetNameList 结果或该测试环境中的简化行为）。代码中通过 `rest.is_empty()` 检查处理了这种情况（见 `parse_confirmed_response`）。

### 4.3 补充示例 — 构造化报文字节拆解（ASN.1 理论对照）

以下为基于 ASN.1 定义构造的典型报文，用于补充说明 pcap 中未覆盖的场景：

#### 4.3.1 Request — 查询 LD1 域下的变量 + continueAfter

```
A0 19                         ← [0] ConfirmedRequest, constructed, length=25
│
├─ 02 01 02                   ← INTEGER, length=1, value=2 → invokeID=2
│
└─ A1 14                      ← [1] GetNameList service, constructed, length=20
   │
   ├─ A0 03                   ← [0] objectClass, constructed, length=3
   │  └─ 80 01 00             ← [0] basicObjectClass, IMPLICIT INTEGER
   │                             length=1, value=0 → "named_variable"
   │
   ├─ A1 05                   ← [1] objectScope, constructed, length=5
   │  └─ 81 03 4C 44 31       ← [1] domainSpecific, IMPLICIT VisibleString
   │                             length=3, value="LD1"
   │
   └─ 82 06 56 61 72 31 30 30 ← [2] continueAfter, IMPLICIT VisibleString
                                 length=6, value="Var100"
```

- `81`（domainSpecific）= `1000 0001` → class=context, **primitive**, tag=1
  - 替换了 VisibleString 的原始 tag `0x1A`
- `82`（continueAfter）= `1000 0010` → class=context, **primitive**, tag=2
  - 注意：这个 `0x82` 在**外层** GetNameListRequest SEQUENCE 中
  - 而 objectScope 内的 `0x82` 是 aaSpecific——它们处于不同的嵌套层级，不会混淆

#### 4.3.2 Request — 查询所有域（逻辑设备列表）

```
A0 0E                         ← [0] ConfirmedRequest, length=14
│
├─ 02 01 01                   ← invokeID=1
│
└─ A1 09                      ← [1] GetNameList, length=9
   │
   ├─ A0 03                   ← [0] objectClass, length=3
   │  └─ 80 01 09             ← basicObjectClass=9 → "domain"
   │
   └─ A1 02                   ← [1] objectScope, length=2
      └─ 80 00                ← [0] vmdSpecific, NULL (length=0)
```

#### 4.3.3 Response — 返回 3 个标识符

```
A1 1C                         ← [1] ConfirmedResponse, length=28
│
├─ 02 01 01                   ← invokeID=1
│
└─ A1 17                      ← [1] GetNameList response, length=23
   │
   ├─ A0 12                   ← [0] listOfIdentifier, length=18
   │  ├─ 1A 04 56 61 72 31   ← VisibleString "Var1"
   │  ├─ 1A 04 56 61 72 32   ← VisibleString "Var2"
   │  └─ 1A 04 56 61 72 33   ← VisibleString "Var3"
   │
   └─ 81 01 FF               ← [1] moreFollows=TRUE (0xFF≠0)
```

**注意：**
- `1A` = Universal VisibleString（tag=26），这里**没有** IMPLICIT 替换，
  因为它是 `SEQUENCE OF Identifier`，Identifier 本身就是 VisibleString
- `81 01 FF` 中 `0xFF` 表示 TRUE，`0x00` 表示 FALSE
- 如果 `moreFollows` 字段完全不出现，按 ASN.1 `DEFAULT TRUE` 规则，取 true

#### 4.3.4 Response — 空列表 + moreFollows=false

```
A1 0A                         ← [1] ConfirmedResponse, length=10
│
├─ 02 01 02                   ← invokeID=2
│
└─ A1 05                      ← [1] GetNameList response, length=5
   │
   ├─ A0 00                   ← [0] listOfIdentifier, length=0 (空)
   │
   └─ 81 01 00               ← [1] moreFollows=FALSE
```

---

## 5. 代码与协议的映射关系

下表将 ASN.1 字段、BER tag、代码解析位置一一对应：

### 5.1 数据结构定义

**Request 结构体** (`mms_pdu.rs:270-275`)：

```rust
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MmsGetNameListRequest {
    pub object_class: Option<String>,   // 查询的对象类别（如 named_variable、domain 等）
    pub domain_id: Option<String>,      // 限定查询范围的域名称（仅 domainSpecific 时有值）
    pub object_scope: Option<String>,   // 查询范围："vmd_specific" / "domain_specific" / "aa_specific"
    pub continue_after: Option<String>, // 分页续传标识符
}
```

**Response 结构体** (`mms_pdu.rs:278-282`)：

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct MmsGetNameListResponse {
    pub identifiers: Vec<String>, // 返回的名称列表（上限 64 条）
    pub more_follows: bool,       // 是否还有后续数据（ASN.1 DEFAULT TRUE）
}
```

### 5.2 Request 侧解析

| ASN.1 字段 | BER tag | 代码位置 | Rust 结构体字段 |
|------------|---------|---------|----------------|
| GetNameListRequest（外层） | `0xA1`（service tag=1） | `parse_confirmed_request` 中 service_num=1 分发 | `MmsGetNameListRequest` |
| objectClass → basicObjectClass | 外 `0xA0` → 内 `0x80` | `parse_get_name_list_request` match `0xA0` | `.object_class` |
| objectScope → vmdSpecific | 外 `0xA1` → 内 `0x80` | match `0xA1` → match `0x80` | `.object_scope = "vmd_specific"` |
| objectScope → domainSpecific | 外 `0xA1` → 内 `0x81` | match `0xA1` → match `0x81` | `.object_scope = "domain_specific"`, `.domain_id` |
| objectScope → aaSpecific | 外 `0xA1` → 内 `0x82` | match `0xA1` → match `0x82` | `.object_scope = "aa_specific"` |
| continueAfter | `0x82` | match `0x82`（外层） | `.continue_after` |

**服务分发入口** (`mms_pdu.rs:642-644`) — `parse_confirmed_request` 根据 service tag 分发：

```rust
MmsConfirmedService::GetNameList => {
    get_name_list_info = Some(parse_get_name_list_request(service_content));
}
```

**Request 核心解析逻辑** (`mms_pdu.rs:465-532`)：

```rust
fn parse_get_name_list_request(content: &[u8]) -> MmsGetNameListRequest {
    let mut result = MmsGetNameListRequest::default();
    let mut pos = content;

    while !pos.is_empty() {
        if let Ok((tag_byte, _, _, inner, rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0xA0 => {
                    // objectClass: 外层 [0] constructed → 内层解析 basicObjectClass
                    if let Ok((_, _, _, class_content, _)) = parse_ber_tlv(inner) {
                        if let Ok(class_val) = parse_ber_integer(class_content) {
                            result.object_class = Some(
                                match class_val {
                                    0 => "named_variable",
                                    // ... 1-8 省略 ...
                                    9 => "domain",
                                    // ... 10-11 省略 ...
                                    _ => "unknown",
                                }.to_string(),
                            );
                        }
                    }
                }
                0xA1 => {
                    // objectScope: [1] constructed → 内部 CHOICE
                    if let Ok((scope_tag, _, _, scope_content, _)) = parse_ber_tlv(inner) {
                        match scope_tag {
                            0x80 => {
                                // vmdSpecific: [0] IMPLICIT NULL
                                result.object_scope = Some("vmd_specific".to_string());
                            }
                            0x81 => {
                                // domainSpecific: [1] IMPLICIT Identifier
                                result.object_scope = Some("domain_specific".to_string());
                                result.domain_id = Some(parse_ber_string(scope_content));
                            }
                            0x82 => {
                                // aaSpecific: [2] IMPLICIT NULL
                                result.object_scope = Some("aa_specific".to_string());
                            }
                            _ => {}
                        }
                    }
                }
                0x82 => {
                    // continueAfter: [2] IMPLICIT Identifier（外层 SEQUENCE 的 [2]）
                    result.continue_after = Some(parse_ber_string(inner));
                }
                _ => {}
            }
            pos = rem;
        } else {
            break;
        }
    }
    result
}
```

> **对应 pcap Frame 12 的执行路径：**
> 1. `parse_ber_tlv` 解析外层 `a0 0e` → tag=0, ConfirmedRequest
> 2. `parse_confirmed_request` 读取 `02 01 00` → invokeID=0
> 3. 读取 `a1 09` → service_num=1 → `MmsConfirmedService::GetNameList`
> 4. 进入 `parse_get_name_list_request`，对 9 字节 service_content 循环：
>    - `a0 03` → objectClass → 内层 `80 01 00` → class_val=0 → `"named_variable"`
>    - `a1 02` → objectScope → 内层 `80 00` → scope_tag=0x80 → `"vmd_specific"`

### 5.3 Response 侧解析

| ASN.1 字段 | BER tag | 代码位置 | Rust 结构体字段 |
|------------|---------|---------|----------------|
| GetNameListResponse（外层） | `0xA1`（service tag=1） | `parse_confirmed_response` 中 service_num=1 分发 | `MmsGetNameListResponse` |
| listOfIdentifier | `0xA0` | `parse_get_name_list_response` match `0xA0` | `.identifiers: Vec<String>` |
| 每个 Identifier | `0x1A`（VisibleString） | 内层 while 循环 | identifiers 中的每个元素 |
| moreFollows | `0x81` | match `0x81` | `.more_follows: bool` |

**Response 分发逻辑** (`mms_pdu.rs:738-765`) — 含空响应兜底处理：

```rust
fn parse_confirmed_response(content: &[u8]) -> Result<MmsPdu, ()> {
    let (_, _, _, id_content, rest) = parse_ber_tlv(content)?;
    let invoke_id = parse_ber_integer(id_content)?;

    // ★ 处理 pcap Frame 14 这种极简响应（无 service response body）
    if rest.is_empty() {
        return Ok(MmsPdu::ConfirmedResponse {
            invoke_id,
            service: MmsConfirmedService::Unknown(0),
            get_name_list_info: None,
        });
    }

    let (_, _, service_num, service_content, _) = parse_ber_tlv(rest)?;
    let service = MmsConfirmedService::from_response_tag(service_num);

    let mut get_name_list_info = None;
    if service == MmsConfirmedService::GetNameList {
        get_name_list_info = Some(parse_get_name_list_response(service_content));
    }

    Ok(MmsPdu::ConfirmedResponse { invoke_id, service, get_name_list_info })
}
```

**Response 核心解析逻辑** (`mms_pdu.rs:695-735`)：

```rust
fn parse_get_name_list_response(content: &[u8]) -> MmsGetNameListResponse {
    let mut identifiers = Vec::new();
    let mut more_follows = true; // ★ ASN.1 DEFAULT TRUE — 字段不出现时取 true

    let mut pos = content;
    while !pos.is_empty() {
        if let Ok((tag_byte, _, _, inner, rem)) = parse_ber_tlv(pos) {
            match tag_byte {
                0xA0 => {
                    // [0] listOfIdentifier: SEQUENCE OF Identifier (VisibleString)
                    let mut id_pos = inner;
                    while !id_pos.is_empty() {
                        if let Ok((_, _, _, id_content, id_rem)) = parse_ber_tlv(id_pos) {
                            if identifiers.len() < 64 {  // ★ 上限 64 条防止内存滥用
                                identifiers.push(parse_ber_string(id_content));
                            }
                            id_pos = id_rem;
                        } else { break; }
                    }
                }
                0x81 => {
                    // [1] moreFollows: BOOLEAN
                    if !inner.is_empty() {
                        more_follows = inner[0] != 0x00;
                    }
                }
                _ => {}
            }
            pos = rem;
        } else { break; }
    }

    MmsGetNameListResponse { identifiers, more_follows }
}
```

### 5.4 日志输出

**Request 侧日志** (`logger.rs:70-83`)：

```rust
if let Some(ref gnl) = get_name_list_info {
    if let Some(ref class) = gnl.object_class {
        js.set_string("object_class", class)?;
    }
    if let Some(ref scope) = gnl.object_scope {
        js.set_string("object_scope", scope)?;
    }
    if let Some(ref domain) = gnl.domain_id {
        js.set_string("domain", domain)?;
    }
    if let Some(ref cont) = gnl.continue_after {
        js.set_string("continue_after", cont)?;
    }
}
```

**Response 侧日志** (`logger.rs:85-98`)：

```rust
MmsPdu::ConfirmedResponse { get_name_list_info, .. } => {
    if let Some(ref gnl) = get_name_list_info {
        if !gnl.identifiers.is_empty() {
            js.open_array("identifiers")?;
            for id in &gnl.identifiers {
                js.append_string(id)?;
            }
            js.close()?;
        }
        js.set_bool("more_follows", gnl.more_follows)?;
    }
}
```

---

## 6. 容易混淆的点

### 6.1 同一个 tag number 在不同层级有不同含义

`0x82` 在 GetNameListRequest 中出现了两次，但含义完全不同：

```
A1 xx               ← GetNameList service
  A0 xx             ← objectClass
  A1 xx             ← objectScope
    82 00           ← aaSpecific (objectScope 内部的 [2])
  82 06 ...         ← continueAfter (GetNameListRequest 外层的 [2])
```

代码中之所以不会混淆，是因为解析 `0xA1`（objectScope）时只对其**内部字节**调用
`parse_ber_tlv`，而 `continueAfter` 的 `0x82` 在**外层循环**中处理。
两者处于不同的 `while` 循环作用域。

### 6.2 `0x80` primitive vs `0xA0` constructed

| tag | 二进制 | bit 5 (C/P) | 用于 |
|-----|--------|-------------|------|
| `0x80` | `1000 0000` | 0 (Primitive) | `[0] IMPLICIT` 原始类型（NULL, INTEGER, VisibleString） |
| `0xA0` | `1010 0000` | 1 (Constructed) | `[0]` 包裹嵌套结构（如 objectClass 包含内部 CHOICE） |

在 GetNameList 解析中：
- `objectClass` 的外层是 `0xA0`（constructed，因为里面还有一层 basicObjectClass）
- `basicObjectClass` 是 `0x80`（primitive，IMPLICIT INTEGER，值直接在 content 中）
- `vmdSpecific` 是 `0x80`（primitive，IMPLICIT NULL）

### 6.3 moreFollows 的 DEFAULT TRUE 语义

ASN.1 `DEFAULT TRUE` 意味着：
- 字段**存在**且值为 `0xFF` → true
- 字段**存在**且值为 `0x00` → false
- 字段**不存在** → true（取默认值）

代码中 `let mut more_follows = true;` 即处理了第三种情况。

---

## 7. 日志输出格式

解析结果最终通过 `logger.rs` 输出为 EVE JSON：

**Request 侧输出：**
```json
{
  "iec61850_mms": {
    "request": {
      "pdu_type": "confirmed_request",
      "invoke_id": 2,
      "service": "get_name_list",
      "object_class": "named_variable",
      "object_scope": "domain_specific",
      "domain": "LD1",
      "continue_after": "Var100"
    }
  }
}
```

**Response 侧输出：**
```json
{
  "iec61850_mms": {
    "response": {
      "pdu_type": "confirmed_response",
      "invoke_id": 2,
      "service": "get_name_list",
      "identifiers": ["Var1", "Var2", "Var3"],
      "more_follows": true
    }
  }
}
```
