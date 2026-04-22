# IEC 61850 MMS 解析器代码审查报告

> 审查范围：`rust/src/iec61850mms/` 目录下全部 6 个文件（mod.rs, mms.rs, parser.rs, mms_pdu.rs, detect.rs, logger.rs）
> 审查视角：Suricata 应用层解析技术专家 + IEC 61850 MMS 协议解析专家
> 日期：2026-04-13

---

## 一、严重问题（影响正确性/安全性）

### S1. COTP 分片重组完全缺失

- **文件**：`mms.rs:262-264`、`parser.rs:99`
- **现象**：`parser.rs` 解析了 COTP DT 帧的 `last_unit`（EOT 标志），但 `mms.rs` 的 `parse_frames` 中从未使用该字段。每个 COTP DT 帧的载荷被独立传入 `parse_mms_pdu`。
- **影响**：MMS PDU 可以跨多个 COTP DT 帧传输（EOT=0 表示后续还有分片，EOT=1 表示最后一帧）。遇到分片 PDU 时解析失败，触发 `MalformedData` **误报**。
- **真实场景**：IEC 61850 的 Read Response 经常包含大量数据点，超过单个 TPKT 帧大小（~65KB），必须分片传输。这在工业现场是**常见场景**，不是边界情况。
- **预期行为**：
  ```
  当前：DT(EOT=0) → parse_mms_pdu → 失败 ❌
  应该：DT(EOT=0) → 缓存 → DT(EOT=1) → 拼接 → parse_mms_pdu ✓
  ```
- **修复方案**：在 `MmsState` 中为每个方向增加 `Vec<u8>` 重组缓冲区，收到 EOT=0 的帧时追加数据，收到 EOT=1 时拼接后传入 `parse_mms_pdu`。

---

### S2. MMS PDU 标签的 class 字段未验证

- **文件**：`mms_pdu.rs:581-582`
- **现象**：
  ```rust
  let (tag_byte, _is_constructed, tag_num, content, _remaining) = parse_ber_tlv(input)?;
  let _class = (tag_byte >> 6) & 0x03;  // 提取了但没使用
  ```
  MMS PDU CHOICE 使用 **context-specific** 标签（class=2，即 tag_byte 的高 2 位 = `10`），但代码没有验证 class 值。
- **影响**：如果收到一个 universal class 的标签（如 `0x03` BITSTRING，tag_num=3），会被误解析为 `UnconfirmedPdu`。在 IDS 场景中，攻击者可能利用这种宽松解析来**规避检测规则**或触发错误的告警。
- **修复方案**：在 `parse_mms_pdu` 中增加 class 检查：
  ```rust
  let class = (tag_byte >> 6) & 0x03;
  if class != 2 {  // 必须是 context-specific
      return Err(());
  }
  ```

---

### S3. Read Request 变量提取逻辑与标准 MMS 编码不匹配

- **文件**：`mms_pdu.rs:698-714`
- **现象**：`parse_read_request` 在 ReadRequest 内容中查找 tag `0xA1`：
  ```rust
  if tag_byte == 0xA1 {
      return parse_variable_access_specification(inner);
  }
  ```
- **问题分析**：按 ISO 9506-2 的 ReadRequest 定义：
  ```asn1
  ReadRequest ::= SEQUENCE {
      specificationWithResult  [0] IMPLICIT BOOLEAN DEFAULT FALSE,
      variableAccessSpecification  VariableAccessSpecification
  }
  VariableAccessSpecification ::= CHOICE {
      listOfVariable   [0] IMPLICIT SEQUENCE OF ...,  -- tag = 0xA0
      variableListName [1] ObjectName                  -- tag = 0xA1
  }
  ```
  绝大多数真实 MMS 流量使用 `listOfVariable`（tag=`0xA0`），而代码只匹配了 `variableListName`（tag=`0xA1`）。
- **影响**：**漏掉绝大多数真实 MMS 流量中的 Read 请求变量列表**。测试用例通过是因为构造了特殊的嵌套结构恰好走通了流程，但不代表真实 pcap 数据能正确解析。
- **修复方案**：`parse_read_request` 应同时处理 `0xA0`（listOfVariable）和 `0xA1`（variableListName）两种情况：
  ```rust
  match tag_byte {
      0xA0 => return parse_list_of_variable(inner),      // listOfVariable
      0xA1 => return parse_variable_list_name(inner),     // variableListName
      _ => {}
  }
  ```

---

### S4. ConcludeRequest 被标记为"单向完成"，导致请求/响应无法关联

- **文件**：`mms.rs:501-506`
- **现象**：
  ```rust
  MmsPdu::ConcludeRequest | MmsPdu::ConcludeResponse => {
      return 1;  // 标记为完成
  }
  ```
  `tx_get_alstate_progress` 对 `ConcludeRequest` 在两个方向（TS/TC）都返回 1。
- **影响**：Suricata 认为该事务双向都已完成（`tx_comp_st_ts=1, tx_comp_st_tc=1`），可能在 ConcludeResponse 到达之前回收事务。ConcludeResponse 到来后找不到匹配事务，只能创建孤立事务。日志中无法将 Conclude 的请求/响应关联起来。
- **修复方案**：不将 `ConcludeRequest` 标记为单向完成。只有 `ConcludeResponse`（无需等待后续数据）和 `UnconfirmedPdu`（本身就是单向的）才应返回 1：
  ```rust
  MmsPdu::UnconfirmedPdu { .. } | MmsPdu::ConcludeResponse => {
      return 1;
  }
  ```

---

### S5. Session CONNECT/ACCEPT 中的 MMS Initiate 参数完全丢失

- **文件**：`mms.rs:274-294`、`mms_pdu.rs:772-803`
- **现象**：`extract_mms_from_session` 对 Session CONNECT（0x0D）和 ACCEPT（0x0E）直接返回 `Ok(None)`，`parse_frames` 随后创建空的 `MmsPdu::InitiateRequest` / `MmsPdu::InitiateResponse`。
- **影响**：IEC 61850 的 Session CONNECT 包含 CP-type PPDU，内部嵌套了 MMS Initiate-Request PDU，包含关键的协商参数：
  - `localDetailCalling` / `localDetailCalled`：最大 PDU 大小
  - `proposedMaxServOutstandingCalling`：最大并发请求数
  - `initRequestDetail`：支持的服务列表、版本号

  这些参数对安全监控有重要意义（如检测异常的 PDU 大小协商、未授权的服务请求等），当前全部丢失。
- **修复方案**：对 Session CONNECT/ACCEPT 帧，解析其 Presentation 层内容，提取 MMS Initiate PDU 的参数，扩展 `MmsPdu::InitiateRequest` / `MmsPdu::InitiateResponse` 枚举值携带这些信息。

---

## 二、中等问题（影响健壮性）

### M1. 状态机无法处理 COTP 重连

- **文件**：`mms.rs:135-155`
- **现象**：`advance_state` 一旦进入 `Closed` 状态，没有任何合法转换路径回到 `Idle`。
- **影响**：COTP 协议允许在同一条 TCP 连接上执行 DR → CR → CC 重新建立传输连接。当前状态机会对重连场景**持续产生 `ProtocolStateViolation` 误报**。
- **修复方案**：增加转换规则 `(Closed, CotpCr) => CotpPending`。

---

### M2. `is_constructed` 标志未验证

- **文件**：`mms_pdu.rs:581`
- **现象**：`_is_constructed` 被提取但从未检查。
- **影响**：ConfirmedRequest（[0]）、ConfirmedResponse（[1]）等 PDU 必须是 constructed（bit 5 = 1）。如果收到 primitive 编码的同 tag 数据（如 `0x80` 而非 `0xA0`），代码会尝试将其内容当作 SEQUENCE 解析，产生不可预测的结果而非干净的错误。
- **修复方案**：对 tag 0-4（SEQUENCE 类型的 PDU）验证 `is_constructed == true`。

---

### M3. BER INTEGER 不处理有符号值

- **文件**：`mms_pdu.rs:430-439`
- **现象**：按无符号方式拼接字节。BER INTEGER 使用二进制补码，`[0xFF]` 应该是 -1 但返回 255。
- **影响**：MMS 的 `invokeID` 是 `Unsigned32`（高位为 1 时会前缀 `0x00` 字节），目前碰巧工作。但函数名 `parse_ber_integer` 暗示通用 BER 整数解析，如果未来用于其他字段（如 error code、offset 等有符号字段）会产生错误结果。
- **修复方案**：要么拆分为 `parse_ber_unsigned` / `parse_ber_signed`，要么在函数注释中明确标注"仅适用于无符号整数"。

---

### M4. BER 不定长编码直接返回错误

- **文件**：`mms_pdu.rs:412-414`
- **现象**：
  ```rust
  } else if first == 0x80 {
      Err(())  // 不定长格式，不支持
  }
  ```
- **影响**：某些工业设备的 ASN.1 编码器会使用不定长编码（`0x80` + 内容 + `0x00 0x00` 终结符）。直接报错导致整条解析链中断，将**合法流量标记为 MalformedData**。
- **修复方案**：实现不定长编码的解析（扫描 `0x00 0x00` 终结符），或者至少尝试跳过该 TLV 而非终止整个解析。

---

### M5. `parse_mms_pdu` 丢弃 remaining 数据且不检查

- **文件**：`mms_pdu.rs:581`
- **现象**：`_remaining` 被丢弃。正常情况下一个 COTP 帧的 MMS 载荷中只有一个 PDU，remaining 应该为空。
- **影响**：如果 remaining 非空，可能意味着帧被错误解析或存在额外的注入数据。静默丢弃可能**遗漏安全异常**。
- **修复方案**：在 remaining 非空时至少记录一个 debug 级别的事件。

---

### M6. 事务完成度判断不区分方向

- **文件**：`mms.rs:490-512`
- **现象**：`iec61850_mms_tx_get_alstate_progress` 接收 `_direction` 参数但完全忽略。
- **影响**：Suricata 会分别为 TS（请求）和 TC（响应）方向调用此函数。对于请求-响应模式，TS 方向在有 request 时应返回完成，TC 方向在有 response 时应返回完成。当前两个方向使用相同逻辑，可能影响 Suricata 的流控和内存管理决策。
- **修复方案**：
  ```rust
  let direction = Direction::from(direction);
  match direction {
      Direction::ToServer => if tx.request.is_some() { return 1; },
      Direction::ToClient => if tx.response.is_some() { return 1; },
  }
  ```

---

### M7. 响应方向的 UnconfirmedPdu 被当作"响应"处理

- **文件**：`mms.rs:193-234`
- **现象**：`handle_mms_pdu` 根据 `is_request`（即流方向）决定创建新事务还是匹配已有事务。服务端主动发送的 `InformationReport`（走 TC 方向，`is_request=false`）实际上是一个"请求"语义的 PDU。
- **影响**：当前逻辑将它填入某个已有事务的 response 字段中，导致**错误的事务关联**——一个 Read 请求的事务可能被关联上一个完全不相关的 InformationReport 作为其"响应"。
- **修复方案**：在 `handle_mms_pdu` 中检查 PDU 类型，对 `UnconfirmedPdu` 无论方向都创建独立事务。

---

## 三、低优先级问题

### L1. COTP CR/CC 创建空事务

- **文件**：`mms.rs:337-364`
- **现象**：COTP CR 创建了新事务但 `request`/`response` 均为 None，CC 匹配到该事务并标记 `updated_tc`。
- **影响**：logger 输出时会产生一个 `iec61850_mms { }` 空 JSON 对象——没有 pdu_type、service 等字段。对日志消费者（SIEM）来说，这是无用的噪声数据。
- **修复方案**：考虑为 COTP 连接管理创建专门的 PDU 类型（如 `MmsPdu::CotpConnect` / `MmsPdu::CotpDisconnect`），或在 logger 中过滤空事务。

---

### L2. Probing parser 可能与其他 TPKT 协议冲突

- **文件**：`parser.rs:174-182`
- **现象**：`probe_tpkt` 只检查 version=3、reserved=0、length 在 7~65530 之间。
- **影响**：RDP（端口 3389）、ISDN 等协议也使用 TPKT 封装。虽然注册时限定了端口 102（`mms.rs:521`），但如果用户配置了通配端口检测，会产生误识别。
- **修复方案**：可以进一步检查 COTP 类型字节（TPKT 载荷的第 2 字节应为 0xE0/0xD0/0x80/0xF0 之一）来增强区分度。

---

### L3. Session 层 Data Transfer SPDU 的处理过于简化

- **文件**：`mms_pdu.rs:784-799`
- **现象**：硬编码了 `01 00 01 00`（Give Tokens + Data Transfer，各 length=0）的模式。
- **影响**：ISO 8327 Session Data Transfer SPDU 可以包含可选参数（如 Enclosure Item 参数），长度不一定为 0。使用了参数的合法帧会被拒绝。
- **修复方案**：解析 Give Tokens 和 Data Transfer SPDU 时应根据长度字段跳过参数，而非硬编码 length=0。

---

### L4. ConfirmedService 缺少部分服务类型

- **文件**：`mms_pdu.rs:92-137`
- **现象**：`from_request_tag` 缺少以下标签映射：
  | 标签号 | 服务名 |
  |--------|--------|
  | 7 | DefineScatteredAccess |
  | 8 | GetScatteredAccessAttributes |
  | 9 | DefineNamedVariable |
  | 14 | DefineNamedType |
  | 15 | GetNamedTypeAttributes |
  | 16 | DeleteNamedType |
  | 17-18 | DefineEventCondition / DeleteEventCondition |
  | 21-25 | DefineSemaphore 等 |
  | 46-62 | Event Management 系列 |
- **影响**：这些服务被归类为 `Unknown(tag)`，检测规则无法按服务名匹配。虽然 IEC 61850 中不常用，但作为通用 MMS 解析器不够完整。

---

### L5. `free_tx` 中的线性搜索

- **文件**：`mms.rs:157-172`
- **现象**：对 `VecDeque` 做 O(n) 线性遍历查找 `tx_id`。
- **影响**：在高流量场景下（如大量 InformationReport 或批量 Read），事务队列可能增长到接近 `IEC61850_MMS_MAX_TX`（默认 256），每次释放事务都需线性搜索。
- **修复方案**：由于 Suricata 的事务释放通常按 FIFO 顺序，可以优先检查队列头部（`front()`），大多数情况可以 O(1) 命中。

---

## 四、问题汇总

| 编号 | 严重级别 | 文件 | 摘要 |
|------|---------|------|------|
| S1 | **严重** | mms.rs, parser.rs | COTP 分片重组缺失，大 PDU 必定解析失败 |
| S2 | **严重** | mms_pdu.rs | MMS PDU 标签 class 未验证，可能误解析非 MMS 数据 |
| S3 | **严重** | mms_pdu.rs | Read Request 变量提取只匹配 0xA1，漏掉常用的 0xA0 |
| S4 | **严重** | mms.rs | ConcludeRequest 被标记为完成，请求/响应无法关联 |
| S5 | **严重** | mms.rs, mms_pdu.rs | Session 层 Initiate 参数完全丢失 |
| M1 | 中等 | mms.rs | 状态机不支持 COTP 重连 |
| M2 | 中等 | mms_pdu.rs | is_constructed 标志未验证 |
| M3 | 中等 | mms_pdu.rs | BER INTEGER 不处理有符号值 |
| M4 | 中等 | mms_pdu.rs | BER 不定长编码直接报错 |
| M5 | 中等 | mms_pdu.rs | parse_mms_pdu 静默丢弃 remaining 数据 |
| M6 | 中等 | mms.rs | 事务完成度判断不区分 TS/TC 方向 |
| M7 | 中等 | mms.rs | 响应方向的 UnconfirmedPdu 错误关联到已有事务 |
| L1 | 低 | mms.rs | COTP CR/CC 创建空事务，日志输出噪声 |
| L2 | 低 | parser.rs | Probing parser 与其他 TPKT 协议可能冲突 |
| L3 | 低 | mms_pdu.rs | Session 层 SPDU 解析硬编码 length=0 |
| L4 | 低 | mms_pdu.rs | ConfirmedService 缺少部分服务类型映射 |
| L5 | 低 | mms.rs | free_tx 线性搜索，高流量下有性能隐患 |

---

## 五、建议修复优先级

1. **S1 COTP 分片重组** — 没有它，任何大于单帧的 MMS 响应都会解析失败，这是生产环境中的常见场景
2. **S3 Read Request 变量提取** — 直接影响检测规则对 MMS Read 操作的匹配能力
3. **S2 PDU 标签 class 验证** — 安全性问题，修复简单（加一行判断）
4. **S4 ConcludeRequest 事务关联** — 修复简单，改一行代码
5. **M7 UnconfirmedPdu 事务关联** — 影响 InformationReport 的日志准确性
6. **M1 状态机重连支持** — 增加一条转换规则
7. 其余问题按需修复
