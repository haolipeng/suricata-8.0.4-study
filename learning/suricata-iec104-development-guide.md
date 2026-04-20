# Suricata 8.0.4 IEC 60870-5-104 协议解析器开发全过程

## 一、背景

IEC 60870-5-104（简称 IEC 104）是电力系统 SCADA 远动通信的核心协议，基于 TCP 端口 2404 传输。Suricata 8.0.4 已有 30+ 种应用层协议解析器（含 IEC 61850 MMS 等 ICS 协议），但缺少 IEC 104 支持。

本文记录了在 Suricata 中从零开发 IEC 104 协议解析器的完整过程，涵盖协议识别、帧解析、ASDU 完整解析、检测关键字和 EVE JSON 日志输出。

### 参考模板

开发全程以已有的 IEC 61850 MMS Rust 实现为参考模板：

| 用途 | 参考文件 |
|------|----------|
| 状态机 / FFI | `rust/src/iec61850mms/mms.rs` |
| 检测关键字 | `rust/src/iec61850mms/detect.rs` |
| JSON 日志 | `rust/src/iec61850mms/logger.rs` |
| 框架定义 | `rust/src/applayer.rs` |

### IEC 104 vs IEC 61850 MMS 关键差异

| 维度 | IEC 61850 MMS | IEC 104 |
|------|---------------|---------|
| 封装 | TPKT/COTP/ASN.1 BER | 直接 TCP，固定二进制 |
| 端口 | 102 | 2404 |
| 帧定界 | TPKT 长度字段 | 起始字节 0x68 + 长度字节 |
| 编码 | ASN.1 BER（变长 TLV） | 固定位域，小端序 |
| 事务模型 | 请求-响应配对（invoke_id） | 每帧独立事务 |
| 探测深度 | max_depth: 16 | max_depth: 6 |

---

## 二、文件结构总览

### 新建文件（7 个）

```
rust/src/iec104/
├── mod.rs          26 行    模块导出
├── parser.rs      373 行    APCI 帧解析（0x68 探测 + I/S/U 帧解码）
├── asdu.rs       1390 行    ASDU 完整解析（TypeID、COT、信息对象值）
├── iec104.rs      537 行    状态机、事务管理、C FFI 导出
├── detect.rs      165 行    检测关键字注册（3 个 sticky buffer）
└── logger.rs      301 行    EVE JSON 日志输出
                  ────
                  2792 行    Rust 代码总量

rules/
└── iec104-events.rules      7 条异常检测事件规则
```

### 修改的现有文件（7 个）

| 文件 | 修改内容 |
|------|----------|
| `rust/src/lib.rs` | 添加 `pub mod iec104;` |
| `src/app-layer-protos.h` | 添加 `ALPROTO_IEC104` 枚举值 |
| `src/app-layer.c` | 添加 `AppProtoRegisterProtoString(ALPROTO_IEC104, "iec104")` |
| `src/app-layer-parser.c` | 添加 `SCRegisterIec104Parser()` 调用 |
| `src/detect-engine-register.c` | 添加 `SCDetectIec104Register()` 调用 |
| `src/output.c` | 添加日志回调注册 + EVE 子模块注册（两处） |
| `suricata.yaml.in` | 添加协议配置 + eve-log types 条目（两处） |

---

## 三、IEC 104 协议格式速览

### APDU 帧结构

```
┌──────────┬──────────┬───────────────────────┬────────────┐
│ Start    │ APDU     │ Control Fields        │ ASDU       │
│ 0x68     │ Length   │ (4 bytes)             │ (仅I帧)    │
│ (1 byte) │ (1 byte) │                       │            │
└──────────┴──────────┴───────────────────────┴────────────┘
                       │
                       ├─ I帧: bit0=0  → 含发送/接收序号 + ASDU
                       ├─ S帧: bit0=1, bit1=0 → 仅接收序号
                       └─ U帧: bit0=1, bit1=1 → 连接控制功能
```

### ASDU 结构（中国标准：IOA=3B, COT=2B, CommonAddr=2B）

```
┌──────────┬──────────┬──────────┬──────────┬──────────────────┐
│ TypeID   │ SQ+Num   │ COT      │ Common   │ Information      │
│ (1 byte) │ (1 byte) │ (2 bytes)│ Addr(2B) │ Objects...       │
└──────────┴──────────┴──────────┴──────────┴──────────────────┘
```

---

## 四、核心数据结构设计

### 4.1 APCI 层（parser.rs）

```rust
/// U 帧功能类型
pub enum UFrameFunction {
    StartDtAct,   // STARTDT 激活
    StartDtCon,   // STARTDT 确认
    StopDtAct,    // STOPDT 激活
    StopDtCon,    // STOPDT 确认
    TestFrAct,    // TESTFR 激活
    TestFrCon,    // TESTFR 确认
}

/// 解析后的 APCI 帧
pub enum ApciFrame {
    IFrame { send_seq: u16, recv_seq: u16, asdu_data: Vec<u8> },
    SFrame { recv_seq: u16 },
    UFrame { function: UFrameFunction },
}
```

### 4.2 ASDU 层（asdu.rs）

```rust
/// TypeID 枚举 —— 约 50 种 IEC 104 标准类型
pub enum TypeId {
    // 监视方向（上行）
    M_SP_NA_1 = 1,    // 单点信息
    M_DP_NA_1 = 3,    // 双点信息
    M_ME_NC_1 = 13,   // 短浮点测量值
    M_SP_TB_1 = 30,   // 单点 + CP56Time2a
    // ...共约 50 种

    // 控制方向（下行）
    C_SC_NA_1 = 45,   // 单命令
    C_IC_NA_1 = 100,  // 总召唤
    C_CS_NA_1 = 103,  // 时钟同步
    // ...

    Unknown(u8),      // 未知类型
}

/// 传送原因
pub struct CauseOfTransmission {
    pub cause: u8,        // 原因值（6 bit, 0-47）
    pub negative: bool,   // 肯定/否定确认
    pub test: bool,       // 测试标志
    pub originator: u8,   // 发端地址
}

/// 信息对象值 —— 25+ 种类型
pub enum InformationValue {
    SinglePoint { spi: bool, quality: u8 },
    DoublePoint { dpi: u8, quality: u8 },
    ShortFloat { value: f32, quality: u8 },
    Normalized { value: i16, quality: u8 },
    Scaled { value: i16, quality: u8 },
    SingleCommand { scs: bool, qualifier: u8 },
    Interrogation { qualifier: u8 },
    ClockSync { time: Cp56Time2a },
    // ...共 25+ 种
}

/// 信息对象
pub struct InformationObject {
    pub ioa: u32,                       // 3 字节信息对象地址
    pub value: InformationValue,
    pub timestamp: Option<Timestamp>,   // CP24Time2a 或 CP56Time2a
}

/// 完整 ASDU
pub struct Asdu {
    pub type_id: TypeId,
    pub is_sequence: bool,              // SQ 位
    pub num_objects: u8,
    pub cot: CauseOfTransmission,
    pub common_addr: u16,               // 公共地址
    pub objects: Vec<InformationObject>,
}
```

### 4.3 状态机（iec104.rs）

```rust
/// 事务 —— 每帧一个独立事务
pub struct Iec104Transaction {
    pub tx_id: u64,
    pub apci: ApciFrame,
    pub asdu: Option<Asdu>,         // 仅 I 帧有 ASDU
    pub tx_data: AppLayerTxData,
}

/// 协议状态
pub struct Iec104State {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<Iec104Transaction>,
    request_gap: bool,              // 请求方向数据间隙
    response_gap: bool,             // 响应方向数据间隙
}

/// 异常事件
#[derive(AppLayerEvent)]
pub enum Iec104Event {
    TooManyTransactions,   // 超出 max-tx 限制
    MalformedApci,         // APCI 帧格式错误
    MalformedAsdu,         // ASDU 解析失败
    InvalidTypeId,         // TypeID 不在已知范围
    InvalidCot,            // COT 值非法
    InvalidApduLength,     // APDU 长度超规范
    UnexpectedUFrame,      // U 帧多功能位同时置位
}
```

---

## 五、逐层实现详解

### 5.1 协议探测（parser.rs）

Suricata 通过 probe 函数判断 TCP 流是否为 IEC 104 协议。判断逻辑非常简单：

```rust
pub fn probe_iec104(input: &[u8]) -> bool {
    if input.len() < 2 {
        return false;
    }
    // 起始字节必须是 0x68，APDU 长度在 [4, 253] 之间
    input[0] == IEC104_START && input[1] >= APDU_MIN_LEN && input[1] <= APDU_MAX_LEN
}
```

注册时设置 `max_depth: 6`，意味着 Suricata 只需检查前 6 字节就能判断协议。

### 5.2 APCI 帧解析（parser.rs）

使用 nom7 streaming parser 解析二进制帧：

```rust
pub fn parse_apci_frame(i: &[u8]) -> IResult<&[u8], ApciFrame> {
    // 1. 验证起始字节 0x68
    let (i, start) = le_u8(i)?;
    if start != IEC104_START { return Err(...); }

    // 2. 读取 APDU 长度
    let (i, apdu_len) = le_u8(i)?;
    if apdu_len < APDU_MIN_LEN { return Err(...); }

    // 3. 取出 apdu_len 字节的有效载荷
    let (remaining, apdu_payload) = take(apdu_len as usize)(i)?;

    // 4. 根据控制域第 1 字节判断帧类型
    let ctrl1 = apdu_payload[0];
    let frame = if ctrl1 & 0x01 == 0 {
        // I 帧：bit0=0
        // 提取发送/接收序号（各 15 bit）和 ASDU 数据
        ApciFrame::IFrame { send_seq, recv_seq, asdu_data }
    } else if ctrl1 & 0x03 == 0x01 {
        // S 帧：bit0=1, bit1=0
        ApciFrame::SFrame { recv_seq }
    } else {
        // U 帧：bit0=1, bit1=1
        // 根据高位 bit 识别功能类型
        ApciFrame::UFrame { function }
    };

    Ok((remaining, frame))
}
```

**关键细节**：序号提取使用位运算，send_seq 和 recv_seq 各占 15 bit：
```rust
let send_seq = ((ctrl1 as u16) >> 1) | ((ctrl2 as u16) << 7);
let recv_seq = ((ctrl3 as u16) >> 1) | ((ctrl4 as u16) << 7);
```

### 5.3 ASDU 解析（asdu.rs）

这是代码量最大的模块（1390 行），完整解析所有标准 TypeID。

#### ASDU 头部解析

```rust
pub fn parse_asdu_header(i: &[u8])
    -> IResult<&[u8], (TypeId, bool, u8, CauseOfTransmission, u16)>
{
    let (i, type_id_raw) = le_u8(i)?;       // TypeID (1B)
    let (i, sq_num) = le_u8(i)?;             // SQ(1bit) + NumObj(7bit)
    let is_sequence = (sq_num & 0x80) != 0;
    let num_objects = sq_num & 0x7F;

    let (i, cot_byte1) = le_u8(i)?;          // COT 第 1 字节
    let (i, originator) = le_u8(i)?;          // COT 第 2 字节（发端地址）
    let cause = cot_byte1 & 0x3F;             // 低 6 位为原因
    let negative = (cot_byte1 & 0x40) != 0;   // P/N 位
    let test = (cot_byte1 & 0x80) != 0;       // T 位

    let (i, common_addr) = le_u16(i)?;        // 公共地址 (2B)
    // ...
}
```

#### 信息对象解析 —— SQ=0 与 SQ=1 两种模式

```rust
pub fn parse_information_objects<'a>(
    i: &'a [u8], type_id: &TypeId, is_sequence: bool, num_objects: u8,
) -> IResult<&'a [u8], Vec<InformationObject>> {

    if is_sequence && num_objects > 0 {
        // SQ=1：首个 IOA + 连续信息元素（IOA 自动递增）
        let (rem, base_ioa) = parse_ioa(input)?;
        for idx in 0..num_objects {
            // 每个对象的 IOA = base_ioa + idx
            let value = parse_information_element(input, type_id)?;
            objects.push(InformationObject { ioa: base_ioa + idx, value, timestamp });
        }
    } else {
        // SQ=0：每个对象独立携带 IOA
        for _ in 0..num_objects {
            let ioa = parse_ioa(input)?;
            let value = parse_information_element(input, type_id)?;
            objects.push(InformationObject { ioa, value, timestamp });
        }
    }
}
```

#### 按 TypeID 分发解析

`parse_information_element` 根据 TypeID 分发到不同的底层解析函数：

```rust
fn parse_information_element<'a>(i: &'a [u8], type_id: &TypeId)
    -> IResult<&'a [u8], InformationValue>
{
    match type_id {
        // 单点信息 —— 1 字节 SIQ
        TypeId::M_SP_NA_1 | TypeId::M_SP_TA_1 | TypeId::M_SP_TB_1 => parse_siq(i),
        // 双点信息
        TypeId::M_DP_NA_1 | ... => parse_diq(i),
        // 短浮点 —— 4 字节 IEEE754 + 1 字节 QDS
        TypeId::M_ME_NC_1 | ... => parse_float_qds(i),
        // 单命令
        TypeId::C_SC_NA_1 | ... => parse_sco(i),
        // 总召唤
        TypeId::C_IC_NA_1 => { let qoi = le_u8(i)?; Ok(Interrogation { qualifier: qoi }) },
        // 时钟同步 —— 7 字节 CP56Time2a
        TypeId::C_CS_NA_1 => { let time = parse_cp56time2a(i)?; Ok(ClockSync { time }) },
        // ...约 50 种类型
    }
}
```

#### 时标解析

```rust
/// CP56Time2a —— 7 字节完整时标
pub fn parse_cp56time2a(i: &[u8]) -> IResult<&[u8], Cp56Time2a> {
    let (i, ms) = le_u16(i)?;           // 毫秒 (0-59999)
    let (i, min_byte) = le_u8(i)?;      // 分钟 + IV 位
    let (i, hour_byte) = le_u8(i)?;     // 小时 + SU 位
    let (i, day_byte) = le_u8(i)?;      // 日 + 星期
    let (i, month_byte) = le_u8(i)?;    // 月
    let (i, year_byte) = le_u8(i)?;     // 年 (2000+)
    // 位域提取...
}
```

### 5.4 状态机核心逻辑（iec104.rs）

#### 事务模型：每帧独立事务

IEC 104 是双向对等协议，不同于 HTTP 的请求-响应配对。被控站主动上报监视信息，控制站下发命令，无法通过 invoke_id 配对。因此采用**每个 APDU 帧创建一个独立事务**，`tx_get_progress` 始终返回 1。

```rust
unsafe extern "C" fn iec104_tx_get_alstate_progress(
    _tx: *mut c_void, _direction: u8,
) -> c_int {
    return 1;  // 每帧即完成
}
```

#### parse_frames 核心方法

这是整个解析器的核心循环，处理数据流中的连续帧：

```rust
fn parse_frames(&mut self, input: &[u8], is_request: bool) -> AppLayerResult {
    // 1. 空数据直接返回
    if input.is_empty() { return AppLayerResult::ok(); }

    // 2. Gap 恢复：等待下一个有效的 0x68 起始字节
    if is_request && self.request_gap {
        if !parser::probe_iec104(input) { return AppLayerResult::ok(); }
        self.request_gap = false;
    }

    // 3. 循环解析帧
    let mut start = input;
    while !start.is_empty() {
        match parser::parse_apci_frame(start) {
            Ok((rem, frame)) => {
                let mut tx = self.new_tx();

                // 4. I 帧：解析 ASDU 并验证
                if let ApciFrame::IFrame { asdu_data, .. } = &frame {
                    match asdu::parse_asdu(asdu_data) {
                        Ok((_, asdu)) => {
                            if !asdu.type_id.is_valid() {
                                tx.tx_data.set_event(Iec104Event::InvalidTypeId as u8);
                            }
                            if !asdu.cot.is_valid() {
                                tx.tx_data.set_event(Iec104Event::InvalidCot as u8);
                            }
                            tx.asdu = Some(asdu);
                        }
                        Err(_) => {
                            tx.tx_data.set_event(Iec104Event::MalformedAsdu as u8);
                        }
                    }
                }

                tx.apci = frame;
                self.transactions.push_back(tx);
                start = rem;  // 继续解析下一帧
            }
            Err(nom::Err::Incomplete(_)) => {
                // 5. 数据不完整，告知 Suricata 需要更多数据
                let consumed = input.len() - start.len();
                return AppLayerResult::incomplete(consumed as u32, (start.len() + 1) as u32);
            }
            Err(_) => {
                // 6. 格式错误，设置事件并中止
                tx.tx_data.set_event(Iec104Event::MalformedApci as u8);
                return AppLayerResult::err();
            }
        }
    }
    AppLayerResult::ok()
}
```

### 5.5 检测关键字（detect.rs）

注册 3 个 sticky buffer，允许在 Suricata 规则中使用 `content` 匹配：

| 关键字 | 匹配内容 | 示例值 |
|--------|----------|--------|
| `iec104.frame_type` | 帧类型字符串 | `"I"`, `"S"`, `"U"` |
| `iec104.typeid` | ASDU 类型名 | `"M_SP_NA_1"`, `"C_IC_NA_1"` |
| `iec104.cot` | 传送原因名 | `"spontaneous"`, `"activation"` |

每个 sticky buffer 的注册遵循固定模式：

```rust
// 1. 定义 setup 函数 —— 在规则解析时调用
unsafe extern "C" fn iec104_frame_type_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC104) != 0 { return -1; }
    if SCDetectBufferSetActiveList(de, s, G_IEC104_FRAME_TYPE_BUFFER_ID) < 0 { return -1; }
    return 0;
}

// 2. 定义 get 函数 —— 在检测时调用，返回要匹配的内容
unsafe extern "C" fn iec104_frame_type_get(
    tx: *const c_void, _flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, Iec104Transaction);
    let frame_type = tx.apci.frame_type_str();  // 返回 "I"/"S"/"U"
    *len = frame_type.len() as u32;
    *buf = frame_type.as_ptr();
    return true;
}

// 3. 在 SCDetectIec104Register 中注册
let kw = SigTableElmtStickyBuffer {
    name: String::from("iec104.frame_type"),
    desc: String::from("IEC 104 frame type content modifier"),
    url: String::from("/rules/iec104-keywords.html#frame-type"),
    setup: iec104_frame_type_setup,
};
helper_keyword_register_sticky_buffer(&kw);
G_IEC104_FRAME_TYPE_BUFFER_ID = SCDetectHelperBufferMpmRegister(
    b"iec104.frame_type\0".as_ptr() as *const libc::c_char,
    b"IEC 104 frame type\0".as_ptr() as *const libc::c_char,
    ALPROTO_IEC104,
    STREAM_TOSERVER | STREAM_TOCLIENT,
    Some(iec104_frame_type_get),
);
```

规则示例：
```
alert tcp any any -> any 2404 (msg:"IEC104 Control Command";
    iec104.typeid; content:"C_SC_NA_1";
    iec104.cot; content:"activation";
    sid:1; rev:1;)
```

### 5.6 EVE JSON 日志输出（logger.rs）

#### 日志回调入口

```rust
#[no_mangle]
pub unsafe extern "C" fn SCIec104LoggerLog(
    tx: *const c_void, js: *mut c_void,
) -> bool {
    let tx = cast_pointer!(tx, Iec104Transaction);
    let js = cast_pointer!(js, JsonBuilder);
    log_iec104(tx, js).is_ok()
}
```

#### 日志结构

```rust
fn log_iec104(tx: &Iec104Transaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("iec104")?;
    js.set_string("frame_type", tx.apci.frame_type_str())?;

    // APCI 字段
    js.open_object("apci")?;
    match &tx.apci {
        ApciFrame::IFrame { send_seq, recv_seq, .. } => {
            js.set_uint("send_seq", *send_seq as u64)?;
            js.set_uint("recv_seq", *recv_seq as u64)?;
        }
        ApciFrame::SFrame { recv_seq } => {
            js.set_uint("recv_seq", *recv_seq as u64)?;
        }
        ApciFrame::UFrame { function } => {
            js.set_string("function", function.as_str())?;
        }
    }
    js.close()?;

    // ASDU（仅 I 帧）
    if let Some(ref asdu) = tx.asdu {
        log_asdu(asdu, js)?;
    }
    js.close()?;
    Ok(())
}
```

#### 输出示例

I 帧（总召唤命令）：
```json
{
  "event_type": "iec104",
  "iec104": {
    "frame_type": "I",
    "apci": { "send_seq": 0, "recv_seq": 1 },
    "asdu": {
      "type_id": 100, "type_name": "C_IC_NA_1",
      "sq": false, "num_objects": 1,
      "cot": {
        "cause": 6, "cause_name": "activation",
        "negative": false, "test": false, "originator": 0
      },
      "common_addr": 37133,
      "objects": [{ "ioa": 0, "value": { "qoi": 20 } }]
    }
  }
}
```

U 帧：
```json
{ "event_type": "iec104", "iec104": { "frame_type": "U", "apci": { "function": "STARTDT_ACT" } } }
```

S 帧：
```json
{ "event_type": "iec104", "iec104": { "frame_type": "S", "apci": { "recv_seq": 10 } } }
```

---

## 六、C 集成点详解

Suricata 的核心框架是 C 语言，Rust 编写的解析器必须通过以下 7 个集成点接入。

### 6.1 协议枚举注册

在 `src/app-layer-protos.h` 中添加枚举值：

```c
    ALPROTO_IEC61850_MMS,
    ALPROTO_IEC104,         // ← 新增

    // signature-only
    ALPROTO_HTTP,
```

### 6.2 协议字符串映射

在 `src/app-layer.c` 的 `AppLayerSetupProtoStrings()` 中注册字符串：

```c
    AppProtoRegisterProtoString(ALPROTO_IEC61850_MMS, "iec61850-mms");
    AppProtoRegisterProtoString(ALPROTO_IEC104, "iec104");  // ← 新增
    AppProtoRegisterProtoString(ALPROTO_HTTP, "http");
```

> **踩坑记录**：这一步最初遗漏，导致 `StringToAppProto()` 遍历 `g_alproto_strings[]` 数组时遇到 NULL 指针触发段错误（SIGSEGV）。详见第八节。

### 6.3 解析器注册

在 `src/app-layer-parser.c` 的 `AppLayerParserRegisterProtocolParsers()` 中添加调用：

```c
    SCRegisterIec61850MmsParser();
    SCRegisterIec104Parser();   // ← 新增
```

### 6.4 检测引擎注册

在 `src/detect-engine-register.c` 的 `SigTableSetup()` 中添加：

```c
    SCDetectIec61850MmsRegister();
    SCDetectIec104Register();   // ← 新增
```

### 6.5 日志回调注册

在 `src/output.c` 的 `OutputRegisterRootLoggers()` 中注册底层回调：

```c
    RegisterSimpleJsonApplayerLogger(
            ALPROTO_IEC104, (EveJsonSimpleTxLogFunc)SCIec104LoggerLog, "iec104");
```

### 6.6 EVE 子模块注册

在 `src/output.c` 的 `OutputRegisterLoggers()` 中注册 EVE 输出子模块：

```c
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonIec104Log", "eve-log.iec104",
            OutputJsonLogInitSub, ALPROTO_IEC104, JsonGenericDirPacketLogger,
            JsonLogThreadInit, JsonLogThreadDeinit);
```

> **踩坑记录**：这一步最初遗漏。仅有 6.5 的 `RegisterSimpleJsonApplayerLogger` 不够——它只存储函数指针，必须通过 `OutputRegisterTxSubModule` 注册 EVE 子模块，日志框架才会为每个事务调用日志回调。没有这一步，`event_type: iec104` 的独立事务日志不会生成（只会在 alert 的 metadata 中附带）。

### 6.7 YAML 配置

在 `suricata.yaml.in` 中两处添加：

**协议配置**（app-layer.protocols 段）：
```yaml
    iec104:
      enabled: yes
      detection-ports:
        dp: 2404
```

**EVE 日志类型**（eve-log.types 段）：
```yaml
        - iec104
```

### 6.8 Rust 端的 C FFI 导出

`SCRegisterIec104Parser()` 是 Rust 到 C 的主要桥梁，通过 `RustParser` 结构体一次性注册所有回调：

```rust
#[no_mangle]
pub unsafe extern "C" fn SCRegisterIec104Parser() {
    let parser = RustParser {
        name: b"iec104\0".as_ptr() as *const c_char,
        default_port: CString::new("[2404]").unwrap().as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(iec104_probing_parser),     // 协议探测
        probe_tc: Some(iec104_probing_parser),
        min_depth: 0,
        max_depth: 6,                               // 探测深度
        state_new: iec104_state_new,                // 创建状态
        state_free: iec104_state_free,              // 释放状态
        tx_free: iec104_state_tx_free,              // 释放事务
        parse_ts: iec104_parse_request,             // 解析请求
        parse_tc: iec104_parse_response,            // 解析响应
        get_tx_count: iec104_state_get_tx_count,
        get_tx: iec104_state_get_tx,
        tx_comp_st_ts: 1,                           // 事务完成状态
        tx_comp_st_tc: 1,
        tx_get_progress: iec104_tx_get_alstate_progress,
        get_eventinfo: Some(Iec104Event::get_event_info),
        get_eventinfo_byid: Some(Iec104Event::get_event_info_by_id),
        get_tx_iterator: Some(state_get_tx_iterator::<Iec104State, Iec104Transaction>),
        get_tx_data: iec104_get_tx_data,
        get_state_data: iec104_get_state_data,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,    // 支持 gap 处理
        // ...
    };

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(...) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_IEC104 = alproto;
        if SCAppLayerParserConfParserEnabled(...) != 0 {
            AppLayerRegisterParser(&parser, alproto);
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_IEC104);
    }
}
```

---

## 七、事件规则

`rules/iec104-events.rules` 定义了 7 条异常检测规则：

```
alert iec104 any any -> any any (msg:"SURICATA IEC104 too many transactions";
    app-layer-event:iec104.too_many_transactions; sid:2260001; rev:1;)

alert iec104 any any -> any any (msg:"SURICATA IEC104 malformed APCI frame";
    app-layer-event:iec104.malformed_apci; sid:2260002; rev:1;)

alert iec104 any any -> any any (msg:"SURICATA IEC104 malformed ASDU";
    app-layer-event:iec104.malformed_asdu; sid:2260003; rev:1;)

alert iec104 any any -> any any (msg:"SURICATA IEC104 invalid type ID";
    app-layer-event:iec104.invalid_type_id; sid:2260004; rev:1;)

alert iec104 any any -> any any (msg:"SURICATA IEC104 invalid cause of transmission";
    app-layer-event:iec104.invalid_cot; sid:2260005; rev:1;)

alert iec104 any any -> any any (msg:"SURICATA IEC104 invalid APDU length";
    app-layer-event:iec104.invalid_apdu_length; sid:2260006; rev:1;)

alert iec104 any any -> any any (msg:"SURICATA IEC104 unexpected U-frame function";
    app-layer-event:iec104.unexpected_u_frame; sid:2260007; rev:1;)
```

事件名称通过 `#[derive(AppLayerEvent)]` 宏自动从 Rust 枚举变体名生成（CamelCase → snake_case）。

---

## 八、踩坑记录

### 8.1 段错误：缺少协议字符串注册

**现象**：编译安装后 `suricata --list-app-layer-protos` 段错误。

**原因**：`src/app-layer.c` 中的 `AppLayerSetupProtoStrings()` 负责为每个静态协议枚举值注册名称字符串。遗漏了 `ALPROTO_IEC104`，导致 `g_alproto_strings[ALPROTO_IEC104].str` 为 NULL。后续 `StringToAppProto()` 遍历数组执行 `strcmp(proto_name, NULL)` 时触发 SIGSEGV。

**修复**：在 `app-layer.c` 中添加 `AppProtoRegisterProtoString(ALPROTO_IEC104, "iec104")`。

**教训**：添加静态协议枚举值时，除了修改 `app-layer-protos.h`，还必须在 `app-layer.c` 中注册对应的字符串映射。

### 8.2 事务日志不生成

**现象**：协议识别成功（flow 记录中 `app_proto: iec104`），规则也能触发告警，但 eve.json 中没有 `event_type: iec104` 的独立事务日志。

**原因**：`RegisterSimpleJsonApplayerLogger()` 仅将日志函数指针存入 `simple_json_applayer_loggers[]` 数组，但这个数组只在 `JsonGenericLogger` 被调用时才使用。而 `JsonGenericLogger` 本身必须通过 `OutputRegisterTxSubModule` 注册为 EVE 子模块后才会被日志框架触发。

```
RegisterSimpleJsonApplayerLogger  →  存储函数指针（底层）
OutputRegisterTxSubModule         →  注册 EVE 子模块（驱动层）
                                      ↓
                                 日志框架调用 JsonGenericLogger
                                      ↓
                                 JsonGenericLogger 查找并调用函数指针
```

**修复**：在 `output.c` 的 `OutputRegisterLoggers()` 中添加 `OutputRegisterTxSubModule` 调用。同时在 `suricata.yaml.in` 的 `eve-log.types` 中添加 `- iec104`。

**教训**：Suricata 的日志系统是两层注册架构，两层缺一不可。

### 8.3 Rust 生命周期错误

**现象**：`parse_information_element` 等函数编译报错 `missing lifetime specifier`。

**原因**：函数有多个引用参数 `(i: &[u8], type_id: &TypeId)` 时，Rust 的生命周期省略规则无法推断返回值 `IResult<&[u8], ...>` 中的 `&[u8]` 应该关联哪个输入参数的生命周期。

**修复**：显式标注生命周期：
```rust
fn parse_information_element<'a>(i: &'a [u8], type_id: &TypeId)
    -> IResult<&'a [u8], InformationValue>
```

### 8.4 PCAP 校验和问题

**现象**：用 pcap 回放测试时无告警和事务日志。

**原因**：pcap 中的数据包校验和无效，Suricata 默认丢弃无效校验和的包。

**修复**：运行时加 `-k none` 参数禁用校验和检查：
```bash
suricata -r test.pcap -k none ...
```

---

## 九、测试验证

### 9.1 单元测试

```bash
cargo test --lib iec104
```

共 30 个测试，覆盖：
- **parser.rs**（8 个）：探测、I/S/U 帧解析、不完整数据、多帧连续、错误起始字节
- **asdu.rs**（8 个）：TypeId 映射、COT 解析、ASDU 头部、单点/浮点/命令/总召唤解析、SQ 模式、CP56Time2a
- **iec104.rs**（6 个）：事务创建、I 帧 ASDU 解析、多帧处理、不完整帧、gap 恢复

### 9.2 PCAP 回放测试

```bash
# 准备规则
cat > /tmp/iec104-test.rules << 'EOF'
alert tcp any any -> any 2404 (msg:"IEC104 I-Frame"; iec104.frame_type; content:"I"; sid:9000001; rev:1;)
alert tcp any any -> any 2404 (msg:"IEC104 U-Frame"; iec104.frame_type; content:"U"; sid:9000002; rev:1;)
alert tcp any any -> any 2404 (msg:"IEC104 S-Frame"; iec104.frame_type; content:"S"; sid:9000003; rev:1;)
alert tcp any any -> any 2404 (msg:"IEC104 Interrogation"; iec104.typeid; content:"C_IC_NA_1"; sid:9000004; rev:1;)
alert tcp any any -> any 2404 (msg:"IEC104 Spontaneous"; iec104.cot; content:"spontaneous"; sid:9000005; rev:1;)
EOF

# 运行
suricata -r iec104.pcap -S /tmp/iec104-test.rules -l /tmp/output/ -k none
```

### 9.3 测试结果

使用 `iec60780-5-104.pcap`（147 包，端口 2404）的实际测试结果：

| 验证项 | 结果 |
|--------|------|
| 协议识别 | flow 记录 `"app_proto":"iec104"` |
| EVE 事务日志 | 52 条 `"event_type":"iec104"` |
| 规则告警 | 71 条告警 |
| I 帧 | 19 条（含完整 ASDU 解析） |
| S 帧 | 17 条 |
| U 帧 | 16 条 |
| typeid 关键字 | 命中：C_IC_NA_1(3次)、M_SP_NA_1(1次) |
| cot 关键字 | 命中：activation(14次)、spontaneous(1次) |

---

## 十、开发检查清单

为后续开发其他 Suricata 应用层协议提供参考：

### Rust 端（6 个文件）

- [ ] `mod.rs` —— 模块导出声明
- [ ] `parser.rs` —— 协议探测函数 + 帧/消息解析（nom7）
- [ ] 数据结构文件 —— 协议特定数据类型和枚举
- [ ] 主文件（如 `iec104.rs`）—— State / Transaction / Event + C FFI 导出 + `SCRegisterXxxParser()`
- [ ] `detect.rs` —— sticky buffer 注册（setup + get + register）
- [ ] `logger.rs` —— JsonBuilder EVE JSON 输出 + `#[no_mangle]` 导出

### C 端（7 个集成点）

- [ ] `rust/src/lib.rs` —— `pub mod xxx;`
- [ ] `src/app-layer-protos.h` —— `ALPROTO_XXX` 枚举值
- [ ] `src/app-layer.c` —— `AppProtoRegisterProtoString(ALPROTO_XXX, "xxx")`
- [ ] `src/app-layer-parser.c` —— `SCRegisterXxxParser()`
- [ ] `src/detect-engine-register.c` —— `SCDetectXxxRegister()`
- [ ] `src/output.c` —— `RegisterSimpleJsonApplayerLogger(...)` + `OutputRegisterTxSubModule(...)`
- [ ] `suricata.yaml.in` —— 协议配置段 + eve-log.types 条目

### 验证

- [ ] `cargo build` 无错误
- [ ] `cargo test --lib xxx` 全部通过
- [ ] `suricata --list-app-layer-protos` 显示新协议
- [ ] PCAP 回放产生 `event_type: xxx` 事务日志
- [ ] 测试规则正确触发告警
