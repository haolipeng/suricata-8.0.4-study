# Suricata Rust 协议解析插件开发指南

> 本文档基于 `rust/src/iec61850mms/` 的实现，整理使用 Rust 为 Suricata 开发新协议解析插件的完整流程。

## 1. 概述

Suricata 的应用层协议解析插件由两部分组成：

- **Rust 端**：实现协议解析逻辑、状态机、事务管理、检测关键字和 JSON 日志输出，通过 `extern "C"` FFI 函数暴露给 C 引擎。
- **C 端胶水代码**：在 Suricata 核心代码中注册协议枚举值、协议字符串和日志模块，使引擎能够识别和调度 Rust 端的解析器。

整体调用链路：

```
TCP 数据流 → Suricata 引擎（C）→ FFI 回调 → Rust 解析器
                                              ↓
                                     状态机 + 事务管理
                                              ↓
                                     检测关键字 / EVE JSON 日志
```

### 1.1 使用 Rust 开发 Suricata 插件的大致流程（速览）

如果你想先有一张“路线图”，可以按下面 6 个阶段推进。每个阶段都对应本文后续章节的详细内容。

1. **选定协议与边界**
   - 明确协议层级（L7 应用层）、传输层（TCP/UDP）、是否有请求/响应模型。
   - 决定事务粒度：一问一答为一个事务，还是“每个独立 PDU 一个事务”。
   - 先定义最小可用目标（MVP）：先识别协议 + 产出基础日志，再逐步补全字段和检测能力。

2. **搭建 Rust 侧骨架**
   - 在 `rust/src/<proto>/` 建模块目录与 `mod.rs`，在 `rust/src/lib.rs` 暴露模块。
   - 定义 `State` / `Transaction` / `Event` 三个核心结构。
   - 实现底层 parser（建议 `nom7` streaming），先保证“不断流解析”。

3. **打通解析主链路（最关键）**
   - 实现 `parse_ts` / `parse_tc`：处理输入、切帧、生成事务、推进状态机。
   - 处理异常路径：`Incomplete`、`gap`、畸形数据、事务上限。
   - 实现 `tx_get_progress` 与 `tx_comp_st_ts/tc`，让引擎知道事务何时“完成”。

4. **完成 FFI 注册与 C 侧接入**
   - Rust 端实现 `SCRegisterXxxParser()`，填充 `RustParser` 回调表。
   - C 端完成“四件套”注册：协议枚举、协议字符串、parser 注册调用、output 日志注册。
   - 调用 `SCAppLayerParserRegisterLogger(...)`，否则 eve logger 不会触发。

5. **补充能力：规则与日志**
   - 在 `detect.rs` 注册 sticky buffer，暴露可匹配字段。
   - 在 `logger.rs` 输出 EVE JSON，确保字段稳定、命名清晰、可长期维护。
   - （可选）增加 frame/state 名称映射，便于规则和调试。

6. **验证与交付**
   - 最少做 4 类验证：协议识别、事务创建、规则命中、EVE 输出。
   - 加入异常场景：分片、乱序/丢包（gap）、非法输入、超大事务数。
   - 修改枚举或 FFI 后做完整重编译，并重新生成 `rust-bindings.h`。

### 1.2 推荐迭代节奏（避免一次做太多）

建议按“先活、再准、再全”的顺序：

- **第 1 轮（可运行）**：能识别协议、能创建事务、能打印最小日志。
- **第 2 轮（可检测）**：补关键字段提取 + sticky buffer + 基础规则。
- **第 3 轮（可上线）**：补齐异常处理、性能边界、回归测试和文档。

这样可以尽早看到端到端结果，减少“写了很多但不知道哪里断了”的排查成本。

## 2. 目录与文件结构

以 `rust/src/iec61850mms/` 为例，当前包含以下 9 个文件：

| 文件 | 职责 |
|------|------|
| `mod.rs` | 模块声明入口，声明子模块的可见性（`pub mod` / `mod`） |
| `mms.rs` | **核心文件**：定义 State/Transaction/Event，实现状态机、请求/响应解析、所有 FFI 导出函数、协议注册函数 |
| `parser.rs` | 底层帧解析器（TPKT/COTP），使用 `nom` 库实现流式解析 |
| `mms_pdu.rs` | MMS PDU 解析入口，负责 BER 解码并构造上层 PDU |
| `mms_types.rs` | MMS 协议数据结构与枚举定义（PDU、服务类型、对象名等） |
| `ber.rs` | BER（Basic Encoding Rules）通用编解码函数 |
| `session.rs` | OSI Session/Presentation 层解包，从封装中提取 MMS 载荷 |
| `detect.rs` | 检测关键字注册（sticky buffer），供 Suricata 规则引擎使用 |
| `logger.rs` | EVE JSON 日志输出，将事务数据序列化为 JSON |

`mod.rs` 的典型内容：

```rust
mod ber;
pub mod detect;
pub mod logger;
pub mod mms;
mod mms_pdu;
mod mms_types;
mod parser;
mod session;
```

需要被 C 端调用的模块标记为 `pub mod`，纯内部模块用 `mod`。

## 3. Rust 端开发步骤

### 3.1 创建模块目录和 `mod.rs`

1. 在 `rust/src/` 下创建以协议名命名的目录，如 `rust/src/iec61850mms/`。
2. 创建 `mod.rs`，声明所有子模块。
3. 在 `rust/src/lib.rs` 中添加一行 `pub mod iec61850mms;`（参考 `lib.rs:129`）。

### 3.2 定义核心数据结构

在主文件（如 `mms.rs`）中定义以下核心类型：

#### 3.2.1 连接状态枚举

```rust
// 参考 mms.rs:50-59
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum MmsConnState {
    #[default]
    Idle,
    CotpPending,
    CotpEstablished,
    AwaitInitResponse,
    MmsAssociated,
    Concluding,
    Closed,
}
```

定义协议生命周期内的所有合法状态。同时需要定义驱动状态转换的事件枚举：

```rust
// 参考 mms.rs:63-72
#[derive(Debug)]
enum MmsConnEvent {
    CotpCr,          // 收到 COTP Connection Request
    CotpCc,          // 收到 COTP Connection Confirm
    CotpDr,          // 收到 COTP Disconnect Request（任何状态均可转 Closed）
    MmsInitReq,      // 收到 MMS Initiate-Request
    MmsInitResp,     // 收到 MMS Initiate-Response
    MmsData,         // 收到普通数据 PDU（Confirmed/Unconfirmed 等）
    MmsConcludeReq,  // 收到 MMS Conclude-Request
    MmsConcludeResp, // 收到 MMS Conclude-Response
}
```

#### 3.2.2 应用层事件枚举

```rust
// 参考 mms.rs:76-80
#[derive(AppLayerEvent)]
enum Iec61850MmsEvent {
    TooManyTransactions,
    MalformedData,
    ProtocolStateViolation,
}
```

使用 `#[derive(AppLayerEvent)]` 派生宏自动生成 `get_event_info` 和 `get_event_info_by_id` 函数，供 Suricata 规则中的 `app-layer-event` 关键字使用。

#### 3.2.3 Transaction 结构

```rust
// 参考 mms.rs:82-111
pub struct MmsTransaction {
    tx_id: u64,
    pub pdu: Option<MmsPdu>,
    pub is_request: bool,
    tx_data: AppLayerTxData,
}

impl Transaction for MmsTransaction {
    fn id(&self) -> u64 { self.tx_id }
}
```

当前实现中，每个事务对应一个独立 PDU（请求和响应不再按 invoke_id 合并为同一事务）。`is_request` 用于标记方向。`tx_data: AppLayerTxData` 是框架要求的字段，用于存储事件、日志状态等元数据。必须实现 `Transaction` trait。

#### 3.2.4 State 结构

```rust
// 参考 mms.rs:114-133
#[derive(Default)]
pub struct MmsState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<MmsTransaction>,
    request_gap: bool,
    response_gap: bool,
    conn_state: MmsConnState,
    ts_cotp_buf: Vec<u8>,
    tc_cotp_buf: Vec<u8>,
}

impl State<MmsTransaction> for MmsState {
    fn get_transaction_count(&self) -> usize { self.transactions.len() }
    fn get_transaction_by_index(&self, index: usize) -> Option<&MmsTransaction> {
        self.transactions.get(index)
    }
}
```

State 持有整个连接的解析状态，包括事务队列和状态机。`state_data: AppLayerStateData` 是框架要求的字段。必须实现 `State<T>` trait。

### 3.3 实现协议帧解析器

在 `parser.rs` 中使用 `nom` 库实现底层帧的流式解析。

关键模式（参考 `parser.rs`）：

```rust
use nom7::bytes::streaming::take;
use nom7::number::streaming::be_u16;
use nom7::IResult;

// 解析帧头
pub fn parse_tpkt_header(i: &[u8]) -> IResult<&[u8], TpktHeader> { ... }

// 解析完整帧（头 + 载荷）
pub fn parse_tpkt_cotp_frame(i: &[u8]) -> IResult<&[u8], TpktCotpFrame<'_>> { ... }

// 探测函数：快速判断输入是否像目标协议
pub fn probe_tpkt(input: &[u8]) -> bool { ... }
```

要点：
- 使用 `streaming` 模式的 nom 解析器，当数据不足时自动返回 `Incomplete`。
- 探测函数（probe）不做完整解析，只检查前几个字节的特征（如魔数、版本号）。
- 帧结构体使用 `&'a [u8]` 借用载荷数据，避免拷贝。

### 3.4 实现状态机与请求/响应解析

在 State 的 `impl` 块中实现核心解析逻辑（参考 `mms.rs:136-446`）：

#### 状态机转换

```rust
// 参考 mms.rs:161-181
fn advance_state(&mut self, event: MmsConnEvent) -> bool {
    let next = match (&self.conn_state, &event) {
        (MmsConnState::Idle, MmsConnEvent::CotpCr) => MmsConnState::CotpPending,
        (MmsConnState::CotpPending, MmsConnEvent::CotpCc) => MmsConnState::CotpEstablished,
        (MmsConnState::CotpEstablished, MmsConnEvent::MmsInitReq) => MmsConnState::AwaitInitResponse,
        (MmsConnState::Idle, MmsConnEvent::MmsInitReq) => MmsConnState::AwaitInitResponse,
        (MmsConnState::AwaitInitResponse, MmsConnEvent::MmsInitResp) => MmsConnState::MmsAssociated,
        (MmsConnState::MmsAssociated, MmsConnEvent::MmsData) => MmsConnState::MmsAssociated,
        (MmsConnState::MmsAssociated, MmsConnEvent::MmsConcludeReq) => MmsConnState::Concluding,
        (MmsConnState::Concluding, MmsConnEvent::MmsConcludeResp) => MmsConnState::Closed,
        (_, MmsConnEvent::CotpDr) => MmsConnState::Closed,
        _ => return false,  // 非法转换
    };
    self.conn_state = next;
    true
}
```

#### 解析入口

```rust
// 参考 mms.rs:369-430
fn parse_frames(&mut self, input: &[u8], is_request: bool) -> AppLayerResult {
    // gap 恢复：探测输入是否从合法 TPKT 头开始
    if is_request && self.request_gap {
        if !parser::probe_tpkt(input) { return AppLayerResult::ok(); }
        self.request_gap = false;
    }
    // ...（响应方向同理）

    let mut start = input;
    while !start.is_empty() {
        match parser::parse_tpkt_cotp_frame(start) {
            Ok((rem, frame)) => {
                // 按 COTP 类型分发：DataTransfer 走重组+MMS解析，其他走连接管理
                if frame.cotp.pdu_type == parser::CotpPduType::DataTransfer {
                    if let Some(complete) = self.reassemble_cotp(
                        frame.payload, frame.cotp.last_unit, is_request,
                    ) {
                        self.handle_cotp_payload(&complete, is_request);
                    }
                } else {
                    self.handle_cotp_connection(frame.cotp.pdu_type);
                }
                start = rem;
            }
            Err(nom::Err::Incomplete(_)) => {
                let consumed = input.len() - start.len();
                let needed = start.len() + 1;
                return AppLayerResult::incomplete(consumed as u32, needed as u32);
            }
            Err(_) => {
                self.emit_malformed_tx();
                return AppLayerResult::err();
            }
        }
    }
    AppLayerResult::ok()
}
```

#### 事务管理要点

- 每解析出一个完整 MMS PDU（无论请求还是响应）都创建一个新事务，并设置 `pdu` 与 `is_request`。
- COTP Data Transfer 支持分片重组（EOT=0 缓存，EOT=1 拼包后再做 Session/MMS 解析）。
- TCP gap 处理：标记 gap 并清空方向缓冲区；收到可探测的 TPKT 头后重新对齐再继续解析。
- 事务数限制：达到 `IEC61850_MMS_MAX_TX` 上限会设置 `TooManyTransactions` 事件，并返回解析错误。

### 3.5 实现 FFI 导出函数

必须实现以下约 10 个 `extern "C"` 回调函数，供 Suricata C 引擎调用（参考 `mms.rs:449-544`）：

| 函数 | 用途 | 参考行号 |
|------|------|----------|
| `probing_parser` | 协议探测：判断流量是否属于本协议 | `mms.rs:450-461` |
| `state_new` | 创建新的协议状态实例 | `mms.rs:463-469` |
| `state_free` | 释放协议状态 | `mms.rs:471-473` |
| `state_tx_free` | 释放指定事务 | `mms.rs:475-478` |
| `parse_request` (parse_ts) | 解析请求方向数据 | `mms.rs:480-499` |
| `parse_response` (parse_tc) | 解析响应方向数据 | `mms.rs:501-515` |
| `state_get_tx` | 按 tx_id 获取事务指针 | `mms.rs:517-529` |
| `state_get_tx_count` | 获取当前事务总数 | `mms.rs:531-534` |
| `tx_get_alstate_progress` | 获取事务完成度（0=进行中，1=完成） | `mms.rs:536-541` |

此外，使用宏生成两个辅助函数：

```rust
// 参考 mms.rs:543-544
export_tx_data_get!(iec61850_mms_get_tx_data, MmsTransaction);
export_state_data_get!(iec61850_mms_get_state_data, MmsState);
```

#### FFI 函数模板

```rust
// 状态创建
extern "C" fn iec61850_mms_state_new(
    _orig_state: *mut c_void, _orig_proto: AppProto,
) -> *mut c_void {
    let state = MyState::new();
    Box::into_raw(Box::new(state)) as *mut c_void
}

// 请求解析
unsafe extern "C" fn iec61850_mms_parse_request(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;
    if eof { return AppLayerResult::ok(); }
    let state = cast_pointer!(state, MyState);
    if stream_slice.is_gap() {
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        state.parse_request(stream_slice.as_slice())
    }
}
```

### 3.6 实现协议注册函数

每个协议必须有一个 `#[no_mangle] pub unsafe extern "C" fn SCRegisterXxxParser()` 函数，在 Suricata 启动时调用，完成协议注册（参考 `mms.rs:548-606`）。

```rust
const PARSER_NAME: &[u8] = b"iec61850-mms\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterIec61850MmsParser() {
    let default_port = CString::new("[102]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,          // 或 IPPROTO_UDP
        probe_ts: Some(iec61850_mms_probing_parser),
        probe_tc: Some(iec61850_mms_probing_parser),
        min_depth: 0,
        max_depth: 16,                 // 探测时检查的最大字节深度
        state_new: iec61850_mms_state_new,
        state_free: iec61850_mms_state_free,
        tx_free: iec61850_mms_state_tx_free,
        parse_ts: iec61850_mms_parse_request,
        parse_tc: iec61850_mms_parse_response,
        get_tx_count: iec61850_mms_state_get_tx_count,
        get_tx: iec61850_mms_state_get_tx,
        tx_comp_st_ts: 1,              // 请求方向事务完成状态值
        tx_comp_st_tc: 1,              // 响应方向事务完成状态值
        tx_get_progress: iec61850_mms_tx_get_alstate_progress,
        get_eventinfo: Some(Iec61850MmsEvent::get_event_info),
        get_eventinfo_byid: Some(Iec61850MmsEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(state_get_tx_iterator::<MmsState, MmsTransaction>),
        get_tx_data: iec61850_mms_get_tx_data,
        get_state_data: iec61850_mms_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS, // 支持 TCP gap
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(), parser.name
    ) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_IEC61850_MMS = alproto;
        if SCAppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(), parser.name
        ) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        // 可选：读取配置项
        if let Some(val) = conf_get("app-layer.protocols.iec61850-mms.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                IEC61850_MMS_MAX_TX.store(v, Ordering::Relaxed);
            }
        }
        // 注册日志器
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_IEC61850_MMS);
    }
}
```

### 3.7 实现检测关键字（sticky buffer）

在 `detect.rs` 中注册 sticky buffer 关键字，使 Suricata 规则能匹配协议字段（参考 `detect.rs`）。当前 IEC 61850 MMS 已注册两个关键字：

- `iec61850_mms.service`：匹配服务名（如 `read`、`write`）
- `iec61850_mms.pdu_type`：匹配 PDU 类型（如 `confirmed_request`）

每个 sticky buffer 需要：

1. **setup 回调**：绑定协议和激活 buffer（`detect.rs:40-50` / `71-81`）
2. **get 回调**：从事务中提取待匹配的字节数据（`detect.rs:54-66` / `84-95`）
3. **注册函数**：`#[no_mangle] pub unsafe extern "C" fn SCDetectXxxRegister()`（`detect.rs:101-133`）

```rust
// 注册函数模板
#[no_mangle]
pub unsafe extern "C" fn SCDetectIec61850MmsRegister() {
    let kw = SigTableElmtStickyBuffer {
        name: String::from("iec61850_mms.field_name"),
        desc: String::from("My protocol field content modifier"),
        url: String::from("/rules/iec61850-mms-keywords.html#field-name"),
        setup: iec61850_mms_field_setup,
    };
    let _kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"iec61850_mms.field_name\0".as_ptr() as *const libc::c_char,
        b"IEC 61850 MMS field\0".as_ptr() as *const libc::c_char,
        ALPROTO_IEC61850_MMS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(iec61850_mms_field_get),
    );
}
```

使用示例（Suricata 规则）：

```
alert tcp any any -> any 102 (msg:"MMS Read detected"; \
    iec61850_mms.service; content:"read"; sid:1; rev:1;)
```

```
alert tcp any any -> any 102 (msg:"MMS Confirmed Request"; \
    iec61850_mms.pdu_type; content:"confirmed_request"; sid:2; rev:1;)
```

### 3.8 实现 EVE JSON 日志

在 `logger.rs` 中实现日志输出（参考 `logger.rs`）。

```rust
// 核心日志函数：将事务数据写入 JsonBuilder
fn log_iec61850_mms(tx: &MmsTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("iec61850_mms")?;
    js.set_string("direction", if tx.is_request { "request" } else { "response" })?;
    if let Some(ref pdu) = tx.pdu {
        // 统一写入 pdu 字段（pdu_type / service / invoke_id / 细节）
    }
    js.close()?;
    Ok(())
}

// FFI 导出入口
#[no_mangle]
pub unsafe extern "C" fn SCIec61850MmsLoggerLog(
    tx: *const c_void, js: *mut c_void,
) -> bool {
    let tx = cast_pointer!(tx, MmsTransaction);
    let js = cast_pointer!(js, JsonBuilder);
    log_iec61850_mms(tx, js).is_ok()
}
```

EVE JSON 输出示例：

```json
{
  "iec61850_mms": {
    "direction": "request",
    "pdu_type": "confirmed_request",
    "invoke_id": 1,
    "service": "read",
    "variables": [
      {"scope": "domain_specific", "domain": "LLN0", "item": "Mod"}
    ]
  }
}
```

### 3.9 在 `rust/src/lib.rs` 中注册模块

在 `rust/src/lib.rs` 中添加一行即可：

```rust
// 参考 lib.rs:129
pub mod iec61850mms;
```

## 4. C 端集成步骤

### 4.1 在 `src/app-layer-protos.h` 添加协议枚举值

```c
// 参考 src/app-layer-protos.h:73
ALPROTO_IEC61850_MMS,
```

在 `AppProto` 枚举中添加新协议的标识符，位置在已有协议之后、`ALPROTO_MAX` 之前。

### 4.2 在 `src/app-layer.c` 注册协议字符串

```c
// 参考 src/app-layer.c:1077
AppProtoRegisterProtoString(ALPROTO_IEC61850_MMS, "iec61850-mms");
```

将协议枚举值与字符串名称绑定，该字符串用于配置文件和日志输出。

### 4.3 在 `src/app-layer-parser.c` 注册解析器调用

```c
// 参考 src/app-layer-parser.c:1823
SCRegisterIec61850MmsParser();
```

在 `AppLayerParserRegisterProtocolParsers()` 函数中添加对 Rust 注册函数的调用，使引擎启动时初始化该协议的解析器。

### 4.4 在 `src/output.c` 注册日志模块

需要在两个位置添加代码：

```c
// 位置 1：注册 JSON simple logger（参考 src/output.c:998-999）
RegisterSimpleJsonApplayerLogger(
    ALPROTO_IEC61850_MMS,
    (EveJsonSimpleTxLogFunc)SCIec61850MmsLoggerLog, "iec61850_mms");

// 位置 2：注册 Tx 子模块（参考 src/output.c:1261-1263）
OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonIec61850MmsLog",
    "eve-log.iec61850_mms", OutputJsonLogInitSub, ALPROTO_IEC61850_MMS,
    JsonGenericDirPacketLogger, JsonLogThreadInit, JsonLogThreadDeinit);
```

## 5. 配置

在 `suricata.yaml.in` 的 `app-layer.protocols` 段中添加协议配置：

```yaml
# 参考 suricata.yaml.in app-layer.protocols 段
iec61850-mms:
  enabled: yes
  detection-ports:
    dp: 102
```

配置项说明：
- `enabled`：是否启用该协议解析器
- `detection-ports.dp`：目标端口（destination port），用于协议探测

可选配置项（在 Rust 注册函数中通过 `conf_get` 读取）：
- `app-layer.protocols.iec61850-mms.max-tx`：单个流允许的最大事务数

## 6. 编译与验证

### 6.1 编译

```bash
# 在 Suricata 源码根目录
cargo build              # 编译 Rust 部分
./configure && make      # 编译完整项目
```

### 6.2 验证步骤

1. **单元测试**：在 Rust 模块中编写 `#[cfg(test)] mod tests`，使用 `cargo test` 运行。
2. **协议探测**：使用 pcap 文件验证协议能被正确识别：
   ```bash
   suricata -r test.pcap --set app-layer.protocols.iec61850-mms.enabled=yes
   ```
3. **EVE JSON 日志**：检查 `eve.json` 中是否输出了正确的协议日志。
4. **检测规则**：编写测试规则，验证 sticky buffer 关键字能正确匹配：
   ```
   alert tcp any any -> any 102 (msg:"test"; iec61850_mms.field_name; content:"value"; sid:1;)
   ```
5. **TCP gap 处理**：使用有丢包的 pcap 验证解析器不会崩溃。

### 6.3 开发清单

- [ ] 创建 `rust/src/iec61850mms/` 目录和 `mod.rs`
- [ ] 定义 State / Transaction / Event 数据结构
- [ ] 实现协议帧解析器（parser.rs）
- [ ] 实现状态机和请求/响应处理
- [ ] 实现所有 FFI 导出函数
- [ ] 实现 `SCRegisterXxxParser()` 协议注册函数
- [ ] 实现检测关键字（detect.rs）
- [ ] 实现 EVE JSON 日志（logger.rs）
- [ ] 在 `rust/src/lib.rs` 注册模块
- [ ] 在 `src/app-layer-protos.h` 添加枚举值
- [ ] 在 `src/app-layer.c` 注册协议字符串
- [ ] 在 `src/output.c` 注册日志模块
- [ ] 在 `suricata.yaml.in` 添加配置段
- [ ] 编写单元测试并验证

## 7. 常见陷阱与排查指南

> 以下内容来自 MySQL 协议解析器开发过程中的实际踩坑记录。每条都曾导致数小时的排查，且多数问题的表现是"沉默失败"——没有错误日志、没有 crash、一切看起来正常但就是不工作。

### 7.1 tx_id 必须从 1 开始（致命，无任何报错）

**表现**：Parser 正确解析了数据，Transaction 已创建（stats 中 `tx.xxx = 1`），Logger 已注册，但 eve.json 中永远没有协议事件输出。Logger 函数**从未被调用**。

**根因**：框架默认的 `state_get_tx_iterator`（`applayer.rs:676`）中有如下逻辑：

```rust
// applayer.rs 第 681 行
if tx.id() < min_tx_id + 1 {
    index += 1;
    continue;  // 跳过这个 tx
}
// 第 688 行
return AppLayerGetTxIterTuple::with_values(tx, tx.id() - 1, ...);
```

当 `min_tx_id = 0`（首次迭代）时，条件变为 `tx.id() < 1`。如果第一个事务的 `tx_id = 0`，则 `0 < 1` 为 true，**该事务被永远跳过**，Logger 永远不会被调用。

**正确做法**：State 的 `new_tx()` 中必须**先递增再赋值**：

```rust
// ✅ 正确：第一个 tx_id = 1
fn new_tx(&mut self) -> MmsTransaction {
    let mut tx = MmsTransaction::new();
    self.tx_id += 1;
    tx.tx_id = self.tx_id;
    tx
}

// ❌ 错误：第一个 tx_id = 0，会被迭代器跳过
fn new_tx(&mut self) -> MysqlTransaction {
    let tx = MysqlTransaction::new(self.tx_id);  // tx_id = 0
    self.tx_id += 1;
    tx
}
```

同理，`get_tx()` 中查找事务时需要 `tx_id + 1`：

```rust
fn get_tx(&mut self, tx_id: u64) -> Option<&MyTransaction> {
    self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
}
```

**排查难度**：极高。没有任何错误日志、warning 或 panic。从"tx 存在但 logger 不调用"到定位根因，中间隔了 OutputTxLog → IterFunc → state_get_tx_iterator → tx.id() 比较逻辑共 5 层抽象。

---

### 7.2 C 端注册四件套缺一不可

新增协议需要修改 **4 个 C 文件**，遗漏任何一项都会导致不同的故障：

| # | 文件 | 注册内容 | 漏掉的后果 |
|---|------|----------|-----------|
| 1 | `src/app-layer-protos.h` | `ALPROTO_XXX` 枚举值 | 编译错误（最容易发现） |
| 2 | `src/app-layer.c` | `AppProtoRegisterProtoString(ALPROTO_XXX, "xxx")` | **Segfault**（`strcmp` 对 NULL 指针）。`StringToAppProto` 遍历 `g_alproto_strings` 数组时，未注册的 slot 的 `str` 字段为 NULL |
| 3 | `src/app-layer-parser.c` | `SCXxxRegisterParser()` 调用 | 协议不会被识别，流量全部 bypass |
| 4 | `src/output.c` | `RegisterSimpleJsonApplayerLogger` + `OutputRegisterTxSubModule` | Logger 不工作，无 eve.json 事件输出 |

**特别注意 #2**：Segfault 不会发生在你的协议注册时，而是发生在**其他协议**（如 SNMP）注册时，因为它们遍历整个 `g_alproto_strings` 数组时碰到了你的空 slot。错误栈回溯会指向 SNMP 或其他协议，极具误导性。

---

### 7.3 Rust 端必须调用 `SCAppLayerParserRegisterLogger`

**表现**：C 端 logger 注册完毕，eve-log 子模块已启用（verbose 日志可见 `enabling 'eve-log' module 'xxx'`），但 Logger 函数从未被调用。

**根因**：`OutputTxLog` 中有一个检查（`output-tx.c:367-368`）：

```c
if (AppLayerParserProtocolHasLogger(ipproto, alproto) == 0)
    goto end;  // 跳过，不调用任何 logger
```

`AppLayerParserProtocolHasLogger` 检查的 `logger` 标志位，只有在 Rust 注册函数中显式调用 `SCAppLayerParserRegisterLogger(IPPROTO_TCP, alproto)` 后才会被置位。

**正确做法**：在 `SCRegisterXxxParser()` 中添加：

```rust
SCAppLayerParserRegisterLogger(IPPROTO_TCP, alproto);
```

---

### 7.4 新增枚举值后必须完整重新编译

**表现**：在 `app-layer-protos.h` 添加 `ALPROTO_XXX` 后做增量编译（`make`），运行时 Segfault。

**根因**：新增枚举值改变了后续所有枚举的数值偏移。C 文件如果没有被重新编译（增量编译可能跳过未修改的 `.c` 文件），它们使用的枚举值与 Rust 端不一致。

**正确做法**：修改 `app-layer-protos.h` 后必须 `make clean && make`。

---

### 7.5 cbindgen 生成绑定不可忘

**表现**：编译时 C 端找不到 Rust FFI 函数的声明（隐式声明 warning），或链接时符号类型不匹配。

**根因**：Rust 的 `#[no_mangle] pub unsafe extern "C"` 函数需要在 `rust/gen/rust-bindings.h` 中有对应的 C 声明。这个文件由 `cbindgen` 自动生成。

**正确做法**：添加新的 FFI 函数后运行：

```bash
cd rust && cbindgen --config cbindgen.toml --crate suricata --output gen/rust-bindings.h
```

---

### 7.6 pcap 文件 checksum 问题

**表现**：Suricata 正常运行但 `app_layer.flow.xxx = 0`（协议未被识别），且日志中有 `packets have an invalid checksum` 警告。

**根因**：抓包工具（如 tcpdump）在本地回环或虚拟网卡上抓的包通常带有未计算的 checksum。Suricata 默认校验 checksum，校验失败的包会被丢弃，导致 TCP 流重组失败。

**正确做法**：运行时加 `-k none` 禁用 checksum 校验：

```bash
suricata -r test.pcap -k none ...
```

或在 `suricata.yaml` 中设置：

```yaml
pcap-file:
  checksum-checks: no
```

---

### 7.7 排查 Logger 不工作的系统化方法

当 eve.json 中没有协议事件输出时，按以下顺序排查：

```
1. 协议是否被识别？
   → cat eve.json | jq 'select(.event_type=="flow") | .app_proto'
   → 如果不是你的协议名，检查 probing_parser 和 yaml 配置

2. Transaction 是否被创建？
   → cat eve.json | jq 'select(.event_type=="stats") | .stats.app_layer.tx.xxx'
   → 如果为 0，检查 parse_ts/parse_tc 是否正确创建了 tx

3. tx_id 是否从 1 开始？（见 7.1）
   → 检查 new_tx() 中 self.tx_id 的递增顺序

4. Logger 是否注册？
   → 运行 suricata -vvv，搜索 "enabling 'eve-log' module 'xxx'"
   → 如果没有，检查 output.c 中的 OutputRegisterTxSubModule

5. SCAppLayerParserRegisterLogger 是否调用？（见 7.3）
   → 检查 Rust 注册函数

6. Logger 函数本身是否正确？
   → 在 logger 函数中加 SCLogNotice! 确认是否被调用
   → 检查 JsonBuilder 操作是否返回 Err
```

## 8. 按文件落地的最小实现清单（MVP）

下面给一份可执行的“从空目录到可运行”的最小清单。建议按顺序做，每完成一项就做一次最小验证，避免一次改太多后难定位问题。

### 8.1 Rust 目录内（必做）

1. `rust/src/<proto>/mod.rs`
   - 声明模块可见性（`pub mod` / `mod`）。
   - 至少包含：`pub mod <proto>;`
   - 若启用检测和日志，再加：`pub mod detect; pub mod logger;`

2. `rust/src/<proto>/<proto>.rs`（核心）
   - 定义 `Transaction`（含 `tx_id`、协议字段、`AppLayerTxData`）。
   - 定义 `State`（含 `AppLayerStateData`、事务队列、gap 标记等）。
   - 实现解析入口：`parse_request` / `parse_response`（或统一 parse）。
   - 实现 FFI 回调：
     - `state_new/state_free/state_tx_free`
     - `parse_ts/parse_tc`
     - `state_get_tx/state_get_tx_count`
     - `tx_get_alstate_progress`
   - 实现 `SCRegisterXxxParser()` 并填充 `RustParser`。
   - 若支持事件，定义 `#[derive(AppLayerEvent)]` 事件枚举并挂到 parser。

3. `rust/src/<proto>/parser.rs`（建议）
   - 实现底层切帧与 probe（`nom7::streaming`）。
   - 明确 `Incomplete` 返回策略（通常 `consumed + needed`）。

4. `rust/src/<proto>/detect.rs`（可选但推荐）
   - 注册至少一个 sticky buffer（先做最关键字段）。
   - 提供 setup/get/register 三件套。

5. `rust/src/<proto>/logger.rs`（可选但推荐）
   - 输出最小 EVE JSON（方向 + 类型 + 关键 ID）。
   - 导出 `SCXxxLoggerLog` 供 C 端注册。

6. `rust/src/lib.rs`
   - 新增一行 `pub mod <proto>;`。

### 8.2 C 侧集成（必做）

1. `src/app-layer-protos.h`
   - 在 `AppProto` 枚举新增 `ALPROTO_XXX`（`ALPROTO_MAX` 前）。

2. `src/app-layer.c`
   - 注册协议字符串：`AppProtoRegisterProtoString(ALPROTO_XXX, "xxx")`。

3. `src/app-layer-parser.c`
   - 在协议 parser 注册入口调用 `SCRegisterXxxParser()`。

4. `src/output.c`（若有 EVE 日志）
   - 注册 simple logger。
   - 注册 `eve-log` tx 子模块。

### 8.3 配置与绑定（高频遗漏）

1. `suricata.yaml.in`
   - 增加 `app-layer.protocols.<proto>` 配置段（`enabled` + 端口）。

2. `rust/gen/rust-bindings.h`
   - 新增/变更 FFI 导出后运行 `cbindgen` 重新生成。

3. 完整重编译
   - 如果改了 `app-layer-protos.h`，建议 `make clean && make`，避免枚举偏移带来的运行时错配。

### 8.4 每一阶段的最小验证

1. **协议识别通过**
   - `eve.json` 的 flow 事件里能看到 `app_proto=<proto>`。

2. **事务创建通过**
   - `stats` 中 `app_layer.tx.<proto>` 递增。
   - `tx_id` 从 1 开始，`get_tx(tx_id)` 与迭代器语义一致。

3. **日志输出通过**
   - `eve-log.<proto>` 有事件，且字段非空、方向正确。

4. **规则匹配通过**
   - sticky buffer 关键字 + `content` 能命中预期流量。

5. **异常路径通过**
   - gap、截断、畸形输入不 crash，并有可观测事件或容错行为。

### 8.5 推荐的首个可交付版本（建议范围）

为避免前期范围过大，首版建议只承诺这 5 点：

- 能识别协议（probe + parser 注册完整）
- 能稳定创建事务（含 tx 生命周期管理）
- 能输出最小日志（1~3 个核心字段）
- 能支持 1 个 sticky buffer 规则匹配
- 能通过基础异常测试（至少 gap + malformed）
