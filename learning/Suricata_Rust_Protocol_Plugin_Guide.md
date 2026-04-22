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
3. 在 `rust/src/lib.rs` 中添加一行 `pub mod iec61850mms;`（参考 `lib.rs:127`）。

### 3.2 定义核心数据结构

在主文件（如 `mms.rs`）中定义以下核心类型：

#### 3.2.1 连接状态枚举

```rust
// 参考 mms.rs:43-54
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum MmsConnState {
    #[default]
    Idle,
    CotpPending,
    CotpEstablished,
    InitPending,
    MmsAssociated,
    Concluding,
    Closed,
}
```

定义协议生命周期内的所有合法状态，以及驱动状态转换的事件枚举。

#### 3.2.2 应用层事件枚举

```rust
// 参考 mms.rs:68-74
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
// 参考 mms.rs:76-107
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
// 参考 mms.rs:109-129
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

在 State 的 `impl` 块中实现核心解析逻辑（参考 `mms.rs:131-464`）：

#### 状态机转换

```rust
// 参考 mms.rs:138-158
fn advance_state(&mut self, event: MmsConnEvent) -> bool {
    let next = match (&self.conn_state, &event) {
        (State::Idle, Event::ConnReq) => State::Pending,
        // ... 其他合法转换 ...
        _ => return false,  // 非法转换
    };
    self.conn_state = next;
    true
}
```

#### 解析入口

```rust
// 参考 mms.rs:387-443
fn parse_frames(&mut self, input: &[u8], is_request: bool) -> AppLayerResult {
    let mut start = input;
    while !start.is_empty() {
        match parser::parse_frame(start) {
            Ok((rem, frame)) => {
                // 处理帧，创建/更新事务
                self.handle_frame(frame, is_request);
                start = rem;
            }
            Err(nom::Err::Incomplete(_)) => {
                let consumed = input.len() - start.len();
                let needed = start.len() + 1;
                return AppLayerResult::incomplete(consumed as u32, needed as u32);
            }
            Err(_) => return AppLayerResult::err(),
        }
    }
    AppLayerResult::ok()
}

fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
    self.parse_frames(input, true)
}

fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
    self.parse_frames(input, false)
}
```

#### 事务管理要点

- 每解析出一个完整 MMS PDU（无论请求还是响应）都创建一个新事务，并设置 `pdu` 与 `is_request`。
- COTP Data Transfer 支持分片重组（EOT=0 缓存，EOT=1 拼包后再做 Session/MMS 解析）。
- TCP gap 处理：标记 gap 并清空方向缓冲区；收到可探测的 TPKT 头后重新对齐再继续解析。
- 事务数限制：达到 `IEC61850_MMS_MAX_TX` 上限会设置 `TooManyTransactions` 事件，并返回解析错误。

### 3.5 实现 FFI 导出函数

必须实现以下约 10 个 `extern "C"` 回调函数，供 Suricata C 引擎调用（参考 `mms.rs:466-579`）：

| 函数 | 用途 | 参考行号 |
|------|------|----------|
| `probing_parser` | 协议探测：判断流量是否属于本协议 | `mms.rs:468-479` |
| `state_new` | 创建新的协议状态实例 | `mms.rs:481-487` |
| `state_free` | 释放协议状态 | `mms.rs:489-491` |
| `state_tx_free` | 释放指定事务 | `mms.rs:493-496` |
| `parse_request` (parse_ts) | 解析请求方向数据 | `mms.rs:498-517` |
| `parse_response` (parse_tc) | 解析响应方向数据 | `mms.rs:519-533` |
| `state_get_tx` | 按 tx_id 获取事务指针 | `mms.rs:535-547` |
| `state_get_tx_count` | 获取当前事务总数 | `mms.rs:549-552` |
| `tx_get_alstate_progress` | 获取事务完成度（0=进行中，1=完成） | `mms.rs:554-576` |

此外，使用宏生成两个辅助函数：

```rust
// 参考 mms.rs:578-579
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

每个协议必须有一个 `#[no_mangle] pub unsafe extern "C" fn SCRegisterXxxParser()` 函数，在 Suricata 启动时调用，完成协议注册（参考 `mms.rs:584-637`）。

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
        get_tx_iterator: Some(state_get_tx_iterator::<MyState, MyTransaction>),
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
            if let Ok(v) = val.parse::<usize>() { MAX_TX = v; }
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

1. **setup 回调**：绑定协议和激活 buffer（`detect.rs:41-51`）
2. **get 回调**：从事务中提取待匹配的字节数据（`detect.rs:55-72`）
3. **注册函数**：`#[no_mangle] pub unsafe extern "C" fn SCDetectXxxRegister()`（`detect.rs:112-144`）

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
// 参考 lib.rs:127
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

### 4.3 在 `src/output.c` 注册日志模块

需要在两个位置添加代码：

```c
// 位置 1：注册 JSON simple logger（参考 src/output.c:999）
JsonSimpleLogRegister(js_ctx, ALPROTO_IEC61850_MMS,
    (EveJsonSimpleTxLogFunc)SCIec61850MmsLoggerLog, "iec61850_mms");

// 位置 2：注册 Tx 子模块（参考 src/output.c:1257-1258）
OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonIec61850MmsLog",
    "eve-log.iec61850-mms", OutputJsonLogInitSub, ALPROTO_IEC61850_MMS,
    JsonGenericDirPacketLogger, ...);
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
