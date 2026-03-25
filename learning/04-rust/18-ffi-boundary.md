---
title: "C-Rust FFI 边界详解"
series: "Suricata 深度解析"
number: 18
author: ""
date: 2026-03-24
version: "Suricata 8.0.3"
keywords: [suricata, rust, C, FFI, cbindgen, RustParser, 内存所有权, 协议注册]
---

# 18 - C-Rust FFI 边界详解

> **导读**：上一篇速成了 Rust 语言基础。本篇聚焦 Suricata 中 C 与 Rust 如何协作——它们之间的"边界"如何设计、数据如何传递、内存所有权如何转移。这不是一个纯语言话题，而是 Suricata 混合架构的核心设计。理解 FFI 边界是你编写自定义 Rust 协议解析器（第 22 篇）的前提。

---

## 1. 全景：C-Rust 边界的架构

Suricata 的 C 和 Rust 代码通过以下机制协作：

```
┌────────────────────────────────────────────────────────┐
│                    C 引擎 (src/)                         │
│                                                         │
│  main() 函数初始化 → SCRustInit() ─────────────────────┐  │
│                                                       │  │
│  AppLayerParserRegisterProtocolParsers()               │  │
│    → SCRegisterDnsUdpParser()  ──────── RustParser ──┐│  │
│    → SCRegisterDnsTcpParser()  ──────── RustParser ──┤│  │
│    → SCRegisterDnp3UdpParser() ──────── RustParser ──┤│  │
│    → ...                                             ││  │
│                                                      ││  │
│  运行时：C 引擎通过 RustParser 中的                    ││  │
│  函数指针调用 Rust 代码                                ││  │
│    state_new() → parse_ts() → get_tx() → tx_free()   ││  │
│                                                      ││  │
├──────────────── FFI 边界 ────────────────────────────┤│  │
│                                                      ││  │
│                Rust 库 (rust/src/)                     ││  │
│                                                      ▼│  │
│  core.rs ←────── SuricataContext (C 函数指针表) ──────┘│  │
│  applayer.rs ─── RustParser 结构体定义                 │  │
│  dns/dns.rs ──── 协议实现 + FFI 导出函数               │  │
│  dns/log.rs ──── 日志 FFI 导出                         │  │
│  dns/detect.rs ─ 检测关键字 FFI 导出                   │  │
│                                                         │
│  编译产物: libsuricata.a ──→ 链接到 C 主程序             │
│  cbindgen 产物: rust-bindings.h ──→ C 代码 #include     │
└─────────────────────────────────────────────────────────┘
```

两个方向的调用：

| 方向 | 机制 | 示例 |
|------|------|------|
| **C → Rust** | `#[no_mangle] extern "C"` 函数 | C 引擎调用 `SCRegisterDnsUdpParser()` |
| **Rust → C** | `extern "C"` 块 + `SuricataContext` 函数指针 | Rust 调用 `SCLogMessage()` 写日志 |

---

## 2. cbindgen：自动生成 C 头文件

Suricata 不手写 C 头文件来声明 Rust 函数——它用 `cbindgen` 工具从 Rust 源码自动生成。

### 2.1 配置文件

```toml
# rust/cbindgen.toml（关键配置）
language = "C"                                    # 生成 C 语言头文件
include_guard = "__RUST_BINDINGS_GEN_H_"          # 防止重复包含
includes = ["stdint.h", "stdbool.h"]              # 需要的 C 标准头文件
documentation_style = "doxy"                       # Doxygen 风格注释
line_length = 80
tab_width = 4

[export]
include = [                                        # 强制导出的类型
    "StreamSlice",
    "AppLayerResult",
    "AppLayerStateData",
    "ModbusState",
    # ...
]
exclude = [                                        # 排除的类型（C 侧已定义）
    "AppLayerDecoderEvents",
    "DetectEngineState",
    "Flow",
    "SuricataContext",
    # ...
]
item_types = ["enums","structs","opaque","functions","constants"]

[export.rename]
"JsonBuilder" = "SCJsonBuilder"                    # 类型重命名
"CLuaState" = "lua_State"

[parse]
exclude = ["libc"]                                 # 不解析 libc crate

[parse.expand]
features = ["cbindgen"]                            # 启用 cbindgen feature
```

### 2.2 生成产物

cbindgen 扫描所有 `#[no_mangle] pub extern "C"` 函数和 `#[repr(C)]` 类型，生成 `rust/gen/rust-bindings.h`（约 6600 行）。C 代码通过 `#include` 这个头文件来调用 Rust 函数：

```c
// rust/gen/rust-bindings.h（自动生成，节选）

// 不透明类型——C 不能访问内部字段
typedef struct DNSTransaction DNSTransaction;

// 函数声明
void SCRegisterDnsUdpParser(void);
void SCRegisterDnsTcpParser(void);
bool SCDnsTxIsRequest(struct DNSTransaction *tx);
bool SCDnsTxIsResponse(struct DNSTransaction *tx);
bool SCDnsTxGetQueryName(
    struct DetectEngineThreadCtx *_de,
    const void *tx, uint8_t flow_flags,
    uint32_t i, const uint8_t **buf, uint32_t *len);
uint16_t SCDnsTxGetResponseFlags(struct DNSTransaction *tx);
bool SCDnsLogJson(
    const struct DNSTransaction *tx,
    uint64_t flags,
    struct SCJsonBuilder *jb);
```

### 2.3 控制导出的方式

| 方式 | 效果 | 示例 |
|------|------|------|
| `#[no_mangle]` + `pub extern "C"` | 函数出现在头文件中 | `SCDnsTxIsRequest` |
| `pub(crate) extern "C"` | 函数**不**出现在头文件中，但可通过函数指针传递 | `state_new`, `parse_request` |
| `#[repr(C)]` + `pub` struct/enum | 类型定义出现在头文件中 | `AppLayerResult` |
| `pub` struct（无 `#[repr(C)]`） | 类型作为**不透明指针**出现 | `DNSTransaction` |
| `/// cbindgen:ignore` | cbindgen 完全忽略 | `extern "C" { fn SCGetContext() }` |

**关键设计**：大部分协议解析回调函数（`state_new`、`parse_request` 等）使用 `pub(crate)` 而非 `pub`——它们不直接出现在头文件中，而是通过 `RustParser` 结构体的函数指针传递给 C 引擎。只有需要被 C 代码直接调用的函数（如注册函数、检测/日志函数）才使用 `#[no_mangle] pub`。

---

## 3. Rust → C：SuricataContext 机制

Rust 代码需要调用 C 端的功能（日志、事件上报、文件操作等），但 Rust 库编译时并不直接链接 C 函数。Suricata 的解决方案是**函数指针表**。

### 3.1 SuricataContext 结构体

```rust
// rust/src/core.rs:157-176
#[repr(C)]
pub struct SuricataContext {
    pub SCLogMessage: SCLogMessageFunc,                      // 日志输出
    DetectEngineStateFree: DetectEngineStateFreeFunc,         // 释放检测状态
    AppLayerDecoderEventsSetEventRaw: ...,                   // 设置事件
    AppLayerDecoderEventsFreeEvents: ...,                    // 释放事件
    pub AppLayerParserTriggerRawStreamInspection: ...,       // 触发流检测
    pub FileOpenFile: SCFileOpenFileWithId,                   // 文件操作
    pub FileCloseFile: SCFileCloseFileById,
    pub FileAppendData: SCFileAppendDataById,
    // ... 更多文件操作回调
    GenericVarFree: GenericVarFreeFunc,                       // 释放通用变量
}
```

每个字段都是一个 C 函数指针类型。`#[repr(C)]` 保证内存布局与 C 一致。

### 3.2 初始化流程

C 引擎在启动时调用 `SCRustInit()`，将函数指针表传入 Rust：

```rust
// rust/src/core.rs:189-202
pub static mut SC: Option<&'static SuricataContext> = None;  // 全局静态变量

pub fn init_ffi(context: &'static SuricataContext) {
    unsafe {
        SC = Some(context);
    }
}

#[no_mangle]
pub extern "C" fn SCRustInit(context: &'static SuricataContext) {
    init_ffi(context);
}
```

之后 Rust 代码通过全局 `SC` 变量调用 C 函数：

```rust
// rust/src/core.rs:205-212
// 安全包装器：避免在每个调用点写 unsafe
pub fn sc_detect_engine_state_free(state: *mut DetectEngineState) {
    unsafe {
        if let Some(c) = SC {
            (c.DetectEngineStateFree)(state);
        }
    }
}
```

### 3.3 为什么用函数指针表而不是直接 extern

这个设计有一个重要原因：**让 Rust 单元测试能独立编译**。

如果 Rust 代码直接声明 `extern "C" { fn SCLogMessage(...); }`，那么 `cargo test` 时链接器会找不到 `SCLogMessage` 的实现（因为没��接 C 代码）。通过函数指针表 + `Option` 包装，Rust 测试可以在 `SC = None` 的状态下运行，不需要 C 代码参与。

---

## 4. C → Rust：RustParser 注册机制

### 4.1 RustParser 结构体

这是 C-Rust FFI 的核心——每个 Rust 协议解析器通过填充这个结构体向 C 引擎注册自己的能力：

```rust
// rust/src/applayer.rs:384-458
#[repr(C)]
pub struct RustParser {
    // ── 基本信息 ──
    pub name:            *const c_char,        // 协议名称，如 b"dns\0"
    pub default_port:    *const c_char,        // 默认端口，如 "[53]"
    pub ipproto:         u8,                   // IPPROTO_TCP 或 IPPROTO_UDP

    // ── 协议探测 ──
    pub probe_ts:        Option<ProbeFn>,       // 探测 to-server 方向
    pub probe_tc:        Option<ProbeFn>,       // 探测 to-client 方向
    pub min_depth:       u16,                   // 最小探测深度
    pub max_depth:       u16,                   // 最大探测深度

    // ── 状态管理 ──
    pub state_new:       StateAllocFn,          // 分配新状态
    pub state_free:      StateFreeFn,           // 释放状态
    pub tx_free:         StateTxFreeFn,         // 释放事务

    // ── 解析 ──
    pub parse_ts:        ParseFn,               // 解析 to-server 数据
    pub parse_tc:        ParseFn,               // 解析 to-client 数据

    // ── 事务管理 ──
    pub get_tx_count:    StateGetTxCntFn,       // 事务总数
    pub get_tx:          StateGetTxFn,          // 获取指定事务
    pub tx_comp_st_ts:   c_int,                 // to-server 完成状态值
    pub tx_comp_st_tc:   c_int,                 // to-client 完成状态值
    pub tx_get_progress:  StateGetProgressFn,    // 事务进度

    // ── 事件 ──
    pub get_eventinfo:      Option<GetEventInfoFn>,
    pub get_eventinfo_byid: Option<GetEventInfoByIdFn>,

    // ── 本地存储 ──
    pub localstorage_new:  Option<LocalStorageNewFn>,
    pub localstorage_free: Option<LocalStorageFreeFn>,

    // ── 文件 ──
    pub get_tx_files:    Option<GetTxFilesFn>,

    // ── 遍历 ──
    pub get_tx_iterator: Option<GetTxIteratorFn>,

    // ── 数据访问 ──
    pub get_state_data:  GetStateDataFn,        // 获取 AppLayerStateData
    pub get_tx_data:     GetTxDataFn,           // 获取 AppLayerTxData

    // ── 配置 ──
    pub apply_tx_config: Option<ApplyTxConfigFn>,
    pub flags:           u32,                   // 解析器标志

    // ── 帧类型 ──
    pub get_frame_id_by_name:  Option<GetFrameIdByName>,
    pub get_frame_name_by_id:  Option<GetFrameNameById>,

    // ── 状态名称 ──
    pub get_state_id_by_name:  Option<GetStateIdByName>,
    pub get_state_name_by_id:  Option<GetStateNameById>,
}
```

### 4.2 函数签名类型

`RustParser` 中每个函数指针都有精确的类型定义：

```rust
// 状态分配
pub type StateAllocFn = extern "C" fn(
    *mut c_void, AppProto
) -> *mut c_void;

// 状态释放
pub type StateFreeFn = extern "C" fn(*mut c_void);

// 解析函数
pub type ParseFn = unsafe extern "C" fn(
    flow: *mut Flow,
    state: *mut c_void,        // 协议状态（不透明指针）
    pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, // 输入数据
    data: *const c_void,
) -> AppLayerResult;

// 协议探测
pub type ProbeFn = unsafe extern "C" fn(
    flow: *const Flow,
    flags: u8,
    input: *const u8,
    input_len: u32,
    rdir: *mut u8,             // 输出：实际方向
) -> AppProto;

// 事务获取
pub type StateGetTxFn = unsafe extern "C" fn(
    state: *mut c_void,
    tx_id: u64,
) -> *mut c_void;
```

### 4.3 DNS 的完整注册示例

以 DNS UDP 解析器为例，走读注册全过程：

```rust
// rust/src/dns/dns.rs:1276-1321
#[no_mangle]
pub unsafe extern "C" fn SCRegisterDnsUdpParser() {
    let default_port = std::ffi::CString::new("[53]").unwrap();

    let parser = RustParser {
        // 基本信息
        name:          b"dns\0".as_ptr() as *const c_char,
        default_port:  default_port.as_ptr(),
        ipproto:       IPPROTO_UDP,

        // 协议探测：UDP 两个方向都用同一个探测函数
        probe_ts:      Some(probe_udp),
        probe_tc:      Some(probe_udp),
        min_depth:     0,
        max_depth:     std::mem::size_of::<DNSHeader>() as u16,  // 12 字节

        // 状态管理
        state_new,                       // fn() -> *mut c_void
        state_free,                      // fn(*mut c_void)
        tx_free:       state_tx_free,    // fn(*mut c_void, u64)

        // 解析
        parse_ts:      parse_request,    // to-server = 请求
        parse_tc:      parse_response,   // to-client = 响应

        // 事务
        get_tx_count:  state_get_tx_count,
        get_tx:        state_get_tx,
        tx_comp_st_ts: 1,               // DNS 是无状态的，事务创建即完成
        tx_comp_st_tc: 1,
        tx_get_progress: tx_get_alstate_progress,

        // 事件：由 #[derive(AppLayerEvent)] 自动生成
        get_eventinfo:      Some(DNSEvent::get_event_info),
        get_eventinfo_byid: Some(DNSEvent::get_event_info_by_id),

        // 事务迭代器：使用泛型实现
        get_tx_iterator: Some(
            crate::applayer::state_get_tx_iterator::<DNSState, DNSTransaction>
        ),

        // 数据访问
        get_tx_data:    state_get_tx_data,
        get_state_data: dns_get_state_data,

        // 帧类型：由 #[derive(AppLayerFrameType)] 自动生成
        get_frame_id_by_name: Some(DnsFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(DnsFrameType::ffi_name_from_id),

        // DNS 不需要的可选回调
        localstorage_new:  None,
        localstorage_free: None,
        get_tx_files:      None,
        apply_tx_config:   Some(apply_tx_config),
        flags:             0,
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    // 向 C 引擎注册
    let ip_proto_str = CString::new("udp").unwrap();
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(), parser.name
    ) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_DNS = alproto;
        if SCAppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(), parser.name
        ) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}
```

### 4.4 C 侧如何调用注册函数

C 引擎在初始化时统一注册所有协议解析器：

```c
// src/app-layer-parser.c:1780-1830（节选）
void AppLayerParserRegisterProtocolParsers(void)
{
    RegisterHTPParsers();          // HTTP（纯 C）
    RegisterSSLParsers();          // TLS/SSL
    SCRegisterDnsUdpParser();      // DNS UDP（Rust）
    SCRegisterDnsTcpParser();      // DNS TCP（Rust）
    RegisterSMBParsers();          // SMB（Rust）
    SCRegisterModbusParser();      // Modbus（Rust）
    // ... 更多协议
}
```

注册后，C 引擎持有每个协议的函数指针。之后处理数据包时，引擎通过函数指针调用 Rust 代码，**不需要知道 Rust 的任何实现细节**。

---

## 5. 内存所有权：谁分配，谁释放

跨 FFI 边界的内存管理是最容易出错的地方。Suricata 遵循一个清晰的原则：

> **谁分配，谁释放。Rust 分配的内存由 Rust 释放，C 分配的内存由 C 释放。**

### 5.1 状态对象的生命周期

```
C 引擎                                    Rust
  │                                         │
  │ ─── state_new() ──────────────────────→ │ Box::new(DNSState::new())
  │ ← ─ *mut c_void ─────────────────────── │ Box::into_raw() 交出所有权
  │                                         │
  │ （引擎持有 void* 指针，多次调用）          │
  │ ─── parse_ts(state, data) ────────────→ │ cast_pointer! 临时借用
  │ ─── parse_tc(state, data) ────────────→ │
  │ ─── get_tx(state, id) ───────────────→ │
  │                                         │
  │ ─── state_free(state) ───────────────→ │ Box::from_raw() 收回所有权
  │                                         │ Drop 自动释放
```

对应的 Rust 代码：

```rust
// 创建：Rust 分配，转为 C 指针
// rust/src/dns/dns.rs:918-924
pub(crate) extern "C" fn state_new(
    _orig_state: *mut c_void, _orig_proto: AppProto,
) -> *mut c_void {
    let state = DNSState::new();        // 在栈上创建
    let boxed = Box::new(state);        // 移到堆上
    return Box::into_raw(boxed) as *mut _;  // 转为原始指针，Rust 放弃所有权
}

// 释放：C 传回指针，Rust 收回所有权并释放
// rust/src/dns/dns.rs:928-931
pub(crate) extern "C" fn state_free(state: *mut c_void) {
    std::mem::drop(unsafe {
        Box::from_raw(state as *mut DNSState)  // 从原始指针恢复 Box
    });                                         // Box 被 drop，内存释放
}
```

### 5.2 中间使用：临时借用

解析函数接收 `*mut c_void`，需要转为 Rust 引用来操作。`cast_pointer!` 宏做的就是这件事：

```rust
// rust/src/applayer.rs:37-40
macro_rules! cast_pointer {
    ($ptr:ident, $ty:ty) => ( &mut *($ptr as *mut $ty) );
}

// 使用（在 unsafe 块中）
// rust/src/dns/dns.rs:943
let state = cast_pointer!(state, DNSState);
```

这只是**借用**——不获取所有权，不会在函数结束时释放对象。

### 5.3 事务对象的生命周期

事务由 `DNSState` 拥有（存储在 `VecDeque<DNSTransaction>` 中），C 引擎通过 `get_tx()` 获取的是**指向 Vec 内部元素的指针**：

```rust
// rust/src/dns/dns.rs:999-1011
pub(crate) unsafe extern "C" fn state_get_tx(
    state: *mut c_void, tx_id: u64,
) -> *mut c_void {
    let state = cast_pointer!(state, DNSState);
    match state.get_tx(tx_id) {
        Some(tx) => tx as *const _ as *mut _,  // 返回内部引用的指针
        None => std::ptr::null_mut(),           // 未找到返回 NULL
    }
}
```

**注意**：C 拿到的事务指针**不拥有**事务对象。它的有效期取决于 `DNSState` 的生命周期和事务是否被 `tx_free` 移除。

### 5.4 零拷贝数据返回

检测关键字函数返回 Rust 内部数据的指针，C 侧只读不释放：

```rust
// rust/src/dns/dns.rs:1038-1062
#[no_mangle]
pub unsafe extern "C" fn SCDnsTxGetQueryName(
    _de: *mut DetectEngineThreadCtx,
    tx: *const c_void,
    flow_flags: u8,
    i: u32,
    buf: *mut *const u8,    // 输出：数据指针
    len: *mut u32,          // 输出：数据长度
) -> bool {
    let tx = cast_pointer!(tx, DNSTransaction);
    let queries = if (flow_flags & STREAM_TOSERVER) == 0 {
        tx.response.as_ref().map(|r| &r.queries)
    } else {
        tx.request.as_ref().map(|r| &r.queries)
    };

    if let Some(queries) = queries {
        if let Some(query) = queries.get(i as usize) {
            if !query.name.value.is_empty() {
                *buf = query.name.value.as_ptr();  // 指向 Vec 内部缓冲区
                *len = query.name.value.len() as u32;
                return true;
            }
        }
    }
    false
}
```

这里 `*buf` 指向 `Vec<u8>` 的内部缓冲区。C 侧可以读取这段数据，但**不能 free 它**——它由 Rust 的 `DNSTransaction` 拥有。

---

## 6. 五类 FFI 函数详解

以 DNS 为例，将所有 FFI 函数分为五类：

### 6.1 状态管理函数

| 函数 | 签名 | 说明 |
|------|------|------|
| `state_new` | `fn(*mut c_void, AppProto) -> *mut c_void` | 分配新的 `DNSState` |
| `state_free` | `fn(*mut c_void)` | 释放 `DNSState` |
| `state_tx_free` | `fn(*mut c_void, u64)` | 从状态中移除指定事务 |

### 6.2 协议探测函数

探测函数在协议检测阶段被调用，判断数据流是否属于该协议：

```rust
// rust/src/dns/dns.rs:1217-1235
pub(crate) unsafe extern "C" fn probe_udp(
    _flow: *const Flow, _dir: u8,
    input: *const u8, len: u32, rdir: *mut u8,
) -> AppProto {
    // 安全检查：空指针或数据太短
    if input.is_null() || len < std::mem::size_of::<DNSHeader>() as u32 {
        return ALPROTO_UNKNOWN;
    }

    // 将 C 指针转为 Rust 切片
    let slice: &[u8] = std::slice::from_raw_parts(input, len as usize);

    // 调用 Rust 探测逻辑
    let (is_dns, is_request, _) = probe(slice, slice.len());
    if is_dns {
        // 通过 rdir 输出参数告知 C 引擎实际方向
        let dir = if is_request { Direction::ToServer } else { Direction::ToClient };
        *rdir = dir as u8;
        return ALPROTO_DNS;
    }
    return 0;
}
```

关键模式：
- `input: *const u8, len: u32` → `std::slice::from_raw_parts()` → `&[u8]`
- 返回 `AppProto`（全局协议 ID）或 `ALPROTO_UNKNOWN`
- `rdir` 是**输出参数**——通过指针写回方向信息

TCP 探测多一步：检查 2 字节长度前缀：

```rust
// rust/src/dns/dns.rs:1237-1258
unsafe extern "C" fn c_probe_tcp(
    _flow: *const Flow, direction: u8,
    input: *const u8, len: u32, rdir: *mut u8,
) -> AppProto {
    if input.is_null() || len < std::mem::size_of::<DNSHeader>() as u32 + 2 {
        return ALPROTO_UNKNOWN;       // TCP DNS 多 2 字节长度前缀
    }
    let slice = std::slice::from_raw_parts(input, len as usize);
    let (is_dns, is_request, _) = probe_tcp(slice);
    if is_dns {
        let dir = if is_request { Direction::ToServer } else { Direction::ToClient };
        if (direction & DIR_BOTH) != u8::from(dir) {
            *rdir = dir as u8;         // 仅在方向不匹配时修正
        }
        return ALPROTO_DNS;
    }
    return 0;
}
```

### 6.3 解析函数

解析函数是 FFI 的核心——C 引擎传入数据，Rust 解析并更新状态：

```rust
// rust/src/dns/dns.rs:939-946
// UDP 请求解析
pub(crate) unsafe extern "C" fn parse_request(
    flow: *mut Flow,
    state: *mut c_void,
    _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice,           // 输入数据（C 传入）
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, DNSState);
    state.parse_request_udp(flow, stream_slice);
    AppLayerResult::ok()
}

// TCP 请求解析——需要处理 gap（数据缺失）
// rust/src/dns/dns.rs:958-969
unsafe extern "C" fn parse_request_tcp(
    flow: *mut Flow,
    state: *mut c_void,
    _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, DNSState);
    if stream_slice.is_gap() {
        state.request_gap(stream_slice.gap_size());   // 处理数据缺失
    } else if !stream_slice.is_empty() {
        return state.parse_request_tcp(flow, stream_slice);  // 正常解析
    }
    AppLayerResult::ok()
}
```

`StreamSlice` 是 FFI 边界的关键数据结构——它封装了 C 传入的原始指针：

```rust
// rust/src/applayer.rs:43-88
#[repr(C)]
pub struct StreamSlice {
    input: *const u8,       // C 传入的缓冲区指针
    input_len: u32,         // 缓冲区长度
    flags: u8,              // STREAM_* 方向/状态标志
    offset: u64,            // 在流中的偏移量
}

impl StreamSlice {
    pub fn as_slice(&self) -> &[u8] {                  // 安全转换为 Rust 切片
        unsafe { std::slice::from_raw_parts(self.input, self.input_len as usize) }
    }
    pub fn is_gap(&self) -> bool {                     // 判断是否为数据缺失
        self.input.is_null() && self.input_len > 0
    }
    pub fn gap_size(&self) -> u32 { self.input_len }
}
```

### 6.4 检测辅助函数

这类函数由 C 侧的检测引擎直接调用（`#[no_mangle]`），用于规则匹配时提取协议字段：

```rust
// rust/src/dns/dns.rs:1013-1021
#[no_mangle]
pub extern "C" fn SCDnsTxIsRequest(tx: &mut DNSTransaction) -> bool {
    tx.request.is_some()
}

#[no_mangle]
pub extern "C" fn SCDnsTxIsResponse(tx: &mut DNSTransaction) -> bool {
    tx.response.is_some()
}

// rust/src/dns/dns.rs:1212-1215
#[no_mangle]
pub extern "C" fn SCDnsTxGetResponseFlags(tx: &mut DNSTransaction) -> u16 {
    return tx.rcode();
}
```

注意 `SCDnsTxIsRequest` 的参数是 `&mut DNSTransaction` 而非 `*mut c_void`——cbindgen 会将其生成为 `struct DNSTransaction *tx`。这种方式比 void 指针更安全，因为类型信息保留了。

### 6.5 日志函数

日志函数将 Rust 解析结果输出为 JSON，供 EVE 日志使用：

```rust
// rust/src/dns/log.rs（节选）
#[no_mangle]
pub extern "C" fn SCDnsLogJson(
    tx: &DNSTransaction,
    flags: u64,
    jb: &mut JsonBuilder,       // Rust 实现的 JSON 构建器
) -> bool {
    // 根据 flags 决定输出哪些字段
    // 写入查询名、类型、响应码、应答等
}

#[no_mangle]
pub extern "C" fn SCDnsLogEnabled(tx: &DNSTransaction, flags: u64) -> bool {
    // 判断该事务是否需要记录日志
}
```

C 侧调用：

```c
// src/output-json-dns.c（C 代码）
bool AlertJsonDns(void *txptr, SCJsonBuilder *js) {
    return SCDnsLogJson(txptr,
        LOG_FORMAT_DETAILED | LOG_QUERIES | LOG_ANSWERS | LOG_ALL_RRTYPES,
        js);
}
```

---

## 7. 类型映射参考

### 7.1 基本类型

| Rust FFI 类型 | C 类型 | 说明 |
|---------------|--------|------|
| `bool` | `bool` | C99 `stdbool.h` |
| `u8` | `uint8_t` | |
| `u16` | `uint16_t` | |
| `u32` | `uint32_t` | |
| `u64` | `uint64_t` | |
| `i32` | `int32_t` | |
| `c_int` | `int` | `std::os::raw::c_int` |
| `c_char` | `char` | `std::os::raw::c_char` |
| `usize` | `uintptr_t` | 平台相关 |

### 7.2 指针类型

| Rust FFI 类型 | C 类型 | 用途 |
|---------------|--------|------|
| `*mut c_void` | `void *` | 不透明对象指针 |
| `*const c_void` | `const void *` | 不透明只读指针 |
| `*mut u8` | `uint8_t *` | 可写字节缓冲区 |
| `*const u8` | `const uint8_t *` | 只读字节缓冲区 |
| `*const c_char` | `const char *` | C 字符串 |
| `&mut T` | `T *` | 可变引用（cbindgen 转为指针） |
| `&T` | `const T *` | 不可变引用 |

### 7.3 复合类型

| Rust 类型 | FFI 表现 | 说明 |
|-----------|---------|------|
| `#[repr(C)] struct` | 同名 C struct | 字段布局完全一致 |
| `#[repr(C)] enum` | C enum | 要求有显式判别值 |
| `pub struct`（无 repr(C)） | `typedef struct Foo Foo;` | 不透明类型，C 只能用指针 |
| `Option<extern "C" fn(...)>` | 可空函数指针 | `None` = NULL |
| `CString` | — | Rust 侧创建的 C 字符串，需要保持存活 |

### 7.4 字符串传递

```rust
// Rust → C：b"literal\0" 方式（编译期，零成本）
name: b"dns\0".as_ptr() as *const c_char,

// Rust → C：CString 方式（运行时分配）
let port = CString::new("[53]").unwrap();
default_port: port.as_ptr(),
// 注意：port 必须在 as_ptr() 的使用期间保持存活！

// C → Rust：*const c_char → &str
let name = CStr::from_ptr(c_name).to_str().unwrap();

// Rust → C：String → *mut c_char（所有权转移）
pub fn rust_string_to_c(s: String) -> *mut c_char {
    CString::new(s).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut())
}

// C 侧用完后必须调用 Rust 的释放函数
#[no_mangle]
pub unsafe extern "C" fn SCRustCStringFree(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}
```

---

## 8. 完整调用链路：一个 DNS 数据包的 FFI 之旅

将前面的知识串联起来，跟踪一个 DNS UDP 数据包在 FFI 边界的完整旅程：

```
[1] C 引擎收到 UDP 数据包
    │
    ▼
[2] 协议检测：C 调用 probe_udp(flow, dir, input, len, &rdir)
    │  ┌─ Rust ──────────────────────────────────────────┐
    │  │ slice = slice::from_raw_parts(input, len)       │
    │  │ (is_dns, is_request, _) = probe(slice)          │
    │  │ if is_dns → return ALPROTO_DNS                  │
    │  └─────────────────────────────────────────────────┘
    │  返回 ALPROTO_DNS，引擎确认这是 DNS 流量
    ▼
[3] 首次解析：C 调用 state_new(NULL, ALPROTO_DNS)
    │  ┌─ Rust ──────────────────────────────────────────┐
    │  │ let state = DNSState::new();                    │
    │  │ Box::into_raw(Box::new(state)) → *mut c_void    │
    │  └─────────────────────────────────────────────────┘
    │  C 引擎拿到 void* state 指针
    ▼
[4] 解析请求：C 调用 parse_request(flow, state, pstate, stream_slice, NULL)
    │  ┌─ Rust ──────────────────────────────────────────┐
    │  │ let state = cast_pointer!(state, DNSState);     │
    │  │ let input = stream_slice.as_slice();             │
    │  │ // nom 解析：be_u16 读取头部、dns_parse_name     │
    │  │ //           解析查询/应答记录                    │
    │  │ let tx = DNSTransaction::new(Direction::ToServer);│
    │  │ tx.request = Some(message);                      │
    │  │ state.transactions.push_back(tx);                │
    │  │ return AppLayerResult::ok();                     │
    │  └─────────────────────────────────────────────────┘
    ▼
[5] 检测引擎：C 调用 get_tx(state, 0) 获取事务
    │  调用 SCDnsTxGetQueryName(de, tx, flags, 0, &buf, &len) 提取查询名
    │  ┌─ Rust ──────────────────────────────────────────┐
    │  │ *buf = query.name.value.as_ptr();  // 零拷贝    │
    │  │ *len = query.name.value.len();                  │
    │  └─────────────────────────────────────────────────┘
    │  C 引擎用 buf/len 做规则匹配
    ▼
[6] 日志输出：C 调用 SCDnsLogJson(tx, flags, jb)
    │  ┌─ Rust ──────────────────────────────────────────┐
    │  │ 将 DNSTransaction 序列化为 JSON                  │
    │  │ 写入 JsonBuilder                                 │
    │  └─────────────────────────────────────────────────┘
    ▼
[7] 事务清理：C 调用 state_tx_free(state, tx_id)
    │  ┌─ Rust ──────────────────────────────────────────┐
    │  │ state.transactions.retain(|tx| tx.id != tx_id)  │
    │  │ 被移除的 DNSTransaction 自动 Drop               │
    │  └─────────────────────────────────────────────────┘
    ▼
[8] 流结束：C 调用 state_free(state)
       ┌─ Rust ──────────────────────────────────────────┐
       │ Box::from_raw(state as *mut DNSState)           │
       │ 自动 Drop：DNSState 及其所有事务被释放            │
       └─────────────────────────────────────────────────┘
```

---

## 9. derive 宏生成的 FFI 代码

Suricata 的自定义 derive 宏大幅减少了 FFI 样板代码。

### 9.1 AppLayerEvent

```rust
#[derive(AppLayerEvent)]
pub enum DNSEvent {
    MalformedData,
    NotRequest,
    // ...
}
```

自动生成：

```rust
impl DNSEvent {
    // 事件名 → 事件 ID（C 调用）
    pub extern "C" fn get_event_info(
        event_name: *const c_char,
        event_id: *mut c_int,
        event_type: *mut AppLayerEventType,
    ) -> c_int { ... }

    // 事件 ID → 事件名（C 调用）
    pub extern "C" fn get_event_info_by_id(
        event_id: c_int,
        event_name: *mut *const c_char,
        event_type: *mut AppLayerEventType,
    ) -> i8 { ... }
}
```

### 9.2 AppLayerFrameType

```rust
#[derive(AppLayerFrameType)]
pub enum DnsFrameType {
    Pdu,
}
```

自动生成 `ffi_id_from_name` 和 `ffi_name_from_id` 函数，注册到 `RustParser` 的 `get_frame_id_by_name` / `get_frame_name_by_id`。

### 9.3 export_tx_data_get! 宏

```rust
// 为每个协议类型生成获取 AppLayerTxData 的 FFI 函数
export_tx_data_get!(rs_dns_get_tx_data, DNSTransaction);

// 展开为：
unsafe extern "C" fn rs_dns_get_tx_data(
    tx: *mut std::os::raw::c_void
) -> *mut AppLayerTxData {
    let tx = &mut *(tx as *mut DNSTransaction);
    &mut tx.tx_data
}
```

---

## 10. 常见陷阱与最佳实践

### 10.1 CString 生命周期

```rust
// 错误！CString 是临时变量，as_ptr() 返回悬垂指针
let ptr = CString::new("dns").unwrap().as_ptr();  // CString 在这行末尾被释放

// 正确：先绑定到变量
let name = CString::new("dns").unwrap();
let ptr = name.as_ptr();  // name 存活期间 ptr 有效
```

### 10.2 不透明类型 vs repr(C) 类型

- 内部结构会变化的类型（`DNSState`、`DNSTransaction`）→ **不加** `#[repr(C)]`，C 侧只用不透明指针
- 需要 C 直接读写字段的类型（`AppLayerResult`、`StreamSlice`）→ **必须加** `#[repr(C)]`

### 10.3 避免跨 FFI 传递 Rust 独有类型

以下类型**不能**跨 FFI 边界：

| 不能传递 | 替代方案 |
|---------|---------|
| `String` | `*mut c_char`（通过 `CString::into_raw()`） |
| `Vec<u8>` | `*const u8` + `u32 len` |
| `&str` | `*const c_char` |
| `Option<T>`（非函数指针） | 用 NULL 表示 None |
| `Result<T, E>` | `AppLayerResult` 或返回码 |
| `enum`（携带数据的） | 拆为 tag + 数据指针 |

### 10.4 unsafe 的最小化原则

Suricata 的模式是：**FFI 函数用 unsafe 壳包裹安全的 Rust 核心逻辑**。

```rust
// FFI 入口（unsafe）
pub(crate) unsafe extern "C" fn parse_request(
    flow: *mut Flow, state: *mut c_void,
    _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, DNSState);    // unsafe：指针转引用
    state.parse_request_udp(flow, stream_slice);   // 调用安全的 Rust 方法
    AppLayerResult::ok()
}

// 安全的核心逻辑（无 unsafe）
impl DNSState {
    fn parse_request_udp(&mut self, flow: *mut Flow, stream_slice: StreamSlice) {
        let input = stream_slice.as_slice();
        // 全部用安全 Rust 实现：nom 解析、Vec 操作、模式匹配...
    }
}
```

---

## 11. DNS 模块的 FFI 函数全景

最后，给出 DNS 模块所有 FFI 函数的分类汇总，方便你在开发新协议时参照：

| 类别 | 函数 | 文件:行号 | `#[no_mangle]` |
|------|------|-----------|----------------|
| **注册** | `SCRegisterDnsUdpParser` | `dns.rs:1277` | 是 |
| | `SCRegisterDnsTcpParser` | `dns.rs:1324` | 是 |
| **状态** | `state_new` | `dns.rs:918` | 否 |
| | `state_free` | `dns.rs:928` | 否 |
| | `state_tx_free` | `dns.rs:933` | 否 |
| **探测** | `probe_udp` | `dns.rs:1217` | 否 |
| | `c_probe_tcp` | `dns.rs:1237` | 否 |
| **解析** | `parse_request` | `dns.rs:939` | 否 |
| | `parse_response` | `dns.rs:948` | 否 |
| | `parse_request_tcp` | `dns.rs:958` | 否 |
| | `parse_response_tcp` | `dns.rs:971` | 否 |
| **事务** | `tx_get_alstate_progress` | `dns.rs:984` | 否 |
| | `state_get_tx_count` | `dns.rs:993` | 否 |
| | `state_get_tx` | `dns.rs:999` | 否 |
| | `state_get_tx_data` | `dns.rs:1023` | 否 |
| | `dns_get_state_data` | `dns.rs:1030` | 否 |
| **检测辅助** | `SCDnsTxIsRequest` | `dns.rs:1013` | 是 |
| | `SCDnsTxIsResponse` | `dns.rs:1018` | 是 |
| | `SCDnsTxGetQueryName` | `dns.rs:1039` | 是 |
| | `SCDnsTxGetAnswerName` | `dns.rs:1066` | 是 |
| | `SCDnsTxGetResponseFlags` | `dns.rs:1213` | 是 |
| **配置** | `apply_tx_config` | `dns.rs:1260` | 否 |
| **日志** | `SCDnsLogJson` | `log.rs:937` | 是 |
| | `SCDnsLogEnabled` | `log.rs:944` | 是 |
| | `SCDnsLogJsonQuery` | `log.rs:796` | 是 |
| | `SCDnsLogJsonAnswer` | `log.rs:964` | 是 |
| **检测注册** | `SCDetectDNSRegister` | `detect.rs:349` | 是 |
| **Lua** | `SCDnsLuaGetTxId` 等 6 个 | `lua.rs` | 是 |

规律：
- **通过函数指针传递的回调** → `pub(crate) extern "C"`，不需要 `#[no_mangle]`
- **被 C 代码直接按名调用的** → `#[no_mangle] pub extern "C"`

---

## 12. 下一步

本篇详解了 C-Rust FFI 边界的设计模式。接下来：

- **第 19 篇 Rust 协议解析器深度剖析**：以 DNS 为例，完整走读 Rust 侧的解析逻辑——从 `parse_request_udp` 进入，经过 nom 解析，到事务生成
- **第 22 篇 开发新协议解析器（Rust 版）**：用本篇的 FFI 模式，从零实现一个新协议

**动手建议**：

1. 阅读 `rust/cbindgen.toml`，理解哪些类型被导出、哪些被排除
2. 在 `rust/gen/rust-bindings.h` 中搜索 `SCDns`，查看 cbindgen 生成的所有 DNS 声明
3. 对比 DNS（`rust/src/dns/dns.rs`）和 DNP3（`rust/src/dnp3/`）的注册函数，观察不同协议的注册模式有何异同
4. 尝试在 `state_new` 中加一行 `SCLogDebug!("DNS state created")`，重新编译运行，验证 FFI 调用链路
