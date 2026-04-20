# 12 - 应用层协议检测与解析

> **导读**：上一篇剖析了流处理与 TCP 重组引擎如何将乱序的 TCP 段拼接成有序的字节流。本篇聚焦 Suricata 的**应用层框架**——它如何自动识别上百种应用协议、如何将重组后的字节流交给具体的协议解析器、事务（Transaction）模型如何工作，以及 C 与 Rust 解析器的注册机制。理解这一层，是读懂检测引擎（第 13-14 篇）和编写自定义解析器（第 21-22 篇）的前提。

---

## 1. 应用层在流水线中的位置

回顾 FlowWorker 流水线，应用层处理紧跟 TCP 重组之后：

```
[Decode] → FlowWorker {
    ① FlowHandlePacket()            ← 流查找/创建
    ② StreamTcpPacket()             ← TCP 状态机 + 段存储
    ③ StreamTcpReassembleHandleSegment()
        → AppLayerHandleTCPData()   ← 应用层入口（本篇重点）
    ④ AppLayerHandleUdp()           ← UDP 应用层入口（本篇重点）
    ⑤ Detect()                      ← 规则检测
    ⑥ OutputLoggerLog()             ← 日志输出
}
```

应用层框架承担两项核心职责：

1. **协议检测（Protocol Detection）**：从流的前 N 个字节自动识别应用层协议
2. **协议解析（Protocol Parsing）**：将字节流解析为结构化的协议状态和事务

---

## 2. 协议标识体系

### 2.1 AppProto 枚举

每种应用协议都有一个全局唯一的整数标识 `AppProto`，定义在 `src/app-layer-protos.h:28-82`：

```c
// src/app-layer-protos.h:28-82
enum AppProtoEnum {
    ALPROTO_UNKNOWN = 0,
    ALPROTO_FAILED  = 1,    // 检测永久失败

    // 真正的协议从这里开始
    ALPROTO_HTTP1,           // HTTP/1.x（使用 libhtp）
    ALPROTO_FTP,
    ALPROTO_SMTP,
    ALPROTO_TLS,             // SSLv2/v3 + TLSv1.x
    ALPROTO_SSH,
    ALPROTO_IMAP,
    ALPROTO_SMB,
    ALPROTO_DCERPC,
    ALPROTO_DNS,
    ALPROTO_MODBUS,          // 工控协议
    ALPROTO_NFS,
    ALPROTO_QUIC,
    ALPROTO_MQTT,
    ALPROTO_HTTP2,
    ALPROTO_WEBSOCKET,
    ALPROTO_LDAP,
    ALPROTO_POP3,
    // ... 共 30+ 种静态协议

    ALPROTO_HTTP,            // 仅用于签名：匹配 HTTP1 或 HTTP2
    ALPROTO_MAX_STATIC,      // 静态协议上限
    // 之后可以动态注册（如 SNMP 插件）
};

typedef uint16_t AppProto;   // 实际类型是 16 位无符号整数
extern AppProto g_alproto_max;
```

关键设计点：

- **`ALPROTO_UNKNOWN`（0）**：尚未检测
- **`ALPROTO_FAILED`（1）**：检测已完成但未识别出任何协议
- **静态 + 动态混合**：内置协议有固定编号（编译时确定），插件协议通过 `AppProtoNewProtoFromString()` 在运行时动态分配编号
- **签名专用协议**：`ALPROTO_HTTP` 不代表具体协议，而是在规则中同时匹配 HTTP/1 和 HTTP/2

### 2.2 协议匹配逻辑

`AppProtoEquals()` 函数（`src/app-layer-protos.h:95-117`）实现了灵活的协议匹配，处理了 DOH2（DNS over HTTP/2）等特殊关系：

```c
// src/app-layer-protos.h:95-117（简化展示）
static inline bool AppProtoEquals(AppProto sigproto, AppProto alproto) {
    if (sigproto == alproto) return true;
    switch (sigproto) {
        case ALPROTO_DNS:
            return (alproto == ALPROTO_DOH2);   // DNS 签名也匹配 DOH2 流
        case ALPROTO_HTTP:
            return (alproto == ALPROTO_HTTP1) || (alproto == ALPROTO_HTTP2);
        case ALPROTO_DCERPC:
            return (alproto == ALPROTO_SMB);     // DCERPC 签名匹配 SMB 流
        // ...
    }
    return false;
}
```

---

## 3. 协议检测引擎

协议检测是应用层框架最精密的部分。Suricata 提供了三种检测机制，按优先级依次尝试：

```
AppLayerProtoDetectGetProto()         // src/app-layer-detect-proto.c:1395
    ├── ① PM: 模式匹配（Pattern Matching）
    ├── ② PP: 探测解析器（Probing Parsers）
    └── ③ PE: 协议期望（Protocol Expectations）
```

### 3.1 全局检测上下文

协议检测的核心数据结构定义在 `src/app-layer-detect-proto.c:144-168`：

```c
// src/app-layer-detect-proto.c:144-168
typedef struct AppLayerProtoDetectCtx_ {
    // 按 IP 协议（TCP/UDP）分组的模式匹配上下文
    AppLayerProtoDetectCtxIpproto ctx_ipp[FLOW_PROTO_DEFAULT];

    // 全局 SPM（Single Pattern Matcher）线程上下文原型
    SpmGlobalThreadCtx *spm_global_thread_ctx;

    // 探测解析器链表（按 IP 协议组织）
    AppLayerProtoDetectProbingParser *ctx_pp;

    // 已注册的协议名称表
    const char **alproto_names;

    // 协议期望表（如 FTP 数据通道）
    uint8_t *expectation_proto;
} AppLayerProtoDetectCtx;
```

每个 IP 协议方向都有一个 `AppLayerProtoDetectPMCtx`（`src/app-layer-detect-proto.c:120-134`），包含一个多模式匹配引擎（MPM）上下文和模式 → 签名的映射表。

### 3.2 机制一：模式匹配（PM）

PM 是最快的检测手段。协议通过注册特征字符串来识别，例如 HTTP 注册 `"HTTP/"` 和 `"GET "`，TLS 注册 Client Hello 的魔数字节。

**注册 API**（`src/app-layer-detect-proto.h:81-91`）：

```c
// 注册大小写敏感模式
int SCAppLayerProtoDetectPMRegisterPatternCS(
    uint8_t ipproto, AppProto alproto,
    const char *pattern, uint16_t depth, uint16_t offset,
    uint8_t direction);

// 注册大小写不敏感模式
int SCAppLayerProtoDetectPMRegisterPatternCI(...);

// 注册模式 + 探测解析器组合
int SCAppLayerProtoDetectPMRegisterPatternCSwPP(...);
```

**检测过程**（`src/app-layer-detect-proto.c:272-304`）：

```
PMGetProtoInspect()
    ├── 计算 searchlen = min(buflen, mpm_ctx.maxdepth)
    ├── 调用 MPM 多模式匹配引擎扫描 buffer
    ├── 遍历匹配到的 pattern，逐一验证：
    │   └── AppLayerProtoDetectPMMatchSignature()
    │       ├── 检查 offset/depth 范围
    │       ├── SPM 精确验证模式
    │       ├── 如果有关联的 PPFunc，调用探测解析器二次确认
    │       └── 处理方向翻转（reverse_flow）
    └── 返回匹配的 alproto
```

PM 的核心优势是**批量扫描**：MPM 引擎（Aho-Corasick 或 Hyperscan）一次扫描可同时匹配所有已注册的协议模式，O(n) 复杂度与模式数量无关。

### 3.3 机制二：探测解析器（PP）

PP 是基于端口的检测机制。对于每个端口，注册一组协议的探测函数，按需调用：

**三层数据结构**（`src/app-layer-detect-proto.c:68-106`）：

```c
// 探测解析器元素：一个协议的探测配置
typedef struct AppLayerProtoDetectProbingParserElement_ {
    AppProto alproto;
    uint16_t min_depth;              // 最小数据量
    uint16_t max_depth;              // 最大探测深度
    ProbingParserFPtr ProbingParserTs;  // toserver 方向探测函数
    ProbingParserFPtr ProbingParserTc;  // toclient 方向探测函数
    struct AppLayerProtoDetectProbingParserElement_ *next;
} AppLayerProtoDetectProbingParserElement;

// 探测解析器端口：一个端口上的所有探测器
typedef struct AppLayerProtoDetectProbingParserPort_ {
    uint16_t port;
    bool use_ports;                  // 是否基于端口触发
    uint16_t dp_max_depth;           // 目的端口方向最大探测深度
    AppLayerProtoDetectProbingParserElement *dp;  // 目的端口探测链表
    AppLayerProtoDetectProbingParserElement *sp;  // 源端口探测链表
    struct AppLayerProtoDetectProbingParserPort_ *next;
} AppLayerProtoDetectProbingParserPort;

// 探测解析器：按 IP 协议组织
typedef struct AppLayerProtoDetectProbingParser_ {
    uint8_t ipproto;
    AppLayerProtoDetectProbingParserPort *port;
    struct AppLayerProtoDetectProbingParser_ *next;
} AppLayerProtoDetectProbingParser;
```

**探测函数签名**（`src/app-layer-detect-proto.h:34-35`）：

```c
typedef AppProto (*ProbingParserFPtr)(
    const Flow *f, uint8_t flags,
    const uint8_t *input, uint32_t input_len,
    uint8_t *rdir);    // 输出参数：检测到的实际方向
```

**PP 检测流程**（`src/app-layer-detect-proto.c:528-627`）：

```
AppLayerProtoDetectPPGetProto()
    ├── 根据 dp/sp 查找注册的探测解析器
    ├── 如果有 alproto_expect（协议升级场景），
    │   优先查找期望协议的探测器 → pe0
    ├── 查找 dp 注册的探测器 → pe1
    ├── 查找 sp 注册的探测器 → pe2
    ├── 遍历 pe0 → pe1 → pe2，依次调用探测函数
    │   ├── 检查 min_depth / max_depth
    │   ├── 调用 ProbingParserTs/Tc(flow, flags, buf, buflen, &rdir)
    │   ├── 返回具体 ALPROTO = 匹配成功
    │   ├── 返回 ALPROTO_UNKNOWN = 数据不够，继续等待
    │   └── 返回 ALPROTO_FAILED = 确认不是此协议
    ├── 使用 alproto_masks 位掩码跟踪已尝试的协议
    └── midstream 场景：交换端口重试
```

**alproto_masks 的巧妙设计**：Flow 中的 `probing_parser_toserver_alproto_masks` 和 `probing_parser_toclient_alproto_masks`（各 32 位）记录了哪些探测器已经返回 `ALPROTO_FAILED`。当所有相关探测器都失败后，整体标记为 `ALPROTO_FAILED`，避免后续数据包重复探测。

### 3.4 机制三：协议期望（PE）

PE 用于处理关联流的协议识别，典型场景是 FTP 数据通道：

1. FTP 控制通道解析到 `PASV` 应答，得知数据端口
2. 调用 `AppLayerExpectationCreate()` 注册期望：源 IP + 目的 IP + 目的端口 → `ALPROTO_FTPDATA`
3. 当新流匹配到期望条件时，`AppLayerProtoDetectPEGetProto()` 直接返回 `ALPROTO_FTPDATA`

### 3.5 三种机制的优先级

`AppLayerProtoDetectGetProto()`（`src/app-layer-detect-proto.c:1395-1439`）按以下顺序执行：

```c
// src/app-layer-detect-proto.c:1395-1439
AppProto AppLayerProtoDetectGetProto(...) {
    AppProto alproto = ALPROTO_UNKNOWN;

    // 1. 先尝试 PM（模式匹配）
    if (!FLOW_IS_PM_DONE(f, flags)) {
        pm_matches = AppLayerProtoDetectPMGetProto(...);
        if (pm_matches > 0) {
            alproto = pm_results[0];
            return alproto;    // PM 命中，直接返回
        }
    }

    // 2. PM 无结果，尝试 PP（探测解析器）
    if (!FLOW_IS_PP_DONE(f, flags)) {
        alproto = AppLayerProtoDetectPPGetProto(...);
        if (AppProtoIsValid(alproto)) {
            return alproto;
        }
    }

    // 3. PP 也无结果，尝试 PE（协议期望）
    if (!FLOW_IS_PE_DONE(f, flags)) {
        alproto = AppLayerProtoDetectPEGetProto(f, flags);
    }

    return alproto;
}
```

每种机制都有对应的"完成"标志位（`FLOW_IS_PM_DONE`、`FLOW_IS_PP_DONE`、`FLOW_IS_PE_DONE`），一旦某个方向的检测完成（无论成功还是失败），不再重复执行。

---

## 4. TCP 应用层入口

### 4.1 AppLayerHandleTCPData

TCP 数据的应用层处理入口是 `AppLayerHandleTCPData()`（`src/app-layer.c:713-866`），由 TCP 重组引擎在拼接出新数据后调用：

```c
// src/app-layer.c:713-715
int AppLayerHandleTCPData(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
    Packet *p, Flow *f, TcpSession *ssn, TcpStream **stream,
    uint8_t *data, uint32_t data_len, uint8_t flags,
    enum StreamUpdateDir app_update_dir)
```

函数的主体逻辑是一个三路分支：

```c
// src/app-layer.c:778-859（简化）
if (alproto == ALPROTO_UNKNOWN && (flags & STREAM_START)) {
    // 路径 A：首次数据，运行协议检测
    TCPProtoDetect(tv, ra_ctx, app_tctx, p, f, ssn,
                   stream, data, data_len, flags, ...);

} else if (alproto != ALPROTO_UNKNOWN && FlowChangeProto(f)) {
    // 路径 B：协议升级（如 STARTTLS），重新检测
    AppLayerProtoDetectReset(f);
    TCPProtoDetect(...);  // 重新运行检测

} else {
    // 路径 C：协议已确定，直接解析
    if (f->alproto != ALPROTO_UNKNOWN) {
        r = AppLayerParserParse(tv, app_tctx->alp_tctx, f,
                                f->alproto, flags, data, data_len);
    }
}
```

**GAP 处理**：当 TCP 重组遇到间隙（丢包）时，带 `STREAM_GAP` 标志调用此函数。如果协议解析器注册了 `APP_LAYER_PARSER_OPT_ACCEPT_GAPS` 标志，间隙会被传递给解析器处理；否则解析器进入错误状态。

### 4.2 TCPProtoDetect

`TCPProtoDetect()`（`src/app-layer.c:394-703`）是 TCP 协议检测的核心函数，负责将检测结果应用到流上：

```
TCPProtoDetect()                    // src/app-layer.c:394
    ├── 调用 AppLayerProtoDetectGetProto()
    │   得到 alproto 和 reverse_flow
    │
    ├── 如果检测到协议：
    │   ├── 处理双方向协议不一致（APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS）
    │   ├── 设置 f->alproto = *alproto
    │   ├── 设置流的重组深度（stream_depth）
    │   ├── 如果 reverse_flow 且是 midstream：翻转流方向
    │   ├── 如果另一个方向的数据先到：触发对向流重组
    │   └── 调用 AppLayerParserParse() 解析本次数据
    │
    └── 如果未检测到：
        ├── midstream 且 toserver 方向已完成：放弃检测
        ├── 如果对向已检测到协议且本方向检测完成：
        │   使用对向协议，触发 APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION
        └── 否则检查是否需要放弃（TCPProtoDetectCheckBailConditions）
```

**方向翻转（Reverse Flow）**：midstream 场景中（没有捕获到 SYN），协议检测器可能发现 toserver/toclient 方向标反了。此时通过 `PacketSwap()` + `FlowSwap()` 翻转整个流的方向。

### 4.3 UDP 应用层入口

UDP 的处理更简单，因为没有流重组，每个数据包直接解析：

```c
// src/app-layer.c:880-979（简化）
int AppLayerHandleUdp(ThreadVars *tv, AppLayerThreadCtx *tctx,
                      Packet *p, Flow *f)
{
    // 1. 如果协议未知，运行检测
    if (*alproto == ALPROTO_UNKNOWN) {
        *alproto = AppLayerProtoDetectGetProto(
            tctx->alpd_tctx, f, p->payload, p->payload_len,
            IPPROTO_UDP, flags, &reverse_flow);

        // 处理检测结果：UNKNOWN / FAILED / 具体协议
        switch (*alproto) { ... }
    }

    // 2. 协议已知，调用解析器
    if (f->alproto != ALPROTO_UNKNOWN && f->alproto != ALPROTO_FAILED) {
        r = AppLayerParserParse(tv, tctx->alp_tctx, f, f->alproto,
                                flags, p->payload, p->payload_len);
    }
}
```

UDP 的特殊处理：

- 每个方向**独立检测**（`alproto_ts` 和 `alproto_tc` 可能不同步）
- 双向不一致时触发 `APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS` 事件
- 检测到 `reverse_flow` 时通过 `PacketSwap()` + `FlowSwap()` 翻转

---

## 5. 解析器框架

### 5.1 AppLayerParserProtoCtx — 解析器注册表

每种协议的解析器通过函数指针表注册到框架中。核心结构是 `AppLayerParserProtoCtx`（`src/app-layer-parser.c:88-128`）：

```c
// src/app-layer-parser.c:88-128（简化）
typedef struct AppLayerParserProtoCtx_ {
    // ====== 状态生命周期 ======
    void *(*StateAlloc)(void *, AppProto);   // 分配协议状态
    void (*StateFree)(void *);                // 释放协议状态

    // ====== 解析函数 ======
    AppLayerParserFPtr Parser[2];  // [0]=toserver, [1]=toclient

    // ====== 事务管理 ======
    uint64_t (*StateGetTxCnt)(void *alstate);
    void *(*StateGetTx)(void *alstate, uint64_t tx_id);
    void (*StateTransactionFree)(void *, uint64_t);
    int (*StateGetProgress)(void *alstate, uint8_t direction);
    int complete_ts;                          // toserver 完成进度值
    int complete_tc;                          // toclient 完成进度值

    // ====== 事件 ======
    int (*StateGetEventInfo)(const char *, uint8_t *, AppLayerEventType *);
    int (*StateGetEventInfoById)(uint8_t, const char **, AppLayerEventType *);

    // ====== 数据访问 ======
    AppLayerStateData *(*GetStateData)(void *state);
    AppLayerTxData *(*GetTxData)(void *tx);
    AppLayerGetFileState (*GetTxFiles)(void *, uint8_t);

    // ====== Frame 支持 ======
    AppLayerParserGetFrameIdByNameFn GetFrameIdByName;
    AppLayerParserGetFrameNameByIdFn GetFrameNameById;

    // ====== 配置 ======
    uint32_t stream_depth;          // 流深度限制
    uint32_t option_flags;          // 选项标志（如 ACCEPT_GAPS）
} AppLayerParserProtoCtx;
```

注册表通过二维数组索引：`alp_ctx.ctxs[alproto][protomap]`，其中 `protomap` 将 IP 协议号映射到 `FLOW_PROTO_TCP`(0)、`FLOW_PROTO_UDP`(1) 等紧凑索引。

### 5.2 解析函数签名

解析函数的统一签名（`src/app-layer-parser.h:131-132`）：

```c
typedef AppLayerResult (*AppLayerParserFPtr)(
    Flow *f,
    void *protocol_state,        // 协议自定义状态
    AppLayerParserState *pstate, // 框架管理的解析器状态
    StreamSlice stream_slice,    // 输入数据切片
    void *local_storage          // 线程局部存储
);
```

返回值 `AppLayerResult` 有三种结果（`src/app-layer-parser.h:77-89`）：

```c
#define APP_LAYER_OK         (AppLayerResult){ 0, 0, 0 }   // 全部消费
#define APP_LAYER_ERROR      (AppLayerResult){-1, 0, 0 }   // 不可恢复错误
#define APP_LAYER_INCOMPLETE(c,n) (AppLayerResult){ 1, (c), (n) }
    // 部分消费：c=已消费字节数, n=还需要的字节数
```

`APP_LAYER_INCOMPLETE` 是一个重要的背压机制——解析器可以告诉重组引擎"我需要更多数据才能继续"，这会设置 `TcpStream.data_required` 字段，让重组引擎在积累足够数据后再次调用解析器。

### 5.3 AppLayerParserState — 框架状态

每个流都有一个由框架管理的解析器状态（`src/app-layer-parser.c:135-153`）：

```c
// src/app-layer-parser.c:135-153
struct AppLayerParserState_ {
    uint16_t flags;              // 状态标志

    uint64_t inspect_id[2];      // 各方向当前正在检测的事务 ID
    uint64_t log_id;             // 当前正在日志记录的事务 ID
    uint64_t min_id;             // 最小有效事务 ID

    AppLayerDecoderEvents *decoder_events;  // 解析器事件
    FramesContainer *frames;     // Frame 容器
};
```

关键标志位（`src/app-layer-parser.h:48-57`）：

| 标志 | 含义 |
|------|------|
| `APP_LAYER_PARSER_NO_INSPECTION` | 不再检测此流 |
| `APP_LAYER_PARSER_NO_REASSEMBLY` | 不再重组此流 |
| `APP_LAYER_PARSER_BYPASS_READY` | 流可以旁路 |
| `APP_LAYER_PARSER_EOF_TS/TC` | 该方向已到达 EOF |
| `APP_LAYER_PARSER_SFRAME_TS/TC` | 该方向存在流帧（streaming frame） |

### 5.4 AppLayerParserParse — 解析主流程

`AppLayerParserParse()`（`src/app-layer-parser.c:1284-1434`）是所有解析的总入口：

```
AppLayerParserParse()                // src/app-layer-parser.c:1284
    │
    ├── 检查解析器是否注册（p->StateAlloc == NULL → 禁用 app-layer）
    │
    ├── 处理 GAP：
    │   如果协议不支持 ACCEPT_GAPS → 触发 raw stream 检测 → 返回错误
    │
    ├── 初始化 AppLayerParserState（首次解析时分配）
    │
    ├── 初始化协议状态：
    │   如果 f->alstate == NULL 或正在协议切换：
    │   └── alstate = p->StateAlloc(alstate, f->alproto_orig)
    │
    ├── 记录调用前的事务数量 p_tx_cnt
    │
    ├── 构造 StreamSlice 并调用解析器：
    │   res = p->Parser[direction](f, alstate, pstate, stream_slice, local_storage)
    │   │
    │   ├── res.status < 0: 错误 → 进入错误处理
    │   ├── res.status == 0: APP_LAYER_OK → 继续
    │   └── res.status > 0: APP_LAYER_INCOMPLETE
    │       ├── 验证 consumed/needed 的合法性
    │       └── 设置 ssn->client/server.data_required = res.needed
    │
    ├── 检查解析器设置的标志：
    │   ├── NO_INSPECTION → 禁用 app-layer + 可能禁用重组
    │   └── BYPASS_READY → 设置流旁路
    │
    └── 更新事务计数统计
```

解析器的协议状态（`f->alstate`）是由各协议自行定义和管理的。框架只负责调用 `StateAlloc` / `StateFree`，不关心内部结构。

---

## 6. 事务（Transaction）模型

事务是 Suricata 应用层的核心抽象。一个事务代表一次完整的应用层交互，例如一次 HTTP 请求-响应对、一次 DNS 查询-应答。

### 6.1 事务生命周期

```
                创建                    完成                    清理
                 │                       │                       │
    Parser ──── alloc tx ──── parse ──── complete_ts/tc ──── tx_free
                 │              │         │                      │
              updated=true   进度推进   inspect_id 追上        min_id 更新
```

关键接口：

```c
// 获取当前事务总数
uint64_t (*StateGetTxCnt)(void *alstate);

// 按 ID 获取事务指针
void *(*StateGetTx)(void *alstate, uint64_t tx_id);

// 获取事务的当前进度
int (*StateGetProgress)(void *alstate, uint8_t direction);

// 释放事务
void (*StateTransactionFree)(void *, uint64_t);
```

### 6.2 事务进度跟踪

每种协议定义自己的进度值。以 DNS 为例：

```
tx_comp_st_ts = 1   // toserver 方向进度为 1 时表示请求完整
tx_comp_st_tc = 1   // toclient 方向进度为 1 时表示应答完整
```

框架在检测和日志阶段使用 `complete_ts` / `complete_tc` 来判断事务是否可以进行检测和日志记录。

### 6.3 AppLayerTxData — 事务元数据

每个事务都必须包含一个 `AppLayerTxData` 结构（在 Rust 中定义，`rust/src/applayer.rs:107-151`），供框架管理检测和日志状态：

```rust
// rust/src/applayer.rs:107-151（简化）
pub struct AppLayerTxData {
    pub config: AppLayerTxConfig,     // 日志配置标志
    pub updated_tc: bool,             // toclient 方向有更新
    pub updated_ts: bool,             // toserver 方向有更新
    flags: u8,                        // 检测跳过/完成标志
    logged: LoggerFlags,              // 已日志记录标志
    pub files_opened: u32,            // 打开的文件数
    pub files_logged: u32,            // 已记录的文件数
    pub file_tx: u8,                  // 文件事务方向
    detect_progress_ts: u8,           // toserver 检测进度
    detect_progress_tc: u8,           // toclient 检测进度
    de_state: *mut DetectEngineState, // 检测引擎状态
    pub events: *mut AppLayerDecoderEvents,  // 解析器事件
}
```

`updated_ts` / `updated_tc` 字段是一个重要的优化：只有标记为"已更新"的事务才会被检测引擎重新评估，避免对未变化的事务做无用功。

### 6.4 事务清理

框架通过 `AppLayerParserTransactionsCleanup()` 定期清理已完成的事务。清理条件：事务 ID 小于 `min_id`，而 `min_id` 是 `inspect_id[0]`、`inspect_id[1]` 和 `log_id` 三者的最小值——即只有检测和日志都处理完毕的事务才会被释放。

---

## 7. StreamSlice — 数据传递接口

`StreamSlice` 是重组引擎向解析器传递数据的统一接口（`rust/src/applayer.rs:43-88`）：

```rust
// rust/src/applayer.rs:43-88
#[repr(C)]
pub struct StreamSlice {
    input: *const u8,     // 数据指针
    input_len: u32,       // 数据长度
    flags: u8,            // STREAM_* 标志
    offset: u64,          // 在流中的绝对偏移
}

impl StreamSlice {
    pub fn is_gap(&self) -> bool {
        self.input.is_null() && self.input_len > 0
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.input, self.input_len as usize) }
    }
}
```

`offset` 字段表示数据在整个流中的绝对位置。这对于 Frame 支持至关重要——Frame 可以使用绝对偏移定义自己在流中的位置和长度。

---

## 8. 协议注册流程

### 8.1 Rust 解析器注册（以 DNS 为例）

Rust 解析器通过填充 `RustParser` 结构体（`rust/src/applayer.rs:385-458`）并调用 C 侧的注册函数来接入框架。以 DNS/UDP 为例（`rust/src/dns/dns.rs:1277-1321`）：

```rust
// rust/src/dns/dns.rs:1277-1321
pub unsafe extern "C" fn SCRegisterDnsUdpParser() {
    let parser = RustParser {
        name: b"dns\0".as_ptr() as *const c_char,
        default_port: CString::new("[53]").unwrap().as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(probe_udp),          // UDP 探测函数
        probe_tc: Some(probe_udp),
        min_depth: 0,
        max_depth: std::mem::size_of::<DNSHeader>() as u16,
        state_new,                           // DNSState 分配
        state_free,                          // DNSState 释放
        parse_ts: parse_request,             // 请求解析
        parse_tc: parse_response,            // 应答解析
        get_tx_count: state_get_tx_count,
        get_tx: state_get_tx,
        tx_free: state_tx_free,
        tx_comp_st_ts: 1,                   // 完成进度
        tx_comp_st_tc: 1,
        tx_get_progress: tx_get_alstate_progress,
        get_eventinfo: Some(DNSEvent::get_event_info),
        get_tx_data: state_get_tx_data,
        get_state_data: dns_get_state_data,
        flags: 0,                            // UDP 不需要 ACCEPT_GAPS
        get_frame_id_by_name: Some(DnsFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(DnsFrameType::ffi_name_from_id),
        // ...
    };

    // 步骤 1：检查配置中是否启用此协议
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str, parser.name) != 0 {
        // 步骤 2：注册协议检测（探测函数 + 端口）
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_DNS = alproto;

        if SCAppLayerParserConfParserEnabled(ip_proto_str, parser.name) != 0 {
            // 步骤 3：注册解析器
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}
```

DNS/TCP 版本类似，但 `flags` 设置了 `APP_LAYER_PARSER_OPT_ACCEPT_GAPS`（`rust/src/dns/dns.rs:1353`），因为 TCP 可能有间隙。

### 8.2 C 侧注册桥接

`AppLayerRegisterProtocolDetection()`（`src/app-layer-register.c:39-91`）和 `AppLayerRegisterParser()`（`src/app-layer-register.c:93-193`）是 C 侧的桥接函数，负责将 `RustParser` 的各字段分发到不同的子系统：

```
AppLayerRegisterProtocolDetection()     // src/app-layer-register.c:39
    ├── StringToAppProto(name) → alproto
    ├── AppLayerProtoDetectRegisterProtocol(alproto, name)
    ├── 读取配置文件中的端口列表
    └── SCAppLayerProtoDetectPPRegister(ipproto, ports, alproto,
            min_depth, max_depth, STREAM_TOSERVER, ProbeTS, ProbeTC)

AppLayerRegisterParser()                // src/app-layer-register.c:93
    ├── AppLayerParserRegisterStateFuncs(StateAlloc, StateFree)
    ├── AppLayerParserRegisterParser(STREAM_TOSERVER, ParseTS)
    ├── AppLayerParserRegisterParser(STREAM_TOCLIENT, ParseTC)
    ├── AppLayerParserRegisterTxFreeFunc(StateTransactionFree)
    ├── AppLayerParserRegisterGetTxCnt(StateGetTxCnt)
    ├── AppLayerParserRegisterGetTx(StateGetTx)
    ├── AppLayerParserRegisterStateProgressCompletionStatus(ts, tc)
    ├── AppLayerParserRegisterGetStateProgressFunc(StateGetProgress)
    ├── AppLayerParserRegisterGetEventInfo(...)
    ├─ AppLayerParserRegisterGetTxFilesFunc(...)    // 如果支持文件
    ├── AppLayerParserRegisterOptionFlags(flags)     // ACCEPT_GAPS 等
    └── AppLayerParserRegisterGetFrameFuncs(...)     // Frame 支持
```

每个 `Register` 函数最终都是将函数指针存入 `AppLayerParserProtoCtx` 的对应字段。

### 8.3 协议注册初始化时序

```
SuricataInit()
    → AppLayerSetup()
        → AppLayerProtoDetectSetup()     // 初始化检测上下文
        → AppLayerParserSetup()          // 初始化解析器上下文
        → AppLayerParserRegisterProtocolParsers()
            → RegisterHTPParsers()       // HTTP/1.x（C 实现）
            → SCRegisterDnsUdpParser()   // DNS/UDP（Rust）
            → SCRegisterDnsTcpParser()   // DNS/TCP（Rust）
            → SCRegisterSmtpParser()     // SMTP
            → SCRegisterTlsParser()      // TLS
            → ...（30+ 种协议）
        → AppLayerProtoDetectPrepareState()  // 编译 MPM 模式
```

`AppLayerProtoDetectPrepareState()`（`src/app-layer-detect-proto.c:1483`）在所有协议注册完成后，将所有 PM 模式编译到 MPM 引擎中（通常是 Aho-Corasick 自动机），生成可供高效多模式匹配的内部状态。

---

## 9. 协议升级机制

某些场景需要在一个 TCP 连接上切换应用层协议，例如 STARTTLS（SMTP → TLS）和 HTTP Upgrade（HTTP/1 → WebSocket）。

### 9.1 STARTTLS

当 SMTP 解析器检测到 `STARTTLS` 命令并收到服务端 `220` 确认后，调用：

```c
// src/app-layer-detect-proto.c:1833-1836
bool SCAppLayerRequestProtocolTLSUpgrade(Flow *f) {
    return AppLayerRequestProtocolChange(f, 443, ALPROTO_TLS);
}
```

`AppLayerRequestProtocolChange()`（`src/app-layer-detect-proto.c:1802-1823`）执行以下操作：

```c
bool AppLayerRequestProtocolChange(Flow *f, uint16_t dp, AppProto expect_proto) {
    if (FlowChangeProto(f)) return false;  // 不允许嵌套协议切换
    FlowSetChangeProtoFlag(f);             // 设置"正在切换"标志
    f->protodetect_dp = dp;                // 设置检测端口为 443
    f->alproto_expect = expect_proto;      // 期望 TLS
    f->alproto_orig = f->alproto;          // 保存原始协议
    return true;
}
```

之后 `AppLayerHandleTCPData()` 的路径 B 会被触发：

1. 清理旧解析器状态
2. 重置 PM/PP/PE 完成标志
3. 重新运行 `TCPProtoDetect()` — 由于 `protodetect_dp=443`，TLS 的探测解析器会被选中
4. 如果新协议与 `alproto_expect` 不匹配，触发 `APPLAYER_UNEXPECTED_PROTOCOL` 事件

### 9.2 强制协议变更

某些场景不需要重新检测，而是直接切换：

```c
// src/app-layer-detect-proto.c:1844-1852
void SCAppLayerForceProtocolChange(Flow *f, AppProto new_proto) {
    if (new_proto != f->alproto) {
        f->alproto_orig = f->alproto;
        f->alproto = new_proto;
        f->alproto_ts = new_proto;
        f->alproto_tc = new_proto;
    }
}
```

典型用例：HTTP/2 流检测到 DNS 查询后，协议从 `ALPROTO_HTTP2` 变更为 `ALPROTO_DOH2`（DNS over HTTP/2）。

---

## 10. 线程上下文

### 10.1 AppLayerThreadCtx

每个工作线程持有一个 `AppLayerThreadCtx`（`src/app-layer.c:59-74`），包含协议检测和解析两个子上下文：

```c
// src/app-layer.c:59-74
struct AppLayerThreadCtx_ {
    AppLayerProtoDetectThreadCtx *alpd_tctx;  // 检测线程上下文
    AppLayerParserThreadCtx *alp_tctx;        // 解析器线程上下文
#ifdef PROFILING
    uint64_t ticks_start, ticks_end, ticks_spent;
    AppProto alproto;
#endif
};
```

**检测线程上下文**（`src/app-layer-detect-proto.c:179-184`）：

```c
struct AppLayerProtoDetectThreadCtx_ {
    PrefilterRuleStore pmq;                    // MPM 匹配结果存储
    MpmThreadCtx mpm_tctx[FLOW_PROTO_DEFAULT][2];  // MPM 线程上下文
    SpmThreadCtx *spm_thread_ctx;              // SPM 线程上下文
};
```

每个线程都有自己的 MPM/SPM 上下文，避免了锁竞争。这也是 Suricata 高性能的关键设计之一。

---

## 11. 端到端数据流

总结一个 TCP 数据包从到达到完成应用层解析的完整数据流：

```
                                      首包
 Packet                            ┌─────────┐
   │                               │ 协议检测 │
   ▼                               └────┬────┘
 FlowWorker                             │ alproto 确定
   │                                    ▼
   ├── FlowHandlePacket()          后续包
   │     → 查找/创建 Flow            ┌─────────┐
   │                                │ 直接解析 │
   ├── StreamTcpPacket()            └────┬────┘
   │     → TCP 状态机处理                 │
   │                                    ▼
   ├── StreamTcpReassembleHandleSegment()
   │     → 段存储 + 重组                 ┌─────────────────┐
   │     → 调用回调:                    │ AppLayerParserParse │
   │       AppLayerHandleTCPData()      └────────┬────────┘
   │         │                                    │
   │         ├── TCPProtoDetect()                 │
   │         │     → AppLayerProtoDetectGetProto()│
   │         │       ├── PM (MPM 多模匹配)       │
   │         │       ├── PP (探测解析器)          │
   │         │       └── PE (协议期望)            │
   │         │                                    │
   │         └── AppLayerParserParse()            │
   │               ├── StateAlloc (首次)          │
   │               ├── Parser[dir]() ─────────────┘
   │               │     → 创建/更新事务
   │               │     → 返回 OK/ERROR/INCOMPLETE
   │               └── 更新 pstate 标志
   │
   ├── Detect()        ← 使用事务进行规则匹配
   └── OutputLoggerLog() ← 使用事务生成日志
```

---

## 12. 支持的协议总览

Suricata 8.0.3 内置支持 30+ 种应用层协议：

| 协议 | 实现语言 | IP 协议 | 说明 |
|------|----------|---------|------|
| HTTP/1.x | C (libhtp) | TCP | 最成熟的解析器 |
| HTTP/2 | Rust | TCP | 支持 HPACK/HUFF 解压 |
| TLS/SSL | Rust | TCP | 支持 JA3/JA4 指纹 |
| DNS | Rust | TCP/UDP | 支持 DOH2 关联 |
| SMTP | Rust | TCP | 支持 STARTTLS 升级 |
| FTP/FTP-DATA | C | TCP | 通过 Expectation 关联数据通道 |
| SSH | Rust | TCP | |
| SMB/DCERPC | Rust | TCP | 管道协议 |
| NFS | Rust | TCP | |
| QUIC | Rust | UDP | 支持 SNI 提取 |
| MQTT | Rust | TCP | IoT 协议 |
| Modbus | Rust | TCP | 工控协议 |
| DNP3 | Rust | TCP | 工控协议 |
| WebSocket | Rust | TCP | 通过 HTTP Upgrade 关联 |
| LDAP | Rust | TCP | |
| POP3 | Rust | TCP | |
| PostgreSQL | Rust | TCP | |
| RDP | Rust | TCP | |
| Telnet | Rust | TCP | |
| SIP | Rust | UDP | |
| DHCP | Rust | UDP | |
| KRB5 | Rust | TCP/UDP | |
| TFTP | Rust | UDP | |
| IKE | Rust | UDP | |
| BitTorrent DHT | Rust | UDP | |

可以看到，Rust 已经成为 Suricata 新增协议解析器的主要实现语言。

---

## 13. 配置要点

应用层相关的 YAML 配置主要在 `app-layer` 节：

```yaml
app-layer:
  protocols:
    http:
      enabled: yes
      # 解析器参数
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    smtp:
      enabled: yes
      # MIME 解码配置
      mime:
        decode-mime: yes
        decode-base64: yes

  # 应用层错误策略
  error-policy: drop-flow   # IPS 模式下解析错误时丢弃流
```

`detection-ports` 配置的端口会被传递给 `SCAppLayerProtoDetectPPParseConfPorts()`，决定在哪些端口上运行探测解析器。如果没有配置，使用协议注册时的 `default_port`。

---

## 14. 小结

本篇剖析了 Suricata 应用层框架的完整架构：

- **协议标识**：`AppProto` 枚举支持 30+ 种静态协议和动态扩展
- **三级协议检测**：PM（模式匹配）→ PP（探测解析器）→ PE（协议期望），层层递进
- **统一解析接口**：`AppLayerParserParse()` 通过函数指针表分发到各协议解析器
- **事务模型**：请求-响应对被抽象为事务，每个事务携带 `AppLayerTxData` 元数据供检测和日志使用
- **协议升级**：`AppLayerRequestProtocolChange()` 支持 STARTTLS、HTTP Upgrade 等场景
- **C/Rust 双轨**：新协议普遍使用 Rust 实现，通过 `RustParser` 结构体桥接到 C 框架

下一篇我们将进入检测引擎，看看规则如何加载、`Signature` 结构如何构建——应用层解析出的事务和缓冲区，最终将在检测引擎中被规则匹配。

---

> **源码索引**
>
> | 文件 | 关键内容 |
> |------|----------|
> | `src/app-layer-protos.h:28-82` | AppProto 枚举定义 |
> | `src/app-layer-protos.c:81-105` | 动态协议注册 |
> | `src/app-layer-detect-proto.c:68-168` | 探测解析器数据结构 + 全局检测上下文 |
> | `src/app-layer-detect-proto.c:272-325` | PM 模式匹配检测 |
> | `src/app-layer-detect-proto.c:528-627` | PP 探测解析器检测 |
> | `src/app-layer-detect-proto.c:1395-1439` | AppLayerProtoDetectGetProto 总入口 |
> | `src/app-layer-detect-proto.c:1802-1870` | 协议变更 + 重置 |
> | `src/app-layer.c:59-74` | AppLayerThreadCtx 线程上下文 |
> | `src/app-layer.c:394-703` | TCPProtoDetect TCP 协议检测 |
> | `src/app-layer.c:713-866` | AppLayerHandleTCPData 入口 |
> | `src/app-layer.c:880-979` | AppLayerHandleUdp UDP 入口 |
> | `src/app-layer-parser.c:88-128` | AppLayerParserProtoCtx 解析器注册表 |
> | `src/app-layer-parser.c:135-153` | AppLayerParserState 框架状态 |
> | `src/app-layer-parser.c:1284-1434` | AppLayerParserParse 解析主流程 |
> | `src/app-layer-register.c:39-193` | 协议注册桥接函数 |
> | `rust/src/applayer.rs:43-88` | StreamSlice 定义 |
> | `rust/src/applayer.rs:107-151` | AppLayerTxData 事务元数据 |
> | `rust/src/applayer.rs:385-458` | RustParser 结构体 |
> | `rust/src/dns/dns.rs:1277-1368` | DNS 解析器注册示例 |
