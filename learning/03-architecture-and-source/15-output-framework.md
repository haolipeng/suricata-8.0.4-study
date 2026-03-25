# 15 - 输出框架与 EVE JSON 生成

> **导读**：前两篇剖析了检测引擎的规则加载和运行时匹配——数据包在经过解码、流重组、应用层解析和检测之后，最后一站便是输出框架。本篇聚焦 Suricata 如何将检测结果、协议日志、流记录和统计信息统一输出，特别是 EVE JSON 这一核心输出格式的生成管线。输出框架采用三层分发架构——RootLogger → 类型调度器 → 具体日志模块，通过模块注册、条件过滤和进度追踪实现灵活的日志路由。

---

## 1. 输出框架总览

### 1.1 三层架构

Suricata 的输出框架是一个分层分发系统。每个数据包处理完毕后，通过一次 `OutputLoggerLog()` 调用触发整个输出管线：

```
┌─────────────────────────────────────────────────────────────────┐
│  数据包处理线程                                                  │
│                                                                 │
│  OutputLoggerLog(tv, p, thread_data)                            │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────────────── RootLogger 层 ─────────────────────┐    │
│  │  active_loggers (TAILQ)                                 │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │    │
│  │  │ Packet   │ │ Tx       │ │ File     │ │Streaming │  │    │
│  │  │ Logger   │ │ Logger   │ │ Logger   │ │ Logger   │  │    │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │    │
│  └───────┼─────────────┼────────────┼────────────┼────────┘    │
│          ▼             ▼            ▼            ▼              │
│  ┌──── 类型调度器层 ──────────────────────────────────────┐    │
│  │  OutputPacketLog  OutputTxLog  OutputFileLogFfc  ...    │    │
│  │       │              │            │                     │    │
│  └───────┼──────────────┼────────────┼─────────────────────┘    │
│          ▼              ▼            ▼                          │
│  ┌──── 具体日志模块层 ─────────────────────────────────────┐    │
│  │  json-alert    json-http   json-file   json-flow  ...   │    │
│  │  fast-log      json-dns   filestore   json-stats  ...   │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

**第一层 RootLogger**：全局注册的根日志器列表，按类型（Packet/Tx/File/Filedata/Streaming）分类，由 `OutputLoggerLog()` 统一遍历调用。

**第二层类型调度器**：每种根日志器内部维护自己的具体日志模块链表（如 `OutputPacketLogger` 链表），负责条件检查和逐模块分发。

**第三层具体日志模块**：实际产生输出的模块，如 `json-alert`、`json-http`、`pcap-log` 等，最终将数据写入 EVE JSON 文件、syslog、Redis 等后端。

### 1.2 核心源文件关系

| 文件 | 作用 |
|------|------|
| `src/output.h` | `OutputModule` 结构体、注册函数声明 |
| `src/output.c` | RootLogger 管理、`OutputLoggerLog` 分发、模块注册 |
| `src/output-packet.c` | 包日志器调度 |
| `src/output-tx.c` | 事务日志器调度 |
| `src/output-flow.h` | 流日志器接口 |
| `src/output-json.h/c` | EVE JSON 核心：初始化、头部生成、输出管线 |
| `src/output-eve.h/c` | `SCEveFileType` 后端接口、用户回调 |
| `src/output-json-alert.c` | 告警 JSON 输出实例 |
| `src/util-logopenfile.h` | `LogFileCtx` 文件上下文 |

---

## 2. 输出模块注册机制

### 2.1 OutputModule 结构体

所有输出模块共用 `OutputModule` 结构体进行注册（`src/output.h:57-84`）：

```c
// src/output.h:57-84
typedef struct OutputModule_ {
    LoggerId logger_id;
    const char *name;
    const char *conf_name;
    const char *parent_name;          // 子模块指向父模块名
    OutputInitFunc InitFunc;
    OutputInitSubFunc InitSubFunc;    // 子模块初始化

    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;

    PacketLogger PacketLogFunc;       // 7 种日志函数指针
    PacketLogger PacketFlushFunc;
    PacketLogCondition PacketConditionFunc;
    TxLogger TxLogFunc;
    TxLoggerCondition TxLogCondition;
    SCFileLogger FileLogFunc;
    SCFiledataLogger FiledataLogFunc;
    FlowLogger FlowLogFunc;
    SCStreamingLogger StreamingLogFunc;
    StatsLogger StatsLogFunc;

    AppProto alproto;                 // 事务日志器绑定的协议
    int tc_log_progress;              // toclient 方向日志进度
    int ts_log_progress;              // toserver 方向日志进度

    TAILQ_ENTRY(OutputModule_) entries;
} OutputModule;
```

每个模块只需填充与自身类型匹配的函数指针。例如包日志器填 `PacketLogFunc` + `PacketConditionFunc`，事务日志器填 `TxLogFunc` + `alproto`。

### 2.2 全局注册链表与注册函数族

所有已注册模块保存在全局链表中（`src/output.c:119`）：

```c
// src/output.c:119
OutputModuleList output_modules = TAILQ_HEAD_INITIALIZER(output_modules);
```

输出框架提供了一组注册函数，覆盖所有日志器类型：

| 注册函数 | 类型 | 额外参数 |
|----------|------|----------|
| `OutputRegisterModule` | 通用模块 | — |
| `OutputRegisterPacketModule/SubModule` | 包日志器 | `LogFunc`, `ConditionFunc` |
| `OutputRegisterTxModule/SubModule` | 事务日志器 | `alproto`, `TxLogFunc` |
| `OutputRegisterTxModuleWithProgress` | 事务+进度 | `tc_log_progress`, `ts_log_progress` |
| `OutputRegisterTxModuleWithCondition` | 事务+条件 | `TxLogCondition` |
| `OutputRegisterFileSubModule` | 文件日志器 | `FileLogFunc` |
| `OutputRegisterFlowSubModule` | 流日志器 | `FlowLogFunc` |
| `OutputRegisterStatsModule/SubModule` | 统计日志器 | `StatsLogFunc` |

### 2.3 Module vs SubModule：父子关系

EVE JSON 的模块架构体现了典型的父子关系：`eve-log` 作为父模块，各 JSON 子模块挂载其下。父模块通过 `OutputRegisterModule()` 注册，负责创建共享的文件上下文；子模块通过 `OutputRegister*SubModule()` 注册，`parent_name` 指向 `"eve-log"`，初始化时接收父模块的 `OutputCtx`。

以告警日志为例（`src/output-json-alert.c:1108-1121`）：

```c
// src/output-json-alert.c:1108-1121
void JsonAlertLogRegister(void)
{
    OutputPacketLoggerFunctions output_logger_functions = {
        .LogFunc = JsonAlertLogger,
        .FlushFunc = JsonAlertFlush,
        .ConditionFunc = JsonAlertLogCondition,
        .ThreadInitFunc = JsonAlertLogThreadInit,
        .ThreadDeinitFunc = JsonAlertLogThreadDeinit,
    };
    OutputRegisterPacketSubModule(LOGGER_JSON_ALERT, "eve-log",
            MODULE_NAME, "eve-log.alert",
            JsonAlertLogInitCtxSub, &output_logger_functions);
}
```

`parent_name = "eve-log"` 表示这是 `eve-log` 的子模块，`conf_name = "eve-log.alert"` 对应 YAML 配置路径。

---

## 3. RootLogger：根日志分发器

### 3.1 RootLogger 结构体

根日志器是类型调度器（Packet、Tx、File 等）向输出框架注册自身的入口（`src/output.c:88-96`）：

```c
// src/output.c:88-96
typedef struct RootLogger_ {
    OutputLogFunc LogFunc;
    OutputFlushFunc FlushFunc;
    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;
    OutputGetActiveCountFunc ActiveCntFunc;

    TAILQ_ENTRY(RootLogger_) entries;
} RootLogger;
```

`ActiveCntFunc` 返回该类型下已注册的具体日志模块数量，用于判断是否需要激活。

### 3.2 两个列表：registered vs active

输出框架维护两个 RootLogger 列表（`src/output.c:101-107`）：

```c
// src/output.c:101-107
static TAILQ_HEAD(, RootLogger_) registered_loggers =
    TAILQ_HEAD_INITIALIZER(registered_loggers);

static TAILQ_HEAD(, RootLogger_) active_loggers =
    TAILQ_HEAD_INITIALIZER(active_loggers);
```

- **`registered_loggers`**：启动时注册的所有类型调度器，与配置无关。
- **`active_loggers`**：根据配置激活的子集。只有配置了至少一个具体日志模块的类型调度器才会被激活。

### 3.3 注册与激活流程

`OutputRegisterRootLogger()` 将类型调度器加入 `registered_loggers`（`src/output.c:874-888`）：

```c
// src/output.c:874-888
void OutputRegisterRootLogger(ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit,
        OutputLogFunc LogFunc,
        OutputGetActiveCountFunc ActiveCntFunc)
{
    RootLogger *logger = SCCalloc(1, sizeof(*logger));
    logger->ThreadInit = ThreadInit;
    logger->ThreadDeinit = ThreadDeinit;
    logger->LogFunc = LogFunc;
    logger->ActiveCntFunc = ActiveCntFunc;
    TAILQ_INSERT_TAIL(&registered_loggers, logger, entries);
}
```

配置解析完成后，`OutputSetupActiveLoggers()` 遍历 `registered_loggers`，调用每个的 `ActiveCntFunc()`，仅将有活跃子日志器的根日志器复制到 `active_loggers`（`src/output.c:903-914`）：

```c
// src/output.c:903-914
void OutputSetupActiveLoggers(void)
{
    RootLogger *logger = TAILQ_FIRST(&registered_loggers);
    while (logger) {
        uint32_t cnt = logger->ActiveCntFunc();
        if (cnt) {
            OutputRegisterActiveLogger(logger);
        }
        logger = TAILQ_NEXT(logger, entries);
    }
}
```

### 3.4 初始化入口

`TmModuleLoggerRegister()` 是整个输出系统的初始化入口（`src/output.c:925-929`）：

```c
// src/output.c:925-929
void TmModuleLoggerRegister(void)
{
    OutputRegisterRootLoggers();  // 注册根日志器 + simple_json_applayer_loggers
    OutputRegisterLoggers();      // 注册所有具体日志模块（40+）
}
```

`OutputRegisterRootLoggers()` 首先分配 `simple_json_applayer_loggers` 数组并注册 20+ 协议的泛型日志函数，然后注册五种根日志器（Packet、Filedata、File、Tx、Streaming）。`OutputRegisterLoggers()` 注册所有具体日志模块（`json-alert`、`json-http`、`pcap-log` 等 40 多个）。

---

## 4. 日志调度运行时

### 4.1 OutputLoggerLog：包处理出口

数据包处理完毕后，线程调用 `OutputLoggerLog()` 将包分发到所有活跃的根日志器（`src/output.c:803-815`）：

```c
// src/output.c:803-815
TmEcode OutputLoggerLog(ThreadVars *tv, Packet *p, void *thread_data)
{
    LoggerThreadStore *thread_store = (LoggerThreadStore *)thread_data;
    RootLogger *logger = TAILQ_FIRST(&active_loggers);
    LoggerThreadStoreNode *thread_store_node = TAILQ_FIRST(thread_store);
    while (logger && thread_store_node) {
        logger->LogFunc(tv, p, thread_store_node->thread_data);
        logger = TAILQ_NEXT(logger, entries);
        thread_store_node = TAILQ_NEXT(thread_store_node, entries);
    }
    return TM_ECODE_OK;
}
```

该函数同步遍历两个列表——`active_loggers` 和线程本地的 `LoggerThreadStore`。每个根日志器的 `LogFunc` 与其配对的线程数据一一对应。

### 4.2 线程本地存储

`LoggerThreadStore` 是一个 TAILQ 链表，每个节点持有一个根日志器的线程私有数据（`src/output.c:109-114`）：

```c
// src/output.c:109-114
typedef struct LoggerThreadStoreNode_ {
    void *thread_data;
    TAILQ_ENTRY(LoggerThreadStoreNode_) entries;
} LoggerThreadStoreNode;

typedef TAILQ_HEAD(LoggerThreadStore_, LoggerThreadStoreNode_) LoggerThreadStore;
```

`OutputLoggerThreadInit()` 在线程启动时遍历 `active_loggers`，依次调用每个根日志器的 `ThreadInit` 回调，将返回的线程数据保存到链表节点中（`src/output.c:817-846`）。线程退出时 `OutputLoggerThreadDeinit()` 执行反向清理（`src/output.c:848-872`）。

---

## 5. 包日志器（PacketLogger）

### 5.1 OutputPacketLogger 链表

包日志器维护一个单链表存储所有已注册的包级别日志模块（`src/output-packet.c:41-51`）：

```c
// src/output-packet.c:41-51
typedef struct OutputPacketLogger_ {
    PacketLogger LogFunc;
    PacketLogCondition ConditionFunc;
    void *initdata;
    struct OutputPacketLogger_ *next;
    const char *name;
    LoggerId logger_id;
    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;
} OutputPacketLogger;

static OutputPacketLogger *list = NULL;
```

每个节点必须同时提供 `LogFunc`（日志函数）和 `ConditionFunc`（条件函数），这是包日志器的设计特色——先问"该不该记"，再问"怎么记"。

### 5.2 OutputPacketLog：条件分发

`OutputPacketLog()` 是包日志器的核心调度函数（`src/output-packet.c:84-118`）：

```c
// src/output-packet.c:84-118（关键路径简化）
static TmEcode OutputPacketLog(ThreadVars *tv, Packet *p, void *thread_data)
{
    OutputPacketLoggerThreadData *op_thread_data = thread_data;
    OutputPacketLogger *logger = list;
    OutputLoggerThreadStore *store = op_thread_data->store;

    while (logger && store) {
        if (logger->ConditionFunc(tv, store->thread_data, p)) {
            PACKET_PROFILING_LOGGER_START(p, logger->logger_id);
            logger->LogFunc(tv, store->thread_data, p);
            PACKET_PROFILING_LOGGER_END(p, logger->logger_id);
        }
        logger = logger->next;
        store = store->next;
    }
    return TM_ECODE_OK;
}
```

对每个包日志模块，先调用 `ConditionFunc` 判断此包是否需要记录。例如告警日志的条件是 `p->alerts.cnt || (p->flags & PKT_HAS_TAG)`。只有条件满足才调用 `LogFunc`。`PACKET_PROFILING_LOGGER_START/END` 宏用于性能分析统计。

### 5.3 注册为 RootLogger

`OutputPacketLoggerRegister()` 将包日志调度器注册为根日志器（`src/output-packet.c:194-198`）：

```c
// src/output-packet.c:194-198
void OutputPacketLoggerRegister(void)
{
    OutputRegisterRootLogger(OutputPacketLogThreadInit,
            OutputPacketLogThreadDeinit,
            OutputPacketLog,
            OutputPacketLoggerGetActiveCount);
}
```

典型的包日志模块实例包括：`json-alert`（告警）、`pcap-log`（PCAP 落盘）、`fast-log`（快速文本告警）、`json-drop`（丢弃包记录）。

---

## 6. 事务日志器（TxLogger）

### 6.1 按协议索引的链表数组

事务日志器的存储结构更复杂——使用按 `alproto` 索引的指针数组，每个协议维护一个独立的日志模块链表（`src/output-tx.c:49-64`）：

```c
// src/output-tx.c:49-62
typedef struct OutputTxLogger_ {
    AppProto alproto;
    TxLogger LogFunc;
    TxLoggerCondition LogCondition;
    void *initdata;
    struct OutputTxLogger_ *next;
    const char *name;
    LoggerId logger_id;
    uint32_t id;              // 位掩码标识（1, 2, 4, 8, ...）
    int tc_log_progress;
    int ts_log_progress;
    TmEcode (*ThreadInit)(ThreadVars *, const void *, void **);
    TmEcode (*ThreadDeinit)(ThreadVars *, void *);
} OutputTxLogger;

static OutputTxLogger **list = NULL;  // list[alproto] -> 链表头
```

`id` 字段用作位掩码标识符（1, 2, 4, 8...），通过 `BIT_U32(logger_id)` 追踪每个事务的日志完成状态。

### 6.2 OutputTxLog：核心调度逻辑

`OutputTxLog()` 是整个输出框架中最复杂的函数（`src/output-tx.c:336-537`），处理事务级别日志的核心逻辑。其工作流程如下：

```
OutputTxLog(tv, p, thread_data)
    │
    ├─ 检查：p->flow 存在？app_update？TCP established？
    │
    ├─ 获取 logger_expectation = 该协议所有已注册日志器的 OR 位掩码
    │
    ├─ 使用 TX 迭代器遍历所有待日志事务：
    │   for each tx (from log_id to total_txs):
    │       │
    │       ├─ 获取 tx 的 ts/tc 进度和完成状态
    │       │
    │       ├─ 文件日志处理：OutputTxLogFiles()
    │       │
    │       ├─ 跳过已完全日志的 tx (txd->logged.flags == logger_expectation)
    │       │
    │       ├─ 调用 OutputTxLogCallLoggers() 逐日志器处理：
    │       │   for each logger at list[alproto]:
    │       │       if (已记录) skip
    │       │       if (EOF) 立即记录
    │       │       elif (有 LogCondition) 检查条件
    │       │       elif (进度不够) skip
    │       │       else 调用 LogFunc
    │       │       设置 tx_logged 位
    │       │
    │       └─ 更新 txd->logged.flags
    │
    └─ 推进日志水位：AppLayerParserSetTransactionLogId(max_id + 1)
```

日志进度追踪是事务日志器的核心设计。每个事务的 `AppLayerTxData` 中有 `logged.flags` 位掩码字段，记录哪些日志器已经处理过该事务。只有当所有预期的日志器都完成（`logged.flags == logger_expectation`）时，事务才被标记为"已完全日志"。

### 6.3 泛型 JSON 日志器

许多协议的日志逻辑相似——构建 EVE 头部、调用协议特定的序列化函数、输出到缓冲区。`JsonGenericLogger()` 封装了这个通用流程（`src/output.c:1012-1038`）：

```c
// src/output.c:1012-1038
static int JsonGenericLogger(ThreadVars *tv, void *thread_data,
        const Packet *p, Flow *f, void *state, void *tx,
        uint64_t tx_id, int dir)
{
    OutputJsonThreadCtx *thread = thread_data;
    EveJsonSimpleAppLayerLogger *al = SCEveJsonSimpleGetLogger(f->alproto);

    SCJsonBuilder *js = CreateEveHeader(p, dir, al->name, NULL, thread->ctx);
    if (!al->LogTx(tx, js))
        goto error;

    OutputJsonBuilderBuffer(tv, p, p->flow, js, thread);
    SCJbFree(js);
    return TM_ECODE_OK;
    // ...
}
```

`simple_json_applayer_loggers[]` 数组（按 `alproto` 索引）存储每个协议的简单序列化函数。在 `OutputRegisterRootLoggers()` 中注册了 20+ 协议的泛型日志器，包括 DNS、TLS、SSH、QUIC、MQTT 等。

---

## 7. 流日志器与统计日志器

### 7.1 流日志器

流日志器在**流回收时**触发，而非包处理路径。接口定义在 `src/output-flow.h:36`：

```c
// src/output-flow.h:36
typedef int (*FlowLogger)(ThreadVars *, void *thread_data, Flow *f);
```

在 FlowWorker 释放流时调用 `OutputFlowLog()`（`src/output-flow.h:57`），遍历注册的流日志模块。典型实例包括 `json-flow`（流记录）和 `json-netflow`（NetFlow 风格聚合）。

流日志器通过 `OutputRegisterFlowSubModule()` 注册为 `eve-log` 的子模块。与包日志器不同，流日志器没有条件函数——当流被回收时总是触发。

### 7.2 统计日志器

统计日志器定期触发，与包处理流水线完全解耦（`src/output-stats.h:50`）：

```c
// src/output-stats.h:50
typedef int (*StatsLogger)(ThreadVars *, void *thread_data, const StatsTable *);
```

`StatsTable` 结构包含全局统计数组和每线程统计数组（`src/output-stats.h:39-46`）：

```c
// src/output-stats.h:39-46
typedef struct StatsTable_ {
    StatsRecord *stats;     // 全局统计记录数组
    StatsRecord *tstats;    // 每线程统计数组
    uint32_t nstats;        // stats 数组大小
    uint32_t ntstats;       // 线程数
    time_t start_time;
    struct timeval ts;
} StatsTable;
```

统计日志器注册为独立的线程模块 `TMM_STATSLOGGER`（通过 `TmModuleStatsLoggerRegister()`），而不是 RootLogger。典型实例为 `json-stats`（EVE stats 事件类型）。

---

## 8. EVE JSON 核心：OutputJsonCtx 与 CreateEveHeader

### 8.1 全局与线程上下文

EVE JSON 系统有两层上下文——全局配置上下文和每线程工作上下文。

**全局上下文**（`src/output-json.h:75-81`）：

```c
// src/output-json.h:75-81
typedef struct OutputJsonCtx_ {
    LogFileCtx *file_ctx;           // 文件/输出句柄
    enum LogFileType json_out;      // 输出类型
    OutputJsonCommonSettings cfg;   // 公共选项（community_id 等）
    HttpXFFCfg *xff_cfg;            // XFF 配置
    SCEveFileType *filetype;        // 插件后端指针
} OutputJsonCtx;
```

**线程上下文**（`src/output-json.h:83-88`）：

```c
// src/output-json.h:83-88
typedef struct OutputJsonThreadCtx_ {
    OutputJsonCtx *ctx;             // 指向全局上下文
    LogFileCtx *file_ctx;           // 线程化时可能指向不同的文件
    MemBuffer *buffer;              // JSON 渲染缓冲区
    bool too_large_warning;         // 大记录警告标志（仅触发一次）
} OutputJsonThreadCtx;
```

### 8.2 OutputJsonRegister 与初始化

`OutputJsonRegister()` 将 EVE JSON 注册为名为 `"eve-log"` 的输出模块（`src/output-json.c:83-94`）：

```c
// src/output-json.c:83-94
void OutputJsonRegister(void)
{
    OutputRegisterModule(MODULE_NAME, "eve-log", OutputJsonInitCtx);
    // 注册 syslog 和 nullsink 后端
    SyslogInitialize();
    NullLogInitialize();
}
```

`OutputJsonInitCtx()` 是初始化的核心（`src/output-json.c:1123-1299`），执行以下步骤：

1. **读取 filetype/type 配置**：支持 `file`/`regular`、`unix_dgram`、`unix_stream`、`redis`，或自定义 `SCEveFileType` 插件
2. **解析 common options**：`community-id`、`metadata`、`ethernet`、`suricata-version`
3. **创建 LogFileCtx**：打开输出文件/连接
4. **配置线程化输出**：`threaded: true` 时为每个线程创建独立文件

### 8.3 CreateEveHeader：构建 JSON 头部

`CreateEveHeader()` 为每条 EVE 记录构建标准头部字段（`src/output-json.c:832-933`）：

```c
// src/output-json.c:832-933（关键路径简化）
SCJsonBuilder *CreateEveHeader(const Packet *p,
        enum SCOutputJsonLogDirection dir,
        const char *event_type, JsonAddrInfo *addr,
        OutputJsonCtx *eve_ctx)
{
    SCJsonBuilder *js = SCJbNewObject();

    // 1. 时间戳（ISO 8601 格式）
    CreateIsoTimeString(p->ts, timebuf, sizeof(timebuf));
    SCJbSetString(js, "timestamp", timebuf);

    // 2. flow_id（流标识）
    CreateEveFlowId(js, f);

    // 3. sensor_id（可选）
    if (sensor_id >= 0)
        SCJbSetUint(js, "sensor_id", sensor_id);

    // 4. 输入接口
    if (p->livedev)
        SCJbSetString(js, "in_iface", p->livedev->dev);

    // 5. pcap_cnt（包计数器）
    if (p->pcap_cnt != 0)
        SCJbSetUint(js, "pcap_cnt", p->pcap_cnt);

    // 6. event_type（事件类型：alert/http/dns/flow/...）
    if (event_type)
        SCJbSetString(js, "event_type", event_type);

    // 7. VLAN 标签
    if (p->vlan_idx > 0) { /* 写入 vlan 数组 */ }

    // 8. 五元组（src_ip, src_port, dest_ip, dest_port, proto）
    JsonAddrInfoInit(p, dir, &addr_info);
    /* 写入地址字段 */

    // 9. IP 版本
    // 10. ICMP 类型/代码
    // 11. 公共选项（metadata, community_id, ethernet）
    if (eve_ctx != NULL)
        EveAddCommonOptions(&eve_ctx->cfg, p, f, js, dir);

    return js;
}
```

生成的 JSON 头部形如：

```json
{
  "timestamp": "2024-01-15T10:30:00.123456+0800",
  "flow_id": 1234567890123456,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dest_ip": "10.0.0.1",
  "dest_port": 80,
  "proto": "TCP",
  "community_id": "1:XYZ..."
}
```

### 8.4 EveAddCommonOptions

`EveAddCommonOptions()` 追加用户通过配置启用的公共字段（`src/output-json.c:396-414`）：

```c
// src/output-json.c:396-414
void EveAddCommonOptions(const OutputJsonCommonSettings *cfg,
        const Packet *p, const Flow *f,
        SCJsonBuilder *js, enum SCOutputJsonLogDirection dir)
{
    if (cfg->include_suricata_version)
        SCJbSetString(js, "suricata_version", PROG_VER);
    if (cfg->include_metadata)
        EveAddMetadata(p, f, js);
    if (cfg->include_ethernet)
        CreateJSONEther(js, p, f, dir);
    if (cfg->include_community_id && f != NULL)
        CreateEveCommunityFlowId(js, f, cfg->community_id_seed);
    if (f != NULL && f->tenant_id > 0)
        SCJbSetUint(js, "tenant_id", f->tenant_id);
}
```

---

## 9. JSON 输出管线：从 JsonBuilder 到磁盘

### 9.1 SCJsonBuilder

`SCJsonBuilder` 是 Rust 实现的 JSON 构建器（通过 C 绑定暴露为 `SCJb*` 系列 API），是 Suricata 输出系统的核心数据结构。相比传统 jansson 库（`json_t`），`SCJsonBuilder` 采用追加式写入（不构建 DOM 树），效率更高。

### 9.2 OutputJsonBuilderBuffer：完整输出流程

每个日志模块完成 JSON 字段填充后，调用 `OutputJsonBuilderBuffer()` 将记录写入后端（`src/output-json.c:997-1042`）：

```c
// src/output-json.c:997-1042
void OutputJsonBuilderBuffer(ThreadVars *tv, const Packet *p,
        Flow *f, SCJsonBuilder *js, OutputJsonThreadCtx *ctx)
{
    LogFileCtx *file_ctx = ctx->file_ctx;
    MemBuffer **buffer = &ctx->buffer;

    // 1. 添加 host 字段（sensor_name）
    if (file_ctx->sensor_name)
        SCJbSetString(js, "host", file_ctx->sensor_name);

    // 2. 添加 pcap_filename（离线分析模式）
    if (file_ctx->is_pcap_offline)
        SCJbSetString(js, "pcap_filename", PcapFileGetFilename());

    // 3. 运行用户注册的回调
    SCEveRunCallbacks(tv, p, f, js);

    // 4. 关闭根 JSON 对象
    SCJbClose(js);

    // 5. 渲染到 MemBuffer
    MemBufferReset(*buffer);
    if (file_ctx->prefix)
        MemBufferWriteRaw(*buffer, file_ctx->prefix, file_ctx->prefix_len);

    size_t jslen = SCJbLen(js);
    // 大记录保护：超过 MemBuffer 容量时尝试扩展
    if (jslen >= remaining) {
        if (MemBufferExpand(buffer, expand_by) < 0) {
            if (!ctx->too_large_warning) {
                SCLogWarning("Formatted JSON EVE record too large, "
                             "will be dropped: %s", partial);
                ctx->too_large_warning = true;
            }
            return;
        }
    }

    // 6. 写入后端
    MemBufferWriteRaw(*buffer, SCJbPtr(js), jslen);
    LogFileWrite(file_ctx, *buffer);
}
```

完整管线：**日志模块 → CreateEveHeader → 填充字段 → OutputJsonBuilderBuffer → SCEveRunCallbacks → SCJbClose → MemBuffer → LogFileWrite → 磁盘/Socket/Redis**。

`too_large_warning` 标志确保超大记录的警告日志只打印一次，避免日志风暴。

---

## 10. EVE FileType 后端系统

### 10.1 SCEveFileType 接口

EVE 后端系统通过 `SCEveFileType` 接口实现可插拔的输出目的地（`src/output-eve.h:73-170`）：

```c
// src/output-eve.h:73-170（简化）
typedef struct SCEveFileType_ {
    const char *name;

    // 生命周期函数
    int (*Init)(const SCConfNode *conf, const bool threaded, void **init_data);
    int (*ThreadInit)(const void *init_data, const ThreadId thread_id,
                      void **thread_data);
    int (*Write)(const char *buffer, const int buffer_len,
                 const void *init_data, void *thread_data);
    void (*ThreadDeinit)(const void *init_data, void *thread_data);
    void (*Deinit)(void *init_data);

    TAILQ_ENTRY(SCEveFileType_) entries;
} SCEveFileType;
```

生命周期：**Init → ThreadInit → Write（每条记录） → ThreadDeinit → Deinit**。在多线程模式下，`ThreadInit` 会被调用多次。

### 10.2 内建后端

| 后端 | filetype 值 | 实现 |
|------|------------|------|
| 普通文件 | `regular` / `file` | 通过 `LogFileCtx` 直接写文件 |
| Unix 数据报 | `unix_dgram` | Unix 域套接字（DGRAM） |
| Unix 流 | `unix_stream` | Unix 域套接字（STREAM） |
| Redis | `redis` | 通过 libhiredis 库 |
| Syslog | `syslog` | `src/output-eve-syslog.c` |
| 空输出 | `nullsink` | `src/output-eve-null.c`（丢弃所有输出） |

前四种是"内建类型"，直接由 `LogFileCtx` 处理。Syslog 和 Nullsink 是通过 `SCEveFileType` 接口注册的"现代后端"。

### 10.3 注册与查找

`SCRegisterEveFileType()` 注册新的后端类型（`src/output-eve.c:100-121`）：

```c
// src/output-eve.c:100-121
bool SCRegisterEveFileType(SCEveFileType *plugin)
{
    // 检查不与内建名称冲突
    if (IsBuiltinTypeName(plugin->name)) {
        SCLogError("Eve file type name conflicts with built-in type: %s",
                plugin->name);
        return false;
    }
    // 检查不与已注册名称冲突
    // ...
    TAILQ_INSERT_TAIL(&output_types, plugin, entries);
    return true;
}
```

`SCEveFindFileType()` 通过名称查找已注册的后端（`src/output-eve.c:82-91`）——简单线性搜索。

### 10.4 LogFileCtx 结构体

`LogFileCtx` 是所有文件输出的底层抽象（`src/util-logopenfile.h:72-166`），关键字段包括：

```c
// src/util-logopenfile.h:72-166（关键字段）
typedef struct LogFileCtx_ {
    FILE *fp;                        // 文件指针

    int (*Write)(...);               // 写函数指针
    void (*Close)(...);              // 关闭函数指针
    void (*Flush)(...);              // 刷新函数指针

    LogFileTypeCtx filetype;         // EVE FileType 后端上下文
    LogThreadedFileCtx *threads;     // 线程化支持

    bool threaded;                   // 是否多线程输出
    enum LogFileType type;           // 文件类型

    char *filename;
    char *sensor_name;
    time_t rotate_time;              // 下次轮转时间
    uint64_t rotate_interval;        // 轮转间隔
    int rotation_flag;               // 轮转通知标志
    bool is_pcap_offline;            // 离线模式标志
    uint64_t dropped;                // 丢弃计数
} LogFileCtx;
```

`Write`/`Close`/`Flush` 函数指针是后端无关的虚函数表。`LogThreadedFileCtx` 通过哈希表管理每线程的 `LogFileCtx` 实例，实现无锁线程化输出。

---

## 11. 告警 JSON 输出实例剖析

以告警日志为完整实例，串联整个输出管线。

### 11.1 AlertJsonOutputCtx 配置

```c
// src/output-json-alert.c:99-106
typedef struct AlertJsonOutputCtx_ {
    LogFileCtx* file_ctx;
    uint16_t flags;                  // LOG_JSON_PAYLOAD, LOG_JSON_PACKET 等
    uint32_t payload_buffer_size;
    HttpXFFCfg *xff_cfg;
    HttpXFFCfg *parent_xff_cfg;
    OutputJsonCtx *eve_ctx;
} AlertJsonOutputCtx;
```

`flags` 位字段控制告警记录包含哪些可选内容（payload、packet、app-layer、flow、rule、verdict 等）。

### 11.2 AlertJsonHeader：构建 alert 对象

`AlertJsonHeader()` 在 EVE 头部之上构建 `alert` 子对象（`src/output-json-alert.c:202-276`）：

```c
// src/output-json-alert.c:202-276（关键路径简化）
void AlertJsonHeader(const Packet *p, const PacketAlert *pa,
        SCJsonBuilder *js, uint16_t flags,
        JsonAddrInfo *addr, char *xff_buffer)
{
    // 判断 action：allowed / blocked
    const char *action = "allowed";
    if (pa->action & ACTION_DROP && EngineModeIsIPS())
        action = "blocked";

    SCJbOpenObject(js, "alert");
    SCJbSetString(js, "action", action);
    SCJbSetUint(js, "gid", pa->s->gid);
    SCJbSetUint(js, "signature_id", pa->s->id);
    SCJbSetUint(js, "rev", pa->s->rev);
    SCJbSetString(js, "signature", pa->s->msg);
    SCJbSetString(js, "category", pa->s->class_msg);
    SCJbSetUint(js, "severity", pa->s->prio);

    if (pa->s->flags & SIG_FLAG_HAS_TARGET)
        AlertJsonSourceTarget(p, pa, js, addr);
    if (flags & LOG_JSON_RULE_METADATA)
        AlertJsonMetadata(pa, js);
    if (flags & LOG_JSON_RULE)
        SCJbSetString(js, "rule", pa->s->sig_str);

    SCJbClose(js);
}
```

### 11.3 AlertAddAppLayer：追加应用层上下文

`AlertAddAppLayer()` 根据协议类型追加应用层详情（`src/output-json-alert.c:321-462`）。对于支持 `simple_json_applayer_loggers` 的协议（DNS、TLS 等），直接调用泛型 `LogTx` 函数；对于 HTTP、SMTP、NFS、SMB 等需要特殊处理的协议，使用独立的逻辑分支。

### 11.4 完整调用链

```
包处理线程
  → OutputLoggerLog()
    → OutputPacketLog()                        [包日志器调度]
      → JsonAlertLogCondition(p)               [检查 p->alerts.cnt]
      → JsonAlertLogger(tv, thread_data, p)    [主函数]
        → AlertJson(tv, aft, p)
          for each alert in p->alerts:
            → CreateEveHeader(p, "alert", ...)    [构建 EVE 头部]
            → AlertJsonHeader(p, pa, js, ...)     [构建 alert 对象]
            → AlertAddAppLayer(p, js, tx_id, ...) [追加应用层]
            → AlertAddPayload(js, p)              [追加载荷]
            → EvePacket(p, js)                    [追加原始包]
            → OutputJsonBuilderBuffer(...)        [渲染并写入]
```

---

## 12. 文件轮转与用户回调

### 12.1 文件轮转机制

输出框架通过标志位实现文件轮转通知（`src/output.c:692-743`）。

注册轮转标志：

```c
// src/output.c:692-703
void OutputRegisterFileRotationFlag(int *flag)
{
    OutputFileRolloverFlag *flag_entry = SCCalloc(1, sizeof(*flag_entry));
    flag_entry->flag = flag;
    SCMutexLock(&output_file_rotation_mutex);
    TAILQ_INSERT_TAIL(&output_file_rotation_flags, flag_entry, entries);
    SCMutexUnlock(&output_file_rotation_mutex);
}
```

当收到 SIGHUP 信号时，调用 `OutputNotifyFileRotation()` 设置所有已注册的标志位（`src/output.c:735-743`）：

```c
// src/output.c:735-743
void OutputNotifyFileRotation(void)
{
    OutputFileRolloverFlag *flag = NULL;
    OutputFileRolloverFlag *tflag;
    SCMutexLock(&output_file_rotation_mutex);
    TAILQ_FOREACH_SAFE(flag, &output_file_rotation_flags, entries, tflag) {
        *(flag->flag) = 1;
    }
    SCMutexUnlock(&output_file_rotation_mutex);
}
```

各日志模块在下次写入时检测到标志位为 1，执行文件关闭-重命名-重新打开序列。`LogFileCtx` 的 `rotation_flag` 字段和 `rotate_time`/`rotate_interval` 字段分别支持信号触发和定时轮转两种模式。

### 12.2 用户回调系统

EVE 输出支持用户（插件或库调用者）注册回调，在每条 JSON 记录关闭前注入自定义字段（`src/output-eve.h:189-210`）：

```c
// src/output-eve.h:189-210
typedef void (*SCEveUserCallbackFn)(ThreadVars *tv, const Packet *p,
        Flow *f, SCJsonBuilder *jb, void *user);

bool SCEveRegisterCallback(SCEveUserCallbackFn fn, void *user);
```

注册实现维护一个单链表（`src/output-eve.c:33-51`）：

```c
// src/output-eve.c:23-27
typedef struct EveUserCallback_ {
    SCEveUserCallbackFn Callback;
    void *user;
    struct EveUserCallback_ *next;
} EveUserCallback;
```

`SCEveRunCallbacks()` 在 `OutputJsonBuilderBuffer()` 中、`SCJbClose()` 之前调用（`src/output-eve.c:53-60`）：

```c
// src/output-eve.c:53-60
void SCEveRunCallbacks(ThreadVars *tv, const Packet *p, Flow *f,
        SCJsonBuilder *jb)
{
    EveUserCallback *cb = eve_user_callbacks;
    while (cb != NULL) {
        cb->Callback(tv, p, f, jb, cb->user);
        cb = cb->next;
    }
}
```

这使得插件可以在不修改核心代码的情况下，向 EVE JSON 添加自定义字段（如威胁情报标签、GeoIP 信息等）。

---

## 13. 小结与源码索引表

本篇剖析了 Suricata 输出框架的完整架构。核心要点回顾：

1. **三层分发**：RootLogger → 类型调度器（Packet/Tx/Flow/Stats）→ 具体日志模块
2. **模块化注册**：通过 `OutputModule` 结构体和 `OutputRegister*` 系列函数，支持 Module/SubModule 父子关系
3. **条件与进度追踪**：包日志器通过 `ConditionFunc` 过滤，事务日志器通过 `logged.flags` 位掩码和进度阈值控制
4. **EVE JSON 管线**：`CreateEveHeader()` → 模块填充字段 → `OutputJsonBuilderBuffer()` → `LogFileWrite()`
5. **可插拔后端**：`SCEveFileType` 接口支持文件、Unix Socket、Redis、Syslog 和自定义插件
6. **扩展点**：`SCEveRegisterCallback()` 允许插件注入自定义 JSON 字段

### 源码索引表

| 文件 | 关键结构/函数 | 行号 |
|------|-------------|------|
| `src/output.h` | `OutputModule` 结构体 | 57-84 |
| `src/output.h` | `OutputRegisterRootLogger()` 声明 | 166-167 |
| `src/output.h` | `OutputLoggerLog()` 声明 | 170 |
| `src/output.c` | `RootLogger` 结构体 | 88-96 |
| `src/output.c` | `registered_loggers` / `active_loggers` | 101-107 |
| `src/output.c` | `OutputLoggerLog()` | 803-815 |
| `src/output.c` | `OutputLoggerThreadInit()` | 817-846 |
| `src/output.c` | `OutputRegisterRootLogger()` | 874-888 |
| `src/output.c` | `OutputSetupActiveLoggers()` | 903-914 |
| `src/output.c` | `TmModuleLoggerRegister()` | 925-929 |
| `src/output.c` | `JsonGenericLogger()` | 1012-1038 |
| `src/output.c` | `OutputRegisterFileRotationFlag()` | 692-703 |
| `src/output.c` | `OutputNotifyFileRotation()` | 735-743 |
| `src/output-packet.c` | `OutputPacketLogger` 结构体 | 41-51 |
| `src/output-packet.c` | `OutputPacketLog()` | 84-118 |
| `src/output-packet.c` | `OutputPacketLoggerRegister()` | 194-198 |
| `src/output-tx.c` | `OutputTxLogger` 结构体 | 49-62 |
| `src/output-tx.c` | `OutputTxLog()` | 336-537 |
| `src/output-tx.c` | `OutputTxLogCallLoggers()` | 275-334 |
| `src/output-tx.c` | `OutputTxLogFiles()` | 140-239 |
| `src/output-flow.h` | `FlowLogger` 类型 | 36 |
| `src/output-stats.h` | `StatsLogger` 类型、`StatsTable` | 39-50 |
| `src/output-json.h` | `OutputJsonCtx` | 75-81 |
| `src/output-json.h` | `OutputJsonThreadCtx` | 83-88 |
| `src/output-json.c` | `OutputJsonRegister()` | 83-94 |
| `src/output-json.c` | `CreateEveHeader()` | 832-933 |
| `src/output-json.c` | `EveAddCommonOptions()` | 396-414 |
| `src/output-json.c` | `OutputJsonBuilderBuffer()` | 997-1042 |
| `src/output-json.c` | `OutputJsonInitCtx()` | 1123-1299 |
| `src/output-eve.h` | `SCEveFileType` 接口 | 73-170 |
| `src/output-eve.h` | `SCEveUserCallbackFn` | 189-190 |
| `src/output-eve.c` | `SCEveRegisterCallback()` | 33-51 |
| `src/output-eve.c` | `SCEveRunCallbacks()` | 53-60 |
| `src/output-eve.c` | `SCRegisterEveFileType()` | 100-121 |
| `src/output-eve.c` | `SCEveFindFileType()` | 82-91 |
| `src/output-json-alert.c` | `AlertJsonOutputCtx` | 99-106 |
| `src/output-json-alert.c` | `AlertJsonHeader()` | 202-276 |
| `src/output-json-alert.c` | `AlertAddAppLayer()` | 321-462 |
| `src/output-json-alert.c` | `JsonAlertLogRegister()` | 1108-1121 |
| `src/util-logopenfile.h` | `LogFileCtx` 结构体 | 72-166 |

---

> **下一篇预告**：第 16 篇将剖析 Suricata 的线程模型与性能架构——包括线程模块（TmModule）系统、四种运行模式的线程拓扑、FlowWorker 架构，以及多线程环境下的锁策略和无锁设计。
