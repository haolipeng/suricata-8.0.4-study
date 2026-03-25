# 09 - 架构总览：数据包的一生

> **导读**：本篇是"架构与源码分析"板块的开篇，从全局视角梳理 Suricata 的启动流程、核心数据结构、线程模型和处理流水线。读完本篇，你将建立一张完整的架构地图，为后续深入各子系统（解码、流处理、检测引擎、输出框架）打下基础。

---

## 1. 源码目录结构

在深入代码之前，先了解 Suricata 8.0.3 的源码布局：

```
suricata/
├── src/                    # C 核心引擎（约 600+ 源文件）
│   ├── main.c              # 入口，仅 69 行
│   ├── suricata.c/.h       # 引擎生命周期管理
│   ├── decode*.c/.h        # 解码层：Ethernet, IPv4/v6, TCP, UDP, ICMP...
│   ├── flow*.c/.h          # 流管理：哈希表、超时、回收
│   ├── stream-tcp*.c/.h    # TCP 流重组引擎
│   ├── app-layer*.c/.h     # 应用层协议检测与解析框架
│   ├── detect*.c/.h        # 检测引擎：规则加载、多模式匹配、签名执行
│   ├── output*.c/.h        # 输出框架：EVE JSON、日志模块
│   ├── tm-modules*.c/.h    # 线程模块定义
│   ├── tm-threads*.c/.h    # 线程管理与流水线调度
│   ├── runmode*.c/.h       # 运行模式：workers, autofp, single
│   ├── util-*.c/.h         # 工具函数：内存池、哈希、CPU 亲和性...
│   └── flow-worker.c       # 核心处理模块：集成流查找+流重组+检测+输出
├── rust/                   # Rust 模块（协议解析器、工具库）
│   └── src/
│       ├── applayer*.rs    # Rust 协议解析器
│       ├── detect/         # Rust 检测关键字
│       └── ffi.rs          # C-Rust FFI 绑定
├── doc/                    # 官方 Sphinx 文档
├── scripts/                # 构建与工具脚本
├── etc/                    # 默认配置文件
└── rules/                  # 内置规则
```

**核心文件规模**：`src/` 目录下约 600 个 `.c/.h` 文件，其中 `detect-*.c` 占比最大（200+ 文件，每个检测关键字一对文件）。Rust 代码主要在 `rust/src/` 下，负责新协议解析器和部分检测关键字的实现。

---

## 2. main() 函数：引擎的十步启动

Suricata 的入口在 `src/main.c`，整个文件仅 69 行，极度简洁：

```c
// src/main.c:26-67
int main(int argc, char **argv)
{
    SuricataPreInit(argv[0]);        // 步骤 1：全局预初始化
#ifdef OS_WIN32
    /* Windows 服务相关 */
    ...
#endif
    SCParseCommandLine(argc, argv);  // 步骤 2：解析命令行参数
    SCFinalizeRunMode();             // 步骤 3：确定运行模式
    SCStartInternalRunMode(argc, argv); // 步骤 4：处理内部模式（如 --list-keywords）
    SCLoadYamlConfig();              // 步骤 5：加载 YAML 配置
    SCEnableDefaultSignalHandlers(); // 步骤 6：安装信号处理器
    SuricataInit();                  // 步骤 7：核心初始化（最重要！）
    SuricataPostInit();              // 步骤 8：等待线程就绪
    SuricataMainLoop();              // 步骤 9：主事件循环
    SuricataShutdown();              // 步骤 10：优雅关闭
    GlobalsDestroy();
    return EXIT_SUCCESS;
}
```

这 10 步构成了引擎的完整生命周期。下面逐一展开关键步骤。

### 2.1 SuricataPreInit — 全局预初始化

```c
// src/suricata.c:3015
void SuricataPreInit(const char *progname)
{
    SCInstanceInit(&suricata, progname);
    InitGlobal();
}
```

`SCInstanceInit()` 初始化全局单例 `SCInstance suricata`（定义在 `src/suricata.h:105`），这是整个引擎的全局状态容器：

```c
// src/suricata.h:105-165（关键字段）
typedef struct SCInstance_ {
    enum SCRunMode run_mode;      // 运行模式（PCAP_DEV, AFP_DEV 等）
    char *pcap_dev;               // 抓包设备名
    char *sig_file;               // 规则文件路径
    char *pid_filename;           // PID 文件路径
    bool daemon;                  // 是否后台运行
    bool offline;                 // 是否离线模式
    int sig_file_exclusive;       // 是否独占规则文件
    bool set_logdir;              // 是否自定义日志目录
    bool set_datadir;             // 是否自定义数据目录
    uint64_t start_time;          // 启动时间戳
    bool system;                  // 是否以系统模式运行
    bool delayed_detect;          // 是否延迟检测
    const char *log_dir;          // 日志输出目录
    const char *progname;         // 程序名
    const char *conf_filename;    // 配置文件路径
    bool strict_rule_keywords;    // 是否严格解析规则关键字
} SCInstance;
```

`InitGlobal()` 做的事情更多（`src/suricata.c:2977`）：

```c
static void InitGlobal(void)
{
    SCRustInit();                       // 初始化 Rust 运行时
    SCLogInitLogModule(NULL);           // 初始化日志子系统
    RunModeRegisterRunModes();          // 注册所有运行模式
    SCConfInit();                       // 初始化配置树
    memset(tmm_modules, 0, sizeof(tmm_modules)); // 清零模块数组
}
```

注意 `memset(tmm_modules, 0, sizeof(tmm_modules))` 这行——`tmm_modules` 是一个全局数组 `TmModule tmm_modules[TMM_SIZE]`（`src/tm-modules.c:29`），后面各子系统会通过注册函数填充这个数组。

### 2.2 SCParseCommandLine — 命令行解析

解析所有命令行参数（`-i`, `-r`, `-s`, `-c`, `--af-packet` 等），将结果写入 `SCInstance suricata` 的各字段。

### 2.3 SCFinalizeRunMode — 确定运行模式

根据命令行参数确定最终的运行模式，设置 `suricata.run_mode`。Suricata 支持 17 种运行模式（`src/runmodes.h`）：

```c
// src/runmodes.h
enum SCRunMode {
    RUNMODE_UNKNOWN = 0,
    RUNMODE_PCAP_DEV,          // 实时 PCAP 抓包
    RUNMODE_PCAP_FILE,         // 读取 PCAP 文件
    RUNMODE_NFQ,               // Linux Netfilter Queue (IPS)
    RUNMODE_NFLOG,             // NFLOG 模式
    RUNMODE_AFP_DEV,           // AF_PACKET 抓包（Linux 高性能）
    RUNMODE_AFXDP_DEV,         // AF_XDP 抓包（eBPF）
    RUNMODE_NETMAP,            // Netmap 高性能抓包
    RUNMODE_DPDK,              // DPDK 旁路内核抓包
    RUNMODE_UNIX_SOCKET,       // Unix Socket 命令模式
    RUNMODE_WINDIVERT,         // Windows Divert (IPS)
    RUNMODE_PLUGIN,            // 插件抓包模式
    ...
};
```

### 2.4 SuricataInit — 核心初始化（最关键）

这是整个启动过程中最重要的函数（`src/suricata.c:3024`，约 90 行），完成以下工作：

```
SuricataInit()
  ├── GlobalsInitPreConfig()           // 初始化全局配置前的子系统
  ├── SetupUserMode()                  // 设置 IDS/IPS 模式
  ├── SCLogLoadConfig()                // 加载日志配置
  ├── RunModeInitializeThreadSettings()// 初始化线程设置
  ├── ParseInterfacesList()            // 解析网络接口列表
  ├── PostConfLoadedSetup()            // 配置加载后的初始化
  │   ├── PacketPoolInit()             //   初始化数据包内存池
  │   ├── FlowInitConfig()             //   初始化流表
  │   ├── StreamTcpInitConfig()        //   初始化 TCP 流重组
  │   ├── AppLayerSetup()              //   初始化应用层解析框架
  │   ├── OutputSetupActiveLoggers()   //   激活输出模块
  │   └── ...
  ├── PostConfLoadedDetectSetup()      // 加载检测引擎与规则
  │   ├── DetectEngineCtxInit()        //   创建检测引擎上下文
  │   ├── SigLoadSignatures()          //   加载签名规则
  │   └── DetectEngineAddToMaster()    //   添加到主检测引擎
  └── RunModeDispatch()                // 分发线程（最关键！）
      ├── RunModeFunc()                //   根据模式创建所有工作线程
      ├── 创建管理线程                  //   FlowManager, FlowRecycler, Stats...
      └── TmThreadsSealThreads()       //   密封线程列表
```

其中 `RunModeDispatch()`（`src/suricata.c:3103`）是线程创建的核心入口，它根据运行模式调用对应的线程创建函数，并启动所有管理线程。这个函数会在后文线程模型部分详细讲解。

### 2.5 SuricataMainLoop — 主事件循环

```c
// src/suricata.c:2934-2969
void SuricataMainLoop(void)
{
    SCInstance *suri = &suricata;
    while(1) {
        if (sigterm_count || sigint_count) {
            suricata_ctl_flags |= SURICATA_STOP;
        }
        if (suricata_ctl_flags & SURICATA_STOP) {
            break;
        }
        TmThreadCheckThreadState();        // 检查线程状态

        if (sighup_count > 0) {
            OutputNotifyFileRotation();    // SIGHUP → 日志轮转
            sighup_count--;
        }
        if (sigusr2_count > 0) {
            DetectEngineReloadStart();     // SIGUSR2 → 规则热重载
            DetectEngineReload(suri);
            DetectEngineReloadSetIdle();
            sigusr2_count--;
        }
        usleep(10 * 1000);                // 10ms 轮询间隔
    }
}
```

主循环做三件事：
1. **信号处理**：SIGTERM/SIGINT → 停止引擎；SIGHUP → 日志轮转；SIGUSR2 → 规则热重载
2. **线程监控**：定期检查工作线程是否存活
3. **休眠**：10ms 轮询间隔，避免空转

### 2.6 SuricataShutdown — 优雅关闭

```c
// src/suricata.c:3112-3121
void SuricataShutdown(void)
{
    SC_ATOMIC_SET(engine_stage, SURICATA_DEINIT);
    UnixSocketKillSocketThread();
    PostRunDeinit(suricata.run_mode, &suricata.start_time);
    TmThreadKillThreads();
}
```

设置引擎阶段为 `SURICATA_DEINIT`，逐步清理资源，杀掉所有线程。

---

## 3. 引擎三阶段状态机

整个引擎的生命周期被一个原子变量 `engine_stage` 控制（`src/suricata.h`）：

```
SURICATA_INIT → SURICATA_RUNTIME → SURICATA_DEINIT
     ↑               ↑                  ↑
  SuricataInit    SuricataPostInit    SuricataShutdown
```

| 阶段 | 含义 | 时机 |
|------|------|------|
| `SURICATA_INIT` | 初始化阶段 | 默认状态，在 `SuricataInit()` 期间 |
| `SURICATA_RUNTIME` | 运行阶段 | `SuricataPostInit()` 中所有线程就绪后设置 |
| `SURICATA_DEINIT` | 销毁阶段 | `SuricataShutdown()` 开始时设置 |

各子系统可以根据 `engine_stage` 判断当前处于哪个阶段，从而做出不同的行为决策。

---

## 4. 核心数据结构

### 4.1 Packet — 数据包

`Packet` 结构体是 Suricata 中最核心的数据结构之一（`src/decode.h:500`），每个被处理的网络数据包对应一个 `Packet` 实例。关键字段如下：

```c
// src/decode.h:500（简化展示）
typedef struct Packet_ {
    /* ====== 五元组（用于流哈希匹配）====== */
    Address src, dst;              // 源/目的 IP 地址
    Port sp, dp;                   // 源/目的端口
    uint8_t proto;                 // 协议号（TCP=6, UDP=17...）
    uint8_t recursion_level;       // 隧道嵌套层数

    /* ====== VLAN 信息 ====== */
    uint16_t vlan_id[VLAN_MAX_LAYERS];
    uint8_t vlan_idx;

    /* ====== 流关联 ====== */
    uint8_t flowflags;             // 流方向标志（FLOW_PKT_TOSERVER/TOCLIENT）
    uint32_t flags;                // 数据包标志位
    struct Flow_ *flow;            // 关联的 Flow 指针
    uint32_t flow_hash;            // 流哈希值（用于快速查找）

    /* ====== 时间戳 ====== */
    SCTime_t ts;                   // 数据包时间戳

    /* ====== 抓包驱动私有数据 ====== */
    union {
        AFPPacketVars afp_v;       // AF_PACKET
        NFQPacketVars nfq_v;       // NFQ
        PcapPacketVars pcap_v;     // libpcap
        DPDKPacketVars dpdk_v;     // DPDK
        ...
    };

    /* ====== 协议层解码结果 ====== */
    struct PacketL2 l2;            // 二层（Ethernet）
    struct PacketL3 l3;            // 三层（IPv4/IPv6）
    struct PacketL4 l4;            // 四层（TCP/UDP）

    /* ====== 载荷 ====== */
    uint8_t *payload;              // 载荷指针
    uint16_t payload_len;          // 载荷长度

    /* ====== IPS 动作 ====== */
    uint8_t action;                // 对数据包的动作（PASS/DROP/REJECT）

    /* ====== 告警 ====== */
    PacketAlerts alerts;           // 该包触发的所有告警

    /* ====== 释放与旁路 ====== */
    void (*ReleasePacket)(struct Packet_ *);    // 数据包释放回调
    int (*BypassPacketsFlow)(struct Packet_ *);  // 流旁路回调

    /* ====== 隧道处理 ====== */
    enum PacketTunnelType ttype;   // none/root/child
    struct Packet_ *root;          // 根数据包（隧道场景）

    /* ====== 内存管理 ====== */
    struct PktPool_ *pool;         // 所属内存池
    uint8_t pkt_data[];            // 柔性数组，存放原始数据包
} Packet;
```

**关键设计点**：

1. **五元组置顶**：`src/dst/sp/dp/proto` 放在结构体最前面，方便作为哈希 key 使用
2. **union 节省空间**：不同抓包驱动的私有数据使用 union，同一时刻只会使用一种
3. **柔性数组**：`pkt_data[]` 使用 C99 柔性数组成员，数据包原始内容直接跟在结构体后面，减少一次内存分配
4. **回调函数指针**：`ReleasePacket` 和 `BypassPacketsFlow` 允许不同抓包驱动注册自己的释放和旁路逻辑
5. **内存池**：每个 `Packet` 从 `PktPool` 分配，避免频繁的 malloc/free

### 4.2 Flow — 网络流

`Flow` 结构体代表一条网络流（双向），通过五元组唯一标识（`src/flow.h:347`）：

```c
// src/flow.h:347（简化展示）
typedef struct Flow_ {
    /* ====== 流 "头部"（初始化后只读）====== */
    FlowAddress src, dst;          // 源/目的地址
    Port sp, dp;                   // 源/目的端口
    uint8_t proto;                 // 协议号
    uint8_t recursion_level;       // 隧道层数
    uint16_t vlan_id[VLAN_MAX_LAYERS];

    /* ====== 哈希与链表 ====== */
    struct Flow_ *next;            // 哈希桶中的下一个 Flow
    uint32_t flow_hash;            // 原始哈希值
    struct FlowBucket_ *fb;        // 所属哈希桶指针

    /* ====== 状态管理 ====== */
    FlowStateType flow_state;      // NEW → ESTABLISHED → CLOSED
    uint32_t flags;                // 流标志位
    SCTime_t startts;              // 流创建时间
    SCTime_t lastts;               // 最后一个包的时间
    uint32_t timeout_policy;       // 超时策略（秒）

    /* ====== 锁保护 ====== */
#ifdef FLOWLOCK_RWLOCK
    SCRWLock r;                    // 读写锁
#elif defined FLOWLOCK_MUTEX
    SCMutex m;                     // 互斥锁
#endif

    /* ====== 应用层状态 ====== */
    AppProto alproto;              // 检测到的应用层协议（HTTP/TLS/DNS...）
    AppProto alproto_ts, alproto_tc; // 各方向的协议（可能不同）
    AppLayerParserState *alparser; // 应用层解析器状态
    void *alstate;                 // 应用层状态数据

    /* ====== 协议特定数据 ====== */
    void *protoctx;                // 协议上下文（如 TcpSession *）

    /* ====== 检测引擎 ====== */
    const struct SigGroupHead_ *sgh_toclient; // toclient 方向的规则组
    const struct SigGroupHead_ *sgh_toserver; // toserver 方向的规则组
    uint32_t de_ctx_version;       // 检测引擎版本号（用于热重载）

    /* ====== 统计 ====== */
    uint32_t todstpktcnt, tosrcpktcnt;   // 各方向包数
    uint64_t todstbytecnt, tosrcbytecnt; // 各方向字节数
} Flow;
```

**流的生命周期状态**（`src/flow.h`）：

```
FLOW_STATE_NEW → FLOW_STATE_ESTABLISHED → FLOW_STATE_CLOSED
                                        → FLOW_STATE_LOCAL_BYPASSED
                                        → FLOW_STATE_CAPTURE_BYPASSED
```

**关键设计点**：

1. **头部只读**：五元组（src/dst/sp/dp/proto）在创建后不再改变，无需加锁即可读取
2. **锁粒度**：每个 Flow 有独立的锁，支持编译时选择读写锁或互斥锁
3. **哈希表存储**：Flow 存在全局哈希表中，通过 `FlowBucket` 管理冲突链表
4. **双向协议检测**：`alproto_ts` 和 `alproto_tc` 允许两个方向检测到不同的协议（如 STARTTLS 场景）

### 4.3 Packet 与 Flow 的关系

```
┌─────────┐        flow_hash        ┌──────────┐
│ Packet  │ ──── FlowHandlePacket ──→│  Flow    │
│         │        查找/创建          │          │
│  .flow ─┼───────────────────────→  │ .alstate │ → 应用层状态
│  .sp/dp │                          │ .protoctx│ → TcpSession
│  .src   │                          │ .sgh_*   │ → 检测规则组
│  .dst   │                          │ .flowvar │ → 流变量
└─────────┘                          └──────────┘
```

每个 `Packet` 通过 `flow_hash` 在全局流表中查找或创建对应的 `Flow`。查找成功后，`Packet.flow` 指向该 Flow，后续的 TCP 重组、应用层解析、规则检测都在 Flow 的上下文中进行。

---

## 5. 线程模块系统 (TmModule)

### 5.1 TmModule 结构

Suricata 采用模块化的线程架构。每个功能模块（抓包、解码、流处理、检测、输出）被抽象为一个 `TmModule`（`src/tm-modules.h:47`）：

```c
// src/tm-modules.h:47-81
typedef struct TmModule_ {
    const char *name;                                    // 模块名称

    /* 线程生命周期 */
    TmEcode (*ThreadInit)(ThreadVars *, const void *, void **);   // 线程初始化
    void (*ThreadExitPrintStats)(ThreadVars *, void *);           // 退出时打印统计
    TmEcode (*ThreadDeinit)(ThreadVars *, void *);                // 线程清理

    /* 数据包处理 */
    TmEcode (*Func)(ThreadVars *, Packet *, void *);     // 处理单个包

    /* 抓包循环 */
    TmEcode (*PktAcqLoop)(ThreadVars *, void *, void *); // 持续抓包循环
    TmEcode (*PktAcqBreakLoop)(ThreadVars *, void *);    // 打断抓包循环

    /* 管理线程 */
    TmEcode (*Management)(ThreadVars *, void *);         // 管理线程主函数

    /* 全局初始化/清理 */
    TmEcode (*Init)(void);
    TmEcode (*DeInit)(void);

    uint8_t cap_flags;                                   // 能力标志
    uint8_t flags;                                       // 模块类型标志
} TmModule;
```

### 5.2 模块类型标志

模块通过 `flags` 字段标识自己的角色（`src/tm-modules.h:31-41`）：

```c
#define TM_FLAG_RECEIVE_TM      0x01    // 抓包模块（如 ReceiveAFP）
#define TM_FLAG_DECODE_TM       0x02    // 解码模块（如 DecodeAFP）
#define TM_FLAG_FLOWWORKER_TM   0x04    // 流处理+检测模块（FlowWorker）
#define TM_FLAG_VERDICT_TM      0x08    // 判决模块（如 VerdictNFQ）
#define TM_FLAG_MANAGEMENT_TM   0x10    // 管理线程（如 FlowManager）
#define TM_FLAG_COMMAND_TM      0x20    // 命令线程（如 UnixManager）
```

### 5.3 全局模块注册表

所有模块通过 ID 注册到全局数组 `tmm_modules[TMM_SIZE]`（`src/tm-modules.c:29`）。模块 ID 定义在 `src/tm-threads-common.h`：

```c
// src/tm-threads-common.h（TmmId 枚举，共 36 个模块）
typedef enum {
    TMM_FLOWWORKER,           // 流处理+检测（核心模块）
    TMM_RECEIVENFQ,           // NFQ 抓包
    TMM_VERDICTNFQ,           // NFQ 判决
    TMM_DECODENFQ,            // NFQ 解码
    TMM_RECEIVEPCAP,          // PCAP 抓包
    TMM_RECEIVEPCAPFILE,      // PCAP 文件读取
    TMM_DECODEPCAP,           // PCAP 解码
    TMM_DECODEPCAPFILE,       // PCAP 文件解码
    TMM_RECEIVEAFP,           // AF_PACKET 抓包
    TMM_DECODEAFP,            // AF_PACKET 解码
    TMM_RECEIVEDPDK,          // DPDK 抓包
    TMM_DECODEDPDK,           // DPDK 解码
    TMM_RECEIVEAFXDP,         // AF_XDP 抓包
    TMM_DECODEAFXDP,          // AF_XDP 解码
    TMM_RECEIVENETMAP,        // Netmap 抓包
    TMM_DECODENETMAP,         // Netmap 解码
    TMM_RESPONDREJECT,        // Reject 响应
    TMM_STATSLOGGER,          // 统计日志
    TMM_FLOWMANAGER,          // 流管理（超时检测）
    TMM_FLOWRECYCLER,         // 流回收
    TMM_BYPASSEDFLOWMANAGER,  // 旁路流管理
    TMM_UNIXMANAGER,          // Unix Socket 管理
    TMM_DETECTLOADER,         // 检测规则加载器
    TMM_LOGFLUSH,             // 日志刷新
    ...
    TMM_SIZE                  // 总数
} TmmId;
```

各模块的注册函数命名规则为 `TmModule<Name>Register()`，在 `SuricataInit()` 调用链中的 `PostConfLoadedSetup()` 完成注册。例如：

```c
// src/flow-worker.c:814-823
void TmModuleFlowWorkerRegister(void)
{
    tmm_modules[TMM_FLOWWORKER].name = "FlowWorker";
    tmm_modules[TMM_FLOWWORKER].ThreadInit = FlowWorkerThreadInit;
    tmm_modules[TMM_FLOWWORKER].Func = FlowWorker;
    tmm_modules[TMM_FLOWWORKER].ThreadBusy = FlowWorkerIsBusy;
    tmm_modules[TMM_FLOWWORKER].ThreadDeinit = FlowWorkerThreadDeinit;
    tmm_modules[TMM_FLOWWORKER].cap_flags = 0;
    tmm_modules[TMM_FLOWWORKER].flags = TM_FLAG_FLOWWORKER_TM;
}
```

---

## 6. 线程与流水线架构

### 6.1 ThreadVars — 线程上下文

每个 Suricata 线程由一个 `ThreadVars` 结构体管理（`src/threadvars.h:59`）：

```c
// src/threadvars.h:59-143（简化展示）
typedef struct ThreadVars_ {
    pthread_t t;                           // POSIX 线程句柄
    void *(*tm_func)(void *);             // 线程入口函数
    char name[16];                         // 线程名（如 "W#01-eth0"）

    uint8_t type;                          // 线程类型
    // TVT_PPT  = 数据包处理线程
    // TVT_MGMT = 管理线程
    // TVT_CMD  = 命令线程

    /* ====== 模块流水线 ====== */
    struct TmSlot_ *tm_slots;              // 流水线槽链表（头节点）
    struct TmSlot_ *tm_flowworker;         // 指向 FlowWorker 槽的快捷指针

    /* ====== 队列系统 ====== */
    Tmq *inq, *outq;                       // 输入/输出队列
    Packet *(*tmqh_in)(ThreadVars *);      // 输入队列处理函数
    void (*tmqh_out)(ThreadVars *, Packet *); // 输出队列处理函数

    /* ====== 内部队列 ====== */
    PacketQueueNoLock decode_pq;           // 解码器产生的伪包队列
    struct PacketQueue_ *stream_pq;        // 流超时注入包队列
    struct FlowQueue_ *flow_queue;         // 流注入队列

    /* ====== 线程控制标志 ====== */
    SC_ATOMIC_DECLARE(uint32_t, flags);    // 原子标志位
    // THV_INIT_DONE  (1<<1)  初始化完成
    // THV_PAUSE      (1<<2)  请求暂停
    // THV_KILL       (1<<4)  请求终止
    // THV_RUNNING    (1<<13) 正在运行

    /* ====== CPU 亲和性 ====== */
    uint16_t cpu_affinity;
    int thread_priority;
} ThreadVars;
```

### 6.2 TmSlot — 流水线槽

线程内部的处理流水线由 `TmSlot` 链表组成（`src/tm-threads.h:53`）：

```c
// src/tm-threads.h:53-79
typedef struct TmSlot_ {
    union {
        TmSlotFunc SlotFunc;                         // 包处理函数
        TmEcode (*PktAcqLoop)(ThreadVars *, void *, void *); // 抓包循环
        TmEcode (*Management)(ThreadVars *, void *); // 管理函数
    };

    struct TmSlot_ *slot_next;                       // 下一个槽

    SC_ATOMIC_DECLARE(void *, slot_data);            // 槽私有数据（原子指针）

    uint8_t tm_flags;                                // 模块标志副本
    int tm_id;                                       // 模块 ID

    TmEcode (*SlotThreadInit)(ThreadVars *, const void *, void **);
    void (*SlotThreadExitPrintStats)(ThreadVars *, void *);
    TmEcode (*SlotThreadDeinit)(ThreadVars *, void *);

    const void *slot_initdata;                       // 初始化数据
} TmSlot;
```

**流水线执行函数**（`src/tm-threads.c:133`）：

```c
TmEcode TmThreadsSlotVarRun(ThreadVars *tv, Packet *p, TmSlot *slot)
{
    for (TmSlot *s = slot; s != NULL; s = s->slot_next) {
        TmEcode r = s->SlotFunc(tv, p, SC_ATOMIC_GET(s->slot_data));

        if (unlikely(r == TM_ECODE_FAILED)) {
            TmThreadsSlotProcessPktFail(tv, NULL);
            return TM_ECODE_FAILED;
        }

        // 解码模块可能产生��包（如 IPv4-in-IPv6 隧道），需要递归处理
        if (s->tm_flags & TM_FLAG_DECODE_TM) {
            TmThreadsProcessDecodePseudoPackets(tv, &tv->decode_pq, s->slot_next);
        }
    }
    return TM_ECODE_OK;
}
```

这个函数遍历 TmSlot 链表，依次调用每个槽的 `SlotFunc` 处理数据包。如果当前槽是解码模块，还会检查是否产生了伪包（如解封隧道后的内层数据包）。

### 6.3 流水线构建过程

以 `TmSlotSetFuncAppend()` 为例，看模块如何被添加到线程的流水线中：

```c
// src/tm-threads.c（简化）
void TmSlotSetFuncAppend(ThreadVars *tv, TmModule *tm, const void *data)
{
    TmSlot *slot = SCCalloc(1, sizeof(TmSlot));

    slot->SlotFunc     = tm->Func;         // 复制函数指针
    slot->PktAcqLoop   = tm->PktAcqLoop;
    slot->Management   = tm->Management;
    slot->SlotThreadInit = tm->ThreadInit;
    slot->SlotThreadDeinit = tm->ThreadDeinit;
    slot->tm_id        = TmModuleGetIDForTM(tm);
    slot->tm_flags     = tm->flags;
    slot->slot_initdata = data;

    // 追加到链表末尾
    if (tv->tm_slots == NULL) {
        tv->tm_slots = slot;
    } else {
        TmSlot *s = tv->tm_slots;
        while (s->slot_next) s = s->slot_next;
        s->slot_next = slot;
    }
}
```

---

## 7. 三种运行模式的线程拓扑

Suricata 的线程拓扑由运行模式决定。三种主要模式的线程结构差异显著。

### 7.1 Workers 模式（默认，AF_PACKET/DPDK/Netmap）

```
 网卡 eth0（RSS 分流到 N 个队列）
  │
  ├── Thread W#01-eth0: [Receive] → [Decode] → [FlowWorker] → [RespondReject]
  ├── Thread W#02-eth0: [Receive] → [Decode] → [FlowWorker] → [RespondReject]
  ├── Thread W#03-eth0: [Receive] → [Decode] → [FlowWorker] → [RespondReject]
  └── Thread W#04-eth0: [Receive] → [Decode] → [FlowWorker] → [RespondReject]

  + 管理线程：FlowManager, FlowRecycler, Stats, LogFlush...
```

Workers 模式创建代码在 `src/util-runmodes.c:245`：

```c
// src/util-runmodes.c:283-324（简化）
// 每个线程包含完整流水线
ThreadVars *tv = TmThreadCreatePacketHandler(tname,
    "packetpool", "packetpool",     // 输入：从包池获取
    "packetpool", "packetpool",     // 输出：还给包池
    "pktacqloop");                  // 线程类型：抓包循环

TmSlotSetFuncAppend(tv, ReceiveAFP,    aconf);  // 槽1：抓包
TmSlotSetFuncAppend(tv, DecodeAFP,     NULL);   // 槽2：解码
TmSlotSetFuncAppend(tv, FlowWorker,    NULL);   // 槽3：流处理+检测+输出
TmSlotSetFuncAppend(tv, RespondReject, NULL);   // 槽4：拒绝响应
```

**特点**：
- 每个线程独立完成抓包→解码→检测→输出全流程
- 依赖网卡 RSS（Receive Side Scaling）将不同流分配到不同线程
- 线程间无数据包传递，锁竞争最小
- 性能最优，是 AF_PACKET 模式的默认选择

### 7.2 AutoFP 模式（PCAP/NFQ 默认）

```
 ┌─────── RX 线程（抓包+解码）─────┐       ┌──── W 线程（检测+输出）────┐
 │ RX#01: [Receive] → [Decode]    │       │ W#01: [FlowWorker] → [RR] │
 │ RX#02: [Receive] → [Decode]    │──→Q──→│ W#02: [FlowWorker] → [RR] │
 │ ...                            │       │ W#03: [FlowWorker] → [RR] │
 └────────────────────────────────┘       └────────────────────────────┘
            flow queue handler
         （按流哈希分发到 W 线程）
```

AutoFP 模式创建代码在 `src/util-runmodes.c:85`：

```c
// RX 线程
ThreadVars *tv_receive = TmThreadCreatePacketHandler(tname,
    "packetpool", "packetpool",     // 输入：从包池获取
    queues, "flow",                 // 输出：通过 flow hash 分发到队列
    "pktacqloop");
TmSlotSetFuncAppend(tv_receive, ReceiveAFP, aconf);
TmSlotSetFuncAppend(tv_receive, DecodeAFP,  NULL);

// W 线程（每个 CPU 一个）
ThreadVars *tv_detect = TmThreadCreatePacketHandler(tname,
    qname, "flow",                  // 输入：从 pickup 队列取包
    "packetpool", "packetpool",     // 输出：还给包池
    "varslot");
TmSlotSetFuncAppend(tv_detect, FlowWorker,    NULL);
TmSlotSetFuncAppend(tv_detect, RespondReject, NULL);
```

**关键机制——flow 队列处理器**：RX 线程的输出使用 `"flow"` 队列处理器，它根据数据包的 `flow_hash` 将同一条流的所有数据包分发到同一个 W 线程。这保证了：
- 同一条流的数据包始终由同一个线程处理
- TCP 重组和应用层解析不需要跨线程同步

**特点**：
- 将抓包/解码与检测/输出解耦
- 适用于无法做 RSS 分流的场景（如 PCAP 单队列）
- 多了一次跨线程的队列传递，有轻微性能损耗
- 是 PCAP 和 NFQ 模式的默认选择

### 7.3 Single 模式

```
 Thread: [Receive] → [Decode] → [FlowWorker] → [RespondReject]
 （一个线程处理所有事情）
```

仅一个工作线程，主要用于调试和测试，不适合生产环境。

### 7.4 三种模式对比总结

| 特性 | Workers | AutoFP | Single |
|------|---------|--------|--------|
| 工作线程数 | N（每网卡队列一个） | RX线程 + W线程 | 1 |
| 包分发机制 | 网卡 RSS 硬件分流 | flow hash 软件分发 | 无需分发 |
| 跨线程通信 | 无 | RX→W 队列 | 无 |
| 锁竞争 | 最小 | 队列锁 | 无 |
| 适用场景 | AF_PACKET, DPDK, Netmap | PCAP, NFQ | 调试/测试 |
| 性能 | 最优 | 良好 | 基线 |

---

## 8. FlowWorker：核心处理中枢

FlowWorker 是 Suricata 最重要的处理模块（`src/flow-worker.c`），它将流查找、TCP 重组、应用层解析、规则检测和日志输出整合在一个函数中。

### 8.1 FlowWorkerThreadData 结构

```c
// src/flow-worker.c:66-99
typedef struct FlowWorkerThreadData_ {
    DecodeThreadVars *dtv;                    // 解码上下文
    StreamTcpThread *stream_thread;           // TCP 流重组上下文
    SC_ATOMIC_DECLARE(DetectEngineThreadCtx*, detect_thread); // 检测引擎上下文（原子）
    void *output_thread;                      // 输出模块上下文
    void *output_thread_flow;                 // 流输出上下文
    PacketQueueNoLock pq;                     // 内部伪包队列
    FlowLookupStruct fls;                     // 流查找结构
} FlowWorkerThreadData;
```

注意 `detect_thread` 使用原子指针——这是为了支持规则热重载。当 SIGUSR2 触发规则重载时，主循环创建新的 `DetectEngineCtx`，然后通过原子操作替换每个线程的 `detect_thread` 指针。

### 8.2 FlowWorker() 执行流程

```c
// src/flow-worker.c:557-738（简化流程）
static TmEcode FlowWorker(ThreadVars *tv, Packet *p, void *data)
{
    FlowWorkerThreadData *fw = data;
    DetectEngineThreadCtx *det_ctx = SC_ATOMIC_GET(fw->detect_thread);

    // ① 刷新包处理
    if (PKT_IS_FLUSHPKT(p)) {
        OutputLoggerFlush(tv, p, fw->output_thread);
        return TM_ECODE_OK;
    }

    // ② PreFlow 钩子（早期检测/丢弃）
    if (det_ctx && det_ctx->de_ctx->PreFlowHook) {
        uint8_t action = det_ctx->de_ctx->PreFlowHook(tv, det_ctx, p);
        if (action & ACTION_DROP) {
            PacketDrop(p, ACTION_DROP, PKT_DROP_REASON_FLOW_PRE_HOOK);
            goto pre_flow_drop;
        }
    }

    // ③ 流查找/创建
    if (p->flags & PKT_WANTS_FLOW) {
        FlowHandlePacket(tv, &fw->fls, p);      // 在流表中查找或创建 Flow
        if (p->flow != NULL) {
            FlowUpdate(tv, fw, p);               // 更新流状态
        }
    }

    // ④ TCP 流重组
    if (p->flow && PacketIsTCP(p)) {
        FlowWorkerStreamTCPUpdate(tv, fw, p, det_ctx, false);
    }

    // ⑤ UDP 应用层解析
    if (p->flow && p->proto == IPPROTO_UDP) {
        AppLayerHandleUdp(tv, fw->stream_thread->ra_ctx->app_tctx, p, p->flow);
    }

    // ⑥ 规则检测
    if (det_ctx != NULL) {
        Detect(tv, p, det_ctx);                  // 核心检测引擎
    }

    // ⑦ 日志输出
    OutputLoggerLog(tv, p, fw->output_thread);

    // ⑧ 清理：释放 TCP 段、清理应用层事务
    if (p->flow) {
        // 释放已处理的 TCP 段，清理完成的事务
        ...
        FlowDeReference(&p->flow);               // 解除流引用
        FLOWLOCK_UNLOCK(f);                       // 释放流锁
    }

    // ⑨ 处理注入流和本地工作队列
    FlowWorkerProcessInjectedFlows(tv, fw, p);
    FlowWorkerProcessLocalFlows(tv, fw, p);

    return TM_ECODE_OK;
}
```

一图总结 FlowWorker 的处理流水线：

```
                    ┌─── FlowWorker() ────────────────────────────┐
                    │                                              │
  Packet ────→ [PreFlowHook] → [FlowLookup] → [StreamTCP]        │
     │              │               │              │               │
     │           早期丢弃        查找/创建        TCP 重组          │
     │              │             Flow           +应用层解析       │
     │              ↓               │              │               │
     │                              ↓              ↓               │
     │                         [AppLayer UDP] ─────┘               │
     │                              │                              │
     │                              ↓                              │
     │                         [Detect()]                          │
     │                         规则匹配                            │
     │                              │                              │
     │                              ↓                              │
     │                         [OutputLog]                         │
     │                         日志输出                            │
     │                              │                              │
     │                              ↓                              │
     │                         [Cleanup]                           │
     │                         释放资源                            │
     └─────────────────────────────────────────────────────────────┘
```

---

## 9. 管理线程

除了数据包处理线程，Suricata 还启动多个管理线程（`src/suricata.c` 中 `RunModeDispatch()` 创建）：

| 线程名 | 模块 ID | 职责 |
|--------|---------|------|
| FlowManagerThread | `TMM_FLOWMANAGER` | 定期扫描流表，检测超时流，生成超时伪包 |
| FlowRecyclerThread | `TMM_FLOWRECYCLER` | 回收已关闭的 Flow 对象，释放内存 |
| StatsLogger | `TMM_STATSLOGGER` | 收集和输出性能统计数据（counters） |
| LogFlush | `TMM_LOGFLUSH` | 定期刷新日志输出缓冲区 |
| BypassedFlowManager | `TMM_BYPASSEDFLOWMANAGER` | 管理被旁路（bypass）的流 |
| UnixManagerThread | `TMM_UNIXMANAGER` | 处理 Unix Socket 命令（如 `suricatasc`） |
| DetectLoader | `TMM_DETECTLOADER` | 加载检测规则（热重载时使用） |

管理线程使用 `TmThreadCreateMgmtThread()` 创建，类型为 `TVT_MGMT`。与数据包处理线程不同，管理线程没有输入/输出队列，它们通过共享内存和原子变量与工作线程通信。

**FlowManager 与工作线程的交互**：

```
FlowManager 线程                      Worker 线程
     │                                     │
     │  扫描流表发现超时流                    │
     │     │                               │
     │     ├── 创建超时伪包                  │
     │     │   (PKT_IS_PSEUDOPKT)          │
     │     │                               │
     │     └── 注入到 Worker 的              │
     │         stream_pq 队列 ─────────────→│
     │                                     │
     │                            TmThreadsHandleInjectedPackets()
     │                            处理超时伪包（释放流资源）
```

---

## 10. 数据包的完整旅程

综合以上各组件，一个网络数据包在 Suricata 中的完整旅程如下：

```
┌─────────────────────────────────────────────────────────────────┐
│                      数据包的一生                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ① PacketPool                                                   │
│     从预分配的内存池获取空白 Packet 结构体                        │
│     │                                                           │
│  ② Receive（抓包模块）                                          │
│     从网卡/文件/NFQ 读取原始数据，填充 Packet                     │
│     设置时间戳、数据长度、抓包驱动特定字段                        │
│     │                                                           │
│  ③ Decode（解码模块）                                           │
│     逐层解析协议头：Ethernet → IPv4/IPv6 → TCP/UDP              │
│     填充 l2/l3/l4 层结构，设置五元组和 payload 指针              │
│     可能产生伪包（隧道解封装）                                   │
│     │                                                           │
│  ④ FlowWorker（流处理+检测+输出）                               │
│     ├── FlowHandlePacket：在流表中查找/创建 Flow                │
│     ├── StreamTCP：TCP 流重组（GAP 处理、乱序重排）             │
│     ├── AppLayer：应用层协议检测与解析（HTTP/TLS/DNS...）       │
│     ├── Detect：多模式匹配 + 规则检测                           │
│     ├── OutputLog：生成 EVE JSON 日志/告警                      │
│     └── Cleanup：释放 TCP 段、清理完成的事务                    │
│     │                                                           │
│  ⑤ RespondReject（可选）                                        │
│     IPS 模式下发送 RST/ICMP Unreachable 拒绝包                  │
     │                                                           │
│  ⑥ PacketPool                                                   │
│     数据包返还到内存池，等待下次使用                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 10.1 时序详解（Workers 模式）

以 AF_PACKET Workers 模式处理一个 HTTP GET 请求为例：

```
时间线    操作                                 源码位置
───────────────────────────────────────────────────────────────
t0       从 PacketPool 获取 Packet             tmqh-packetpool.c
t1       AF_PACKET recvmsg() 读取原始帧        source-af-packet.c
t2       DecodeAFP() 解析 Ethernet 头          source-af-packet.c
t3       DecodeEthernet() → DecodeIPv4()       decode-ethernet.c
         → DecodeTCP()                         decode-tcp.c
         填充 p->src/dst/sp/dp/proto
t4       计算 flow_hash                        flow-hash.c
t5       FlowHandlePacket() 查找流表           flow-hash.c
         → 首包：创建新 Flow
         → 后续包：找到已有 Flow
t6       StreamTcpPacket() TCP 状态机          stream-tcp.c
         处理 SYN/ACK/数据/FIN
t7       StreamTcpReassembleHandleSegment()    stream-tcp-reassemble.c
         重组 TCP 流，回调应用层解析器
t8       AppLayerParserParse()                 app-layer-parser.c
         HTTP 请求解析 → 创建事务
t9       Detect(tv, p, det_ctx)                detect.c
         多模式匹配 → 签名逐条验证
t10      OutputLoggerLog()                     output.c
         生成 EVE JSON 事件
t11      FlowDeReference(&p->flow)             flow.c
         释放流引用，解锁
t12      tmqh_out(tv, p)                       tmqh-packetpool.c
         数据包返还内存池
```

### 10.2 IPS 模式的额外步骤

在 IPS 模式（如 NFQ）下，数据包旅程有额外环节：

```
Receive(NFQ) → Decode → FlowWorker → Verdict(NFQ)
                                        │
                                   NF_ACCEPT 或 NF_DROP
                                   通过 nfq_set_verdict()
                                   告知内核放行或丢弃
```

AutoFP 模式下，NFQ 还需要 Verdict 线程将判决结果回写给内核。

---

## 11. 输出模块注册体系

Suricata 的输出（日志）系统采用分层注册架构（`src/output.c`）：

```
RootLogger（根日志器）
├── PacketLogger     — 基于 Packet 的日志（alert, drop）
├── TxLogger         — 基于事务的日志（http, dns, tls...）
├── FileLogger       — 文件相关日志（fileinfo, filestore）
├── FlowLogger       — 流日志
├── StreamingLogger  — 流式数据日志
└── StatsLogger      — 统计日志
```

每种日志器类型都有对应的注册函数：

```c
// src/output.c
OutputRegisterModule()              // 通用模块注册
OutputRegisterPacketModule()        // 包级日志模块
OutputRegisterTxModule()            // 事务级日志模块
OutputRegisterFileSubModule()       // 文件日志子模块
```

所有注册的模块存放在全局链表 `output_modules` 中（`src/output.c:119`）。在 `SuricataInit()` 期间，`OutputSetupActiveLoggers()` 根据 `suricata.yaml` 的 `outputs` 配置激活对应的模块。

输出框架的详细源码分析将在第 15 篇中展开。

---

## 12. 子系统关系图

将所有子系统的关系整合成一张全景图：

```
┌──────────────────── Suricata 架构全景 ──────────────────────┐
│                                                              │
│  ┌─── 配置层 ─────────────────────────────────────────┐     │
│  │  suricata.yaml   命令行参数   SCInstance            │     │
│  └─────────────────────────┬───────────────────────────┘     │
│                            │                                 │
│  ┌─── 线程管理层 ──────────┼───────────────────────────┐     │
│  │  RunModeDispatch()      │                           │     │
│  │  ├── Workers/AutoFP/Single 模式选择                 │     │
│  │  ├── TmThread 创建与 TmSlot 流水线组装              │     │
│  │  └── 管理线程启动                                   │     │
│  └─────────────────────────┬───────────────────────────┘     │
│                            │                                 │
│  ┌─── 数据处理层 ──────────┼───────────────────────────┐     │
│  │                         ↓                           │     │
│  │  ┌──────┐  ┌──────┐  ┌──────────────────────┐      │     │
│  │  │Receive│→│Decode│→│     FlowWorker        │      │     │
│  │  │      │  │      │  │  ┌────────────────┐  │      │     │
│  │  │AF_PKT│  │ IPv4 │  │  │  Flow Lookup   │  │      │     │
│  │  │PCAP  │  │ IPv6 │  │  │  Stream TCP    │  │      │     │
│  │  │NFQ   │  │ TCP  │  │  │  App Layer     │  │      │     │
│  │  │DPDK  │  │ UDP  │  │  │  Detect Engine │  │      │     │
│  │  │...   │  │ ...  │  │  │  Output Logger │  │      │     │
│  │  └──────┘  └──────┘  │  └────────────────┘  │      │     │
│  │                      └──────────────────────┘      │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                              │
│  ┌─── 管理层 ─────────────────────────────────────────┐     │
│  │  FlowManager (超时)     FlowRecycler (回收)         │     │
│  │  StatsLogger (统计)     UnixManager (命令)          │     │
│  │  DetectLoader (规则热重载)                          │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                              │
│  ┌─── 存储层 ─────────────────────────────────────────┐     │
│  │  FlowHash (流表)    PacketPool (包池)               │     │
│  │  DetectEngineCtx (规则)  HostTable (主机表)         │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 13. 实验：观察线程拓扑

### 13.1 查看 Workers 模式线程

在 Docker 实验环境中运行：

```bash
# 启动 Suricata（AF_PACKET Workers 模式）
suricata -c /etc/suricata/suricata.yaml -i eth0 &

# 查看线程
ps -T -p $(pidof suricata) | head -20
```

输出类似：

```
  PID  SPID  TTY      TIME CMD
 1234  1234  ?    00:00:00 suricata
 1234  1235  ?    00:00:01 W#01-eth0        ← Workers 线程
 1234  1236  ?    00:00:01 W#02-eth0
 1234  1237  ?    00:00:01 W#03-eth0
 1234  1238  ?    00:00:01 W#04-eth0
 1234  1239  ?    00:00:00 FM               ← FlowManager
 1234  1240  ?    00:00:00 FR               ← FlowRecycler
 1234  1241  ?    00:00:00 SL               ← StatsLogger
 1234  1242  ?    00:00:00 LF               ← LogFlush
 1234  1243  ?    00:00:00 US               ← UnixManager
```

线程名的约定（定义在 `src/runmodes.h`）：
- `W` = Workers 线程（`thread_name_workers`）
- `RX` = AutoFP 的接收线程（`thread_name_autofp`）
- `TX` = Verdict 线程（`thread_name_verdict`）
- `FM` = FlowManager
- `FR` = FlowRecycler

### 13.2 查看 AutoFP 模式线程

```bash
# PCAP 模式默认使用 AutoFP
suricata -c /etc/suricata/suricata.yaml -i eth0 --runmode autofp &

ps -T -p $(pidof suricata) | head -20
```

```
  PID  SPID  TTY      TIME CMD
 2345  2345  ?    00:00:00 suricata
 2345  2346  ?    00:00:01 RX#01-eth0       ← 接收+解码线程
 2345  2347  ?    00:00:01 W#01             ← 检测线程（从队列读取）
 2345  2348  ?    00:00:01 W#02
 2345  2349  ?    00:00:01 W#03
 2345  2350  ?    00:00:01 W#04
 2345  2351  ?    00:00:00 FM
 ...
```

### 13.3 读取 PCAP 文件

```bash
# 读取 PCAP 文件（通常使用 single 或 autofp 模式）
suricata -r /opt/pcaps/test.pcap -l /tmp/suricata-test/

# 查看统计输出
cat /tmp/suricata-test/stats.log | grep "capture.kernel"
```

---

## 14. 本篇小结与后续预告

本篇从宏观视角建立了 Suricata 的架构认知：

| 知识点 | 关键源码文件 |
|--------|-------------|
| 引擎生命周期（10 步启动） | `src/main.c`, `src/suricata.c` |
| 全局状态 SCInstance | `src/suricata.h` |
| Packet 结构体 | `src/decode.h:500` |
| Flow 结构体 | `src/flow.h:347` |
| TmModule 线程模块系统 | `src/tm-modules.h`, `src/tm-modules.c` |
| TmSlot 流水线 | `src/tm-threads.h:53` |
| ThreadVars 线程上下文 | `src/threadvars.h:59` |
| 流水线执行 TmThreadsSlotVarRun | `src/tm-threads.c:133` |
| FlowWorker 核心处理 | `src/flow-worker.c:557` |
| 运行模式线程拓扑 | `src/util-runmodes.c` |
| 输出模块注册 | `src/output.c` |

**后续文章预告**：

- **第 10 篇：解码层 — 协议栈逐层解包**：深入 `decode-*.c`，看 Ethernet → IPv4/IPv6 → TCP/UDP 的逐层解析过程，理解解码器如何填充 `Packet` 的各层结构
- **第 11 篇：流处理与 TCP 重组**：深入 `flow-*.c` 和 `stream-tcp*.c`，了解流表的哈希实现、TCP 状态机和流重组算法
- **第 12 篇：应用层协议检测与解析**：深入 `app-layer-*.c`，理解协议检测（probing parser）和解析器框架

---

> **参考源码版本**：Suricata 8.0.3（commit: 3bd9f773b）
> **核心文件清单**：`src/main.c`(69行), `src/suricata.c`(3200+行), `src/suricata.h`(256行), `src/decode.h`(700+行), `src/flow.h`(500+行), `src/flow-worker.c`(823行), `src/tm-modules.h`(81行), `src/tm-threads.h`(220+行), `src/tm-threads.c`(1300+行), `src/threadvars.h`(143行), `src/util-runmodes.c`(400+行), `src/output.c`(1000+行)
