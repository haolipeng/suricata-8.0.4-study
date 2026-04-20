# 13 - 检测引擎（上）：规则加载与 Signature 结构

> **导读**：前几篇我们走完了数据包从解码、流处理、TCP 重组到应用层解析的全部旅程。从本篇开始，进入 Suricata 的核心——**检测引擎**。本篇（上篇）聚焦"静态"部分：规则如何被解析为内存中的 `Signature` 结构、关键字如何通过 `sigmatch_table` 注册、签名如何经过四阶段构建（`SigPrepareStage1-4`）形成运行时的 `SigGroupHead` 分组。下一篇（下篇）则关注"动态"部分：多模式匹配（MPM）与检测执行流程。

---

## 1. 检测引擎在流水线中的位置

回顾 FlowWorker 流水线，检测引擎处于应用层解析之后：

```
[Decode] → FlowWorker {
    ① FlowHandlePacket()              ← 流查找/创建
    ② StreamTcpPacket()               ← TCP 状态机 + 重组
    ③ AppLayerHandleTCPData()         ← 应用层协议解析
    ④ Detect()                        ← 检测引擎（本篇 + 下篇）
    ⑤ OutputLoggerLog()               ← 日志输出
}
```

检测引擎可以分为两大阶段：

- **初始化阶段**（本篇重点）：加载规则文件 → 解析为 `Signature` 链表 → 构建签名分组 → 生成运行时数据结构
- **运行时阶段**（下篇重点）：对每个数据包/事务执行预过滤 → 逐签名匹配 → 触发告警/动作

---

## 2. 规则的文本结构

在深入源码之前，先回顾一条 Suricata 规则的标准格式：

```
action protocol src_addr src_port direction dst_addr dst_port (options)
```

例如：

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Example"; flow:established,to_server; content:"GET"; http.method; content:"/evil"; http.uri; sid:2001001; rev:1;)
```

规则由两部分组成：

| 部分 | 内容 | 对应解析函数 |
|------|------|-------------|
| **头部（Header）** | action、protocol、地址、端口、方向 | `SigParseBasics()` |
| **选项（Options）** | 括号内的关键字列表 | `SigParseOptions()` |

每个选项关键字（如 `content`、`flow`、`sid`）都对应 `sigmatch_table` 中的一个注册项，由其 `Setup()` 回调完成解析。

---

## 3. 关键字注册体系：sigmatch_table

### 3.1 SigTableElmt 结构

Suricata 的每个检测关键字都通过 `SigTableElmt` 结构注册到全局数组 `sigmatch_table[]` 中。该结构定义在 `src/detect.h:1417-1464`：

```c
// src/detect.h:1417-1464
typedef struct SigTableElmt_ {
    /** 包匹配函数 */
    int (*Match)(DetectEngineThreadCtx *, Packet *,
                 const Signature *, const SigMatchCtx *);

    /** 应用层 TX 匹配函数 */
    int (*AppLayerTxMatch)(DetectEngineThreadCtx *, Flow *,
            uint8_t flags, void *alstate, void *txv,
            const Signature *, const SigMatchCtx *);

    /** 文件匹配函数 */
    int (*FileMatch)(DetectEngineThreadCtx *,
        Flow *, uint8_t flags, File *,
        const Signature *, const SigMatchCtx *);

    /** InspectionBuffer 转换回调 */
    void (*Transform)(DetectEngineThreadCtx *,
                      InspectionBuffer *, void *context);

    /** 关键字解析 Setup 回调 */
    int (*Setup)(DetectEngineCtx *, Signature *, const char *);

    /** 预过滤支持 */
    bool (*SupportsPrefilter)(const Signature *s);
    int (*SetupPrefilter)(DetectEngineCtx *de_ctx,
                          struct SigGroupHead_ *sgh);

    void (*Free)(DetectEngineCtx *, void *);

    uint16_t flags;     // SIGMATCH_* 标志
    uint8_t tables;     // 支持的检测表
    const char *name;   // 关键字名称
    const char *alias;  // 别名
    const char *desc;   // 描述
    const char *url;    // 文档链接
} SigTableElmt;
```

每个关键字最核心的三个回调：

| 回调 | 作用 | 调用时机 |
|------|------|---------|
| `Setup` | 解析关键字参数，创建 `SigMatchCtx` 并添加到签名 | 规则加载阶段 |
| `Match` | 针对包级别数据执行匹配 | 运行时检测 |
| `AppLayerTxMatch` | 针对应用层事务执行匹配 | 运行时检测 |

### 3.2 DetectKeywordId 枚举

每个关键字都有一个唯一的整数 ID，定义在 `src/detect-engine-register.h:27` 的 `DetectKeywordId` 枚举中：

```c
// src/detect-engine-register.h:27-96（节选）
enum DetectKeywordId {
    DETECT_SID,
    DETECT_PRIORITY,
    DETECT_REV,
    DETECT_CLASSTYPE,
    DETECT_APP_LAYER_PROTOCOL,
    DETECT_ACK,
    DETECT_SEQ,
    DETECT_FLAGS,
    DETECT_TTL,
    DETECT_DSIZE,
    DETECT_FLOW,
    // ...
    DETECT_CONTENT,
    DETECT_PCRE,
    DETECT_DEPTH,
    DETECT_DISTANCE,
    DETECT_WITHIN,
    DETECT_OFFSET,
    DETECT_FAST_PATTERN,
    DETECT_BYTETEST,
    DETECT_BYTEJUMP,
    // ...
    DETECT_TBLSIZE,  // 数组大小哨兵
};
```

枚举的前面部分（`DETECT_APP_LAYER_PROTOCOL` 到 `DETECT_FLOW`）按预过滤优先级排列——ID 越小的关键字在自动预过滤选择时优先级越高。

### 3.3 SIGMATCH 标志

关键字的 `flags` 字段使用如下标志位，定义在 `src/detect.h:1648-1682`：

```c
#define SIGMATCH_NOOPT              BIT_U16(0)   // 无参数
#define SIGMATCH_IPONLY_COMPAT      BIT_U16(1)   // 兼容 IP-only 规则
#define SIGMATCH_DEONLY_COMPAT      BIT_U16(2)   // 兼容 Decoder-Event-only 规则
#define SIGMATCH_OPTIONAL_OPT       BIT_U16(4)   // 参数可选
#define SIGMATCH_QUOTES_OPTIONAL    BIT_U16(5)   // 参数可加引号
#define SIGMATCH_QUOTES_MANDATORY   BIT_U16(6)   // 参数必须加引号
#define SIGMATCH_HANDLE_NEGATION    BIT_U16(7)   // 由解析器处理取反
#define SIGMATCH_INFO_CONTENT_MODIFIER BIT_U16(8)  // 内容修饰符
#define SIGMATCH_INFO_STICKY_BUFFER    BIT_U16(9)  // 粘性缓冲区
#define SIGMATCH_INFO_DEPRECATED       BIT_U16(10) // 已废弃关键字
#define SIGMATCH_STRICT_PARSING        BIT_U16(11) // 严格解析模式
#define SIGMATCH_SUPPORT_FIREWALL      BIT_U16(12) // 支持防火墙规则
```

这些标志决定了规则解析器如何处理关键字参数（是否需要引号、是否支持取反），以及关键字是否兼容特殊的规则分类（IP-only、Decoder-Event-only）。

---

## 4. 签名匹配元素：SigMatch 与 SigMatchData

### 4.1 初始化时结构：SigMatch

规则加载期间，每个关键字实例被表示为一个 `SigMatch` 节点，形成双向链表：

```c
// src/detect.h:356-362
typedef struct SigMatch_ {
    uint16_t type;           // 关键字类型（DetectKeywordId）
    uint16_t idx;            // 在签名中的位置索引
    SigMatchCtx *ctx;        // 关键字私有数据（由 Setup 分配）
    struct SigMatch_ *next;
    struct SigMatch_ *prev;
} SigMatch;
```

`SigMatch` 链表按关键字在规则中出现的顺序排列。例如对于规则选项 `content:"GET"; http.method; content:"/evil"; http.uri;`，会生成如下链表：

```
SigMatch{type=DETECT_CONTENT, ctx=→"GET"}
    → SigMatch{type=DETECT_HTTP_METHOD}
        → SigMatch{type=DETECT_CONTENT, ctx=→"/evil"}
            → SigMatch{type=DETECT_HTTP_URI}
```

### 4.2 运行时结构：SigMatchData

初始化完成后，`SigMatch` 双向链表被压缩为更紧凑的 `SigMatchData` 数组，去掉了 `prev`/`next` 指针和 `idx`，用布尔标志标记末尾：

```c
// src/detect.h:365-369
typedef struct SigMatchData_ {
    uint16_t type;       // 关键字类型
    bool is_last;        // 是否为列表末尾
    SigMatchCtx *ctx;    // 关键字私有数据
} SigMatchData;
```

这个转换在 `SigMatchPrepare()` 中完成（`src/detect-engine-build.c:2110-2174`），核心逻辑是调用 `SigMatchList2DataArray()` 将链表转为数组：

```c
// src/detect-engine-build.c:2119-2126
for (int type = 0; type < DETECT_SM_LIST_MAX; type++) {
    if (type == DETECT_SM_LIST_PMATCH &&
        (s->init_data->init_flags & SIG_FLAG_INIT_STATE_MATCH))
        continue;
    SigMatch *sm = s->init_data->smlists[type];
    s->sm_arrays[type] = SigMatchList2DataArray(sm);
}
```

转换完成后，`SigMatch` 链表被释放，`init_data` 被整体释放，节省大量内存。运行时检测引擎只需遍历 `SigMatchData` 数组，用 `is_last` 判断终止，比遍历链表更快且缓存友好。

### 4.3 签名匹配列表分类

签名内的关键字被分到不同的列表中，由 `DetectSigmatchListEnum` 定义（`src/detect.h:115-139`）：

```c
// src/detect.h:115-139
enum DetectSigmatchListEnum {
    DETECT_SM_LIST_MATCH = 0,     // 包级别非负载匹配（ttl, flow 等）
    DETECT_SM_LIST_PMATCH,        // 负载/流内容匹配（content 等）
    DETECT_SM_LIST_BASE64_DATA,   // base64_data 关键字
    DETECT_SM_LIST_POSTMATCH,     // 匹配后动作（flowbit set 等）
    DETECT_SM_LIST_TMATCH,        // 后检测标记（tag）
    DETECT_SM_LIST_SUPPRESS,      // 告警抑制
    DETECT_SM_LIST_THRESHOLD,     // 阈值控制
    DETECT_SM_LIST_MAX,           // 内置列表上限

    // 动态注册的列表从这里开始（粘性缓冲区如 http.uri 等）
    DETECT_SM_LIST_DYNAMIC_START = DETECT_SM_LIST_MAX,
};
```

**内置列表**（0 到 `DETECT_SM_LIST_MAX`）存储在 `Signature->sm_arrays[]` 固定大小数组中。**动态列表**（粘性缓冲区如 `http.uri`、`dns.query` 等）则通过 `Signature->init_data->buffers[]` 动态数组管理，每个缓冲区对应一个独立的检测引擎（Inspect Engine）。

---

## 5. Signature 结构详解

`Signature` 是整个检测引擎中最核心的数据结构，定义在 `src/detect.h:668-751`。它存储了一条规则从解析到运行时需要的所有信息。

### 5.1 完整结构

```c
// src/detect.h:668-751
typedef struct Signature_ {
    /* ===== 标志与分类 ===== */
    uint32_t flags;               // SIG_FLAG_* 标志集合
    enum SignatureType type;      // 规则类型（IP-only/PD-only/PKT/APP_TX 等）
    AppProto alproto;             // 关联的应用层协议

    /* ===== 负载大小约束 ===== */
    uint16_t dsize_low;
    uint16_t dsize_high;
    uint8_t dsize_mode;

    /* ===== 快速过滤 ===== */
    SignatureMask mask;           // 快速排除掩码
    SigIntId iid;                 // 内部唯一 ID（数组索引）
    uint8_t action;               // 动作（alert/drop/pass/reject）
    uint8_t file_flags;           // 文件相关标志

    /* ===== 协议与地址 ===== */
    DetectProto proto;            // IP 协议匹配
    uint16_t addr_dst_match4_cnt; // IPv4 目标地址数量
    uint16_t addr_src_match4_cnt;
    uint16_t addr_dst_match6_cnt; // IPv6 目标地址数量
    uint16_t addr_src_match6_cnt;
    DetectMatchAddressIPv4 *addr_dst_match4;
    DetectMatchAddressIPv4 *addr_src_match4;
    DetectMatchAddressIPv6 *addr_dst_match6;
    DetectMatchAddressIPv6 *addr_src_match6;

    /* ===== 规则元数据 ===== */
    uint16_t class_id;            // 分类 ID
    uint8_t detect_table;         // 检测表（enum DetectTable）
    uint8_t app_progress_hook;    // 防火墙规则的进度钩子
    uint32_t id;                  // sid（规则 ID）
    uint32_t gid;                 // generator ID
    uint32_t rev;                 // 版本号
    int prio;                     // 优先级
    DetectPort *sp, *dp;          // 源/目标端口

    /* ===== 检测引擎 ===== */
    DetectEngineAppInspectionEngine *app_inspect;    // 应用层检测引擎链
    DetectEnginePktInspectionEngine *pkt_inspect;    // 包级别检测引擎链
    DetectEngineFrameInspectionEngine *frame_inspect; // 帧检测引擎链
    SigMatchData *sm_arrays[DETECT_SM_LIST_MAX];     // 运行时匹配数组

    /* ===== 描述信息 ===== */
    char *msg;                    // 告警消息
    char *class_msg;              // 分类消息
    DetectReference *references;  // 参考链接
    DetectMetadataHead *metadata; // 元数据
    char *sig_str;                // 原始规则字符串

    /* ===== 初始化数据 ===== */
    SignatureInitData *init_data; // 初始化阶段数据（构建后释放）
    struct Signature_ *next;      // 链表指针
} Signature;
```

### 5.2 关键字段解析

**flags（SIG_FLAG_*）**

`flags` 是一个 32 位位掩码，编码了规则的多种属性，定义在 `src/detect.h:241-287`：

```c
#define SIG_FLAG_SRC_ANY         BIT_U32(0)   // 源地址为 any
#define SIG_FLAG_DST_ANY         BIT_U32(1)   // 目标地址为 any
#define SIG_FLAG_SP_ANY          BIT_U32(2)   // 源端口为 any
#define SIG_FLAG_DP_ANY          BIT_U32(3)   // 目标端口为 any
#define SIG_FLAG_DSIZE           BIT_U32(5)   // 使用了 dsize 关键字
#define SIG_FLAG_APPLAYER        BIT_U32(6)   // 应用层规则
#define SIG_FLAG_TXBOTHDIR       BIT_U32(7)   // 需要双方向 tx
#define SIG_FLAG_REQUIRE_PACKET  BIT_U32(9)   // 需要包匹配
#define SIG_FLAG_REQUIRE_STREAM  BIT_U32(10)  // 需要流匹配
#define SIG_FLAG_MPM_NEG         BIT_U32(11)  // MPM 模式带取反
#define SIG_FLAG_TOSERVER        BIT_U32(19)  // to_server 方向
#define SIG_FLAG_TOCLIENT        BIT_U32(20)  // to_client 方向
#define SIG_FLAG_PREFILTER       BIT_U32(23)  // 参与预过滤
#define SIG_FLAG_FILESTORE       BIT_U32(18)  // 使用 filestore
```

**SignatureType（规则分类）**

每条规则在初始化时会被 `SignatureSetType()` 分类为以下类型之一（`src/detect.h:64-80`）：

```c
enum SignatureType {
    SIG_TYPE_NOT_SET = 0,
    SIG_TYPE_IPONLY,       // 仅检查 IP 地址（Radix 树匹配）
    SIG_TYPE_LIKE_IPONLY,  // 类似 IP-only，走包引擎
    SIG_TYPE_PDONLY,       // 仅检查协议检测结果
    SIG_TYPE_DEONLY,       // 仅匹配解码器事件
    SIG_TYPE_PKT,          // 包级别检测
    SIG_TYPE_PKT_STREAM,   // 包 + 流检测
    SIG_TYPE_STREAM,       // 纯流检测
    SIG_TYPE_APPLAYER,     // 应用层但非 TX
    SIG_TYPE_APP_TX,       // 应用层 TX 检测（最常见）
};
```

这个分类至关重要——它决定了规则在哪个检测路径中被执行。分类逻辑在 `SignatureSetType()` 中（`src/detect-engine-build.c:1636-1704`），按优先级依次检查：

```
SignatureSetType() 判定顺序：
    ① hook.type == APP → SIG_TYPE_APP_TX
    ② SignatureIsPDOnly() → SIG_TYPE_PDONLY
    ③ SignatureIsIPOnly() → SIG_TYPE_IPONLY / SIG_TYPE_LIKE_IPONLY
    ④ SignatureIsDEOnly() → SIG_TYPE_DEONLY
    ⑤ 根据 buffer/pmatch/match 类型 → PKT/STREAM/PKT_STREAM/APP_TX
    ⑥ 有 SIG_FLAG_APPLAYER → SIG_TYPE_APPLAYER
    ⑦ 默认 → SIG_TYPE_PKT
```

**SignatureMask（快速排除掩码）**

`mask` 字段用于快速排除明显不匹配的签名。系统同时为每个数据包计算一个 `PacketMask`，只有 `(sig->mask & pkt_mask) == sig->mask` 时，签名才需要进一步检测。掩码包括：

- `SIG_MASK_REQUIRE_PAYLOAD` — 需要有负载
- `SIG_MASK_REQUIRE_NO_PAYLOAD` — 需要无负载
- `SIG_MASK_REQUIRE_FLOW` — 需要有流上下文
- `SIG_MASK_REQUIRE_REAL_PKT` — 需要真实包（非伪包）
- `SIG_MASK_REQUIRE_FLAGS_INITDEINIT` — 需要 SYN/RST/FIN 标志
- `SIG_MASK_REQUIRE_ENGINE_EVENT` — 需要引擎事件

掩码在 `SignatureCreateMask()` 中生成（`src/detect-engine-build.c:440`），根据签名使用的关键字自动设置。

### 5.3 SignatureInitData（初始化阶段数据）

`SignatureInitData` 存储仅在初始化阶段需要的数据，构建完成后会被释放以节省内存。定义在 `src/detect.h:589-665`，关键字段：

```c
// src/detect.h:589-665（关键字段）
typedef struct SignatureInitData_ {
    // 初始化标志
    uint32_t init_flags;     // SIG_FLAG_INIT_* 标志

    // 关键字匹配列表（初始化用的链表头）
    SigMatch *smlists[DETECT_SM_LIST_MAX];
    SigMatch *smlists_tail[DETECT_SM_LIST_MAX];

    // 动态缓冲区（粘性缓冲区的关键字列表）
    SignatureInitDataBuffer *buffers;
    uint32_t buffer_index;
    uint32_t buffers_size;

    // 多协议支持
    AppProto alprotos[SIG_ALPROTO_MAX];

    // MPM（多模式匹配）候选
    SigMatch *mpm_sm;
    uint16_t mpm_sm_list;

    // 预过滤候选
    SigMatch *prefilter_sm;
    bool has_possible_prefilter;

    // 转换操作
    DetectEngineTransforms transforms;

    // 签名评分（用于排序）
    int score;

    // Hook（防火墙规则的钩子点）
    SignatureHook hook;
    bool firewall_rule;

    // 取反标记（当前关键字）
    bool negated;
} SignatureInitData;
```

`init_data->smlists[]` 是初始化阶段的关键字链表，与运行时的 `sm_arrays[]` 对应。在 `SigMatchPrepare()` 中，前者被转换为后者，然后 `init_data` 被整体释放。

---

## 6. 规则解析流程

### 6.1 总体流程

```
SigLoadSignatures()                          ← 入口
  ├── ProcessSigFiles()                      ← 逐文件处理
  │     └── DetectEngineAppendSig()          ← 逐条解析
  │           └── SigInit()
  │                 └── SigInitHelper()
  │                       ├── SigParse()     ← 解析规则文本
  │                       │   ├── SigParseBasics()  ← 解析头部
  │                       │   └── SigParseOptions() ← 解析选项（循环）
  │                       ├── SigSetupPrefilter()   ← 选择预过滤关键字
  │                       └── SigValidateConsolidate() ← 验证与分类
  ├── SCSigOrderSignatures()                 ← 签名排序
  └── SigGroupBuild()                        ← 构建签名分组
```

### 6.2 SigLoadSignatures：加载入口

`SigLoadSignatures()` 是规则加载的入口函数，定义在 `src/detect-engine-loader.c:372-517`。它的职责是：

```c
// src/detect-engine-loader.c:372-517（流程简化）
int SigLoadSignatures(DetectEngineCtx *de_ctx,
                      char *sig_file, bool sig_file_exclusive)
{
    // 1. 加载防火墙规则文件（如果配置了）
    LoadFirewallRuleFiles(de_ctx);

    // 2. 从 yaml 配置的 rule-files 列表逐个加载
    TAILQ_FOREACH(file, &rule_files->head, next) {
        sfile = DetectLoadCompleteSigPath(de_ctx, file->val);
        ProcessSigFiles(de_ctx, sfile, sig_stat,
                        &good_sigs, &bad_sigs, &skipped_sigs);
    }

    // 3. 加载命令行 -s 指定的规则文件
    if (sig_file != NULL) {
        ProcessSigFiles(de_ctx, sig_file, ...);
    }

    // 4. 签名排序
    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    // 5. 阈值配置
    SCThresholdConfInitContext(de_ctx);

    // 6. 构建签名分组（核心！）
    SigGroupBuild(de_ctx);
}
```

`ProcessSigFiles()` 对每条规则调用 `DetectEngineAppendSig()`，后者是解析单条规则的入口。

### 6.3 DetectEngineAppendSig：解析与去重

`DetectEngineAppendSig()` 在 `src/detect-parse.c:3439-3489` 中定义，负责解析单条规则并将其加入 `de_ctx->sig_list` 链表：

```c
// src/detect-parse.c:3439-3489
Signature *DetectEngineAppendSig(DetectEngineCtx *de_ctx,
                                 const char *sigstr)
{
    // 1. 调用 SigInit 解析规则字符串
    Signature *sig = SigInit(de_ctx, sigstr);

    // 2. 检查重复签名（相同 sid + gid）
    int dup_sig = DetectEngineSignatureIsDuplicate(de_ctx, sig);
    if (dup_sig == 1) {
        SCLogError("Duplicate signature \"%s\"", sigstr);
        goto error;
    } else if (dup_sig == 2) {
        // 新版本替换旧版本
        SCLogWarning("Signature with newer revision...");
    }

    // 3. 处理双向规则（<>）
    if (sig->init_data->init_flags & SIG_FLAG_INIT_BIDIREC) {
        sig->next->next = de_ctx->sig_list;
    } else {
        sig->next = de_ctx->sig_list;
    }

    // 4. 头插法加入 sig_list
    de_ctx->sig_list = sig;
    return sig;
}
```

双向规则（`<>`）会被克隆为两条规则，源/目地址互换，都加入链表。

### 6.4 SigParse：两遍解析

`SigParse()` 在 `src/detect-parse.c:1862-1913` 中定义。`SigInitHelper` 会调用 `SigParse()` **两次**：

```c
// src/detect-parse.c:2865-3012（SigInitHelper 关键流程）
static Signature *SigInitHelper(DetectEngineCtx *de_ctx,
                                const char *sigstr, ...)
{
    Signature *sig = SigAlloc();
    sig->sig_str = SCStrdup(sigstr);
    sig->gid = 1;  // 默认 gid

    // 第一遍：仅扫描 requires 关键字
    int ret = SigParse(de_ctx, sig, sigstr, dir, &parser, true);
    if (ret == -4)  // requires 不满足
        goto error;

    // 检查 SID 是否存在
    if (sig->id == 0) {
        SCLogError("Signature missing required value \"sid\".");
        goto error;
    }

    // 第二遍：完整解析所有关键字
    ret = SigParse(de_ctx, sig, sigstr, dir, &parser, false);

    // 设置默认优先级
    if (sig->prio == -1)
        sig->prio = DETECT_DEFAULT_PRIO;  // 默认 3

    // 如果是应用层规则但未指定协议，自动配置
    if (sig->alproto != ALPROTO_UNKNOWN)
        AppLayerProtoDetectSupportedIpprotos(sig->alproto,
                                             sig->proto.proto);

    // 构建地址匹配数组
    SigBuildAddressMatchArray(sig);

    // 选择预过滤关键字
    SigSetupPrefilter(de_ctx, sig);

    // 验证与分类
    SigValidateConsolidate(de_ctx, sig, &parser, dir);

    return sig;
}
```

第一遍解析（`requires=true`）的目的是快速检查规则的 `requires` 关键字——如果当前引擎版本或功能不满足要求，直接跳过该规则而不报错。

### 6.5 SigParseBasics：解析规则头部

`SigParseBasics()` 在 `src/detect-parse.c:1738-1828` 中定义，用词法分析的方式将规则头部拆分为各个字段：

```c
// src/detect-parse.c:1740-1828（简化）
static int SigParseBasics(DetectEngineCtx *de_ctx, Signature *s,
                          const char *sigstr, SignatureParser *parser, ...)
{
    // 按空格/括号拆分头部字段
    SigParseToken(&index, parser->action, ...);     // "alert"
    SigParseList(&index, parser->protocol, ...);    // "http"
    SigParseList(&index, parser->src, ...);         // "$HOME_NET"
    SigParseList(&index, parser->sp, ...);          // "any"
    SigParseToken(&index, parser->direction, ...);  // "->"
    SigParseList(&index, parser->dst, ...);         // "$EXTERNAL_NET"
    SigParseList(&index, parser->dp, ...);          // "any"
    // 剩余部分作为 options

    // 解析 Action（alert/drop/pass/reject）
    SigParseAction(s, parser->action);

    // 解析 Protocol（可能包含 hook，如 "dns:request_complete"）
    SigParseProto(s, parser->protocol);

    // 解析方向
    if (strcmp(parser->direction, "<>") == 0)
        s->init_data->init_flags |= SIG_FLAG_INIT_BIDIREC;
    else if (strcmp(parser->direction, "=>") == 0)
        s->flags |= SIG_FLAG_TXBOTHDIR;

    // 解析地址和端口
    SigParseAddress(de_ctx, s, parser->src, SIG_DIREC_SRC);
    SigParseAddress(de_ctx, s, parser->dst, SIG_DIREC_DST);
    SigParsePort(de_ctx, s, parser->sp, SIG_DIREC_SRC);
    SigParsePort(de_ctx, s, parser->dp, SIG_DIREC_DST);
}
```

Protocol 字段支持新的 hook 语法（如 `dns:request_complete`），这是 Suricata 8.x 防火墙规则的新特性。Hook 解析通过 `SigParseProtoHookApp()` 完成（`src/detect-parse.c:1316-1366`），将 `hook` 结构设置到 `init_data` 中。

### 6.6 SigParseOptions：关键字循环解析

规则选项部分（括号内的关键字列表）通过循环调用 `SigParseOptions()` 逐个解析。每次迭代：

1. 提取下一个关键字名称和值（以分号分隔）
2. 在 `sigmatch_table[]` 中查找对应的注册项
3. 调用注册项的 `Setup()` 回调完成关键字特定的解析
4. 将结果作为 `SigMatch` 节点添加到签名的相应列表中

例如，`content` 关键字的 `Setup` 回调会解析内容模式字符串，创建 `DetectContentData` 结构，并将其封装为 `SigMatch` 添加到 `DETECT_SM_LIST_PMATCH` 列表中。

---

## 7. 检测引擎上下文：DetectEngineCtx

`DetectEngineCtx` 是检测引擎的全局上下文，贯穿初始化和运行时，定义在 `src/detect.h:932-1131`。这是一个大型结构体，关键字段分组如下：

### 7.1 签名存储

```c
// src/detect.h:941-953
Signature *sig_list;         // 解析后的签名链表
uint32_t sig_cnt;            // 签名总数

Signature **sig_array;       // 按 iid 索引的签名数组
uint32_t sig_array_len;      // 数组长度
uint32_t signum;             // 下一个可用的 iid
```

`sig_list` 是解析阶段的链表，`sig_array` 是构建阶段生成的数组，后者支持 O(1) 按内部 ID 查找。

### 7.2 签名分组查找结构

```c
// src/detect.h:959
DetectEngineLookupFlow flow_gh[FLOW_STATES];  // 按方向索引
```

`DetectEngineLookupFlow` 结构（`src/detect.h:861-865`）是运行时查找签名分组的入口：

```c
typedef struct DetectEngineLookupFlow_ {
    DetectPort *tcp;               // TCP 端口树
    DetectPort *udp;               // UDP 端口树
    struct SigGroupHead_ *sgh[256]; // 按协议号索引的 SGH
} DetectEngineLookupFlow;
```

`flow_gh[0]` 对应 toclient 方向，`flow_gh[1]` 对应 toserver 方向。对于 TCP/UDP，通过目标端口查找到对应的 `SigGroupHead`；对于其他协议，通过协议号直接索引 `sgh[proto]`。

### 7.3 多模式匹配相关

```c
// src/detect.h:935-936, 996, 1004-1007
uint8_t mpm_matcher;                          // MPM 算法（AC/HS）
MpmCtxFactoryContainer *mpm_ctx_factory_container;

int32_t sgh_mpm_context_proto_tcp_packet;     // TCP 包 MPM 上下文
int32_t sgh_mpm_context_proto_udp_packet;     // UDP 包 MPM 上下文
int32_t sgh_mpm_context_proto_other_packet;   // 其他协议 MPM 上下文
int32_t sgh_mpm_context_stream;               // 流 MPM 上下文
```

### 7.4 IP-Only 与特殊分组

```c
// src/detect.h:970, 1017
DetectEngineIPOnlyCtx io_ctx;                 // IP-only 引擎上下文
struct SigGroupHead_ *decoder_event_sgh;      // 解码器事件签名分组
```

IP-only 引擎使用 Radix 树（`SCRadix4Tree`/`SCRadix6Tree`）存储仅包含地址条件的规则，跳过所有负载检测。

### 7.5 缓冲区与检测引擎注册

```c
// src/detect.h:1083-1093
DetectBufferMpmRegistry *app_mpms_list;       // 应用层 MPM 注册列表
DetectEngineAppInspectionEngine *app_inspect_engines; // 应用层检测引擎列表
DetectEnginePktInspectionEngine *pkt_inspect_engines; // 包检测引擎列表
DetectBufferMpmRegistry *pkt_mpms_list;       // 包 MPM 注册列表
DetectEngineFrameInspectionEngine *frame_inspect_engines; // 帧检测引擎列表
```

### 7.6 版本与重载

```c
// src/detect.h:1013, 1056-1058, 1064
uint32_t version;                             // 引擎版本，重载时递增
uint32_t ref_cnt;                             // 引用计数
struct DetectEngineCtx_ *next;                // master 列表中的链接
enum DetectEnginePrefilterSetting prefilter_setting; // 预过滤策略
```

预过滤策略 `prefilter_setting` 支持两种模式：

- `DETECT_PREFILTER_MPM`：仅使用多模式匹配（默认）
- `DETECT_PREFILTER_AUTO`：自动选择最佳预过滤关键字

---

## 8. 签名分组：SigGroupHead

`SigGroupHead`（简称 SGH）将共享相同匹配条件（如同一个目标端口范围）的签名分组在一起，是运行时检测的基本单元。定义在 `src/detect.h:1627-1646`：

```c
// src/detect.h:1627-1646
typedef struct SigGroupHead_ {
    uint16_t flags;

    uint16_t filestore_cnt;       // 包含 filestore 关键字的签名数

    uint32_t id;                  // 唯一 ID（用于索引 sgh_array）

    PrefilterEngine *pkt_engines;            // 包级预过滤引擎
    PrefilterEngine *payload_engines;        // 负载预过滤引擎
    PrefilterEngine *tx_engines;             // TX 级预过滤引擎
    PrefilterEngine *frame_engines;          // 帧级预过滤引擎
    PrefilterEngine *post_rule_match_engines; // 规则匹配后引擎

    SigGroupHeadInitData *init;   // 初始化数据（构建后释放）
} SigGroupHead;
```

SGH 最重要的成员是各级 `PrefilterEngine` 链表。每个预过滤引擎封装了一种快速筛选机制（通常是多模式匹配），能在全量签名匹配前快速缩小候选集。

SGH 的构建和使用：

```
初始化：           运行时查找：
                   Packet → Flow 方向 → 协议
                     ↓
TCP/UDP:           flow_gh[dir].tcp/udp → 端口匹配
                     → 找到对应的 SigGroupHead
                     ↓
其他协议:          flow_gh[dir].sgh[proto]
                     → 直接索引到 SigGroupHead
                     ↓
SGH 内部:          PrefilterEngine → 候选签名集
                     → 逐签名精确匹配
```

---

## 9. 签名分组构建：SigGroupBuild

`SigGroupBuild()` 是整个初始化阶段的核心，定义在 `src/detect-engine-build.c:2185-2254`。它将解析后的签名链表转换为高效的运行时数据结构：

```c
// src/detect-engine-build.c:2185-2254
int SigGroupBuild(DetectEngineCtx *de_ctx)
{
    // 0. 分配内部 ID
    de_ctx->signum = 0;
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next)
        s->iid = de_ctx->signum++;

    // 1. 确定快速模式（Fast Pattern）
    DetectSetFastPatternAndItsId(de_ctx);

    // 2. 初始化标准 MPM 工厂上下文
    SigInitStandardMpmFactoryContexts(de_ctx);

    // 3-6. 四阶段构建
    SigPrepareStage1(de_ctx);  // 预处理
    SigPrepareStage2(de_ctx);  // 分组
    SigPrepareStage3(de_ctx);  // 特殊分组
    SigPrepareStage4(de_ctx);  // 预过滤设置

    // 7. 准备 MPM
    DetectMpmPrepareBuiltinMpms(de_ctx);
    DetectMpmPrepareAppMpms(de_ctx);
    DetectMpmPreparePktMpms(de_ctx);
    DetectMpmPrepareFrameMpms(de_ctx);

    // 8. 将 SigMatch 链表转为 SigMatchData 数组
    SigMatchPrepare(de_ctx);

    return 0;
}
```

### 9.1 Stage 1：预处理

`SigPrepareStage1()` 在 `src/detect-engine-build.c:1714-1826` 中定义，对每条签名执行预处理：

```c
int SigPrepareStage1(DetectEngineCtx *de_ctx)
{
    // 分配按 iid 索引的签名数组
    de_ctx->sig_array = SCCalloc(de_ctx->sig_array_len,
                                 sizeof(Signature *));

    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        // 将签名存入数组
        de_ctx->sig_array[s->iid] = s;

        // 统计规则类型
        // SIG_TYPE_IPONLY / payload / applayer / deonly

        // 检测取反 MPM
        if (RuleMpmIsNegated(s))
            s->flags |= SIG_FLAG_MPM_NEG;

        // 创建快速排除掩码
        SignatureCreateMask(s);

        // 传播 dsize 限制到 content 关键字
        DetectContentPropagateLimits(s);
        SigParseApplyDsizeToContent(s);

        // 评分（用于后续排序）
        RuleSetScore(s);

        de_ctx->sig_cnt++;
    }
}
```

`SignatureCreateMask()` 遍历签名的所有关键字，根据使用的关键字类型设置掩码位。例如使用了 `flowbits` 就设置 `SIG_MASK_REQUIRE_FLOW`，使用了 `content` 就设置 `SIG_MASK_REQUIRE_PAYLOAD`。

### 9.2 Stage 2：签名分组

`SigPrepareStage2()` 在 `src/detect-engine-build.c:1868-1902` 中定义，是分组的核心：

```c
int SigPrepareStage2(DetectEngineCtx *de_ctx)
{
    // 初始化 IP-Only 引擎
    IPOnlyInit(de_ctx, &de_ctx->io_ctx);

    // 按目标端口将 TCP/UDP 规则分组
    de_ctx->flow_gh[1].tcp = RulesGroupByPorts(
        de_ctx, IPPROTO_TCP, SIG_FLAG_TOSERVER);
    de_ctx->flow_gh[0].tcp = RulesGroupByPorts(
        de_ctx, IPPROTO_TCP, SIG_FLAG_TOCLIENT);
    de_ctx->flow_gh[1].udp = RulesGroupByPorts(
        de_ctx, IPPROTO_UDP, SIG_FLAG_TOSERVER);
    de_ctx->flow_gh[0].udp = RulesGroupByPorts(
        de_ctx, IPPROTO_UDP, SIG_FLAG_TOCLIENT);

    // 其他协议按协议号分组
    RulesGroupByIPProto(de_ctx);

    // 分配特殊类型的签名
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        if (s->type == SIG_TYPE_IPONLY) {
            IPOnlyAddSignature(de_ctx, &de_ctx->io_ctx, s);
        } else if (s->type == SIG_TYPE_DEONLY) {
            DetectEngineAddDecoderEventSig(de_ctx, s);
        } else if (/* pre_stream hook */) {
            DetectEngineAddSigToPreStreamHook(de_ctx, s);
        } else if (/* pre_flow hook */) {
            DetectEngineAddSigToPreFlowHook(de_ctx, s);
        }
    }

    IPOnlyPrepare(de_ctx);  // 构建 Radix 树
}
```

`RulesGroupByPorts()` 是分组的核心算法。对于 TCP/UDP，它将规则按**目标端口**范围分组，相同端口范围的规则共享一个 `SigGroupHead`。这是一个树形结构：

```
flow_gh[toserver].tcp
  ├── Port 80    → SigGroupHead { sig1, sig2, sig5 }
  ├── Port 443   → SigGroupHead { sig3, sig6 }
  ├── Port 25    → SigGroupHead { sig4 }
  └── Port any   → SigGroupHead { sig7, sig8 }
```

### 9.3 Stage 3：特殊分组

`SigPrepareStage3()` 在 `src/detect-engine-build.c:1944-1956` 中定义，处理三种特殊的签名分组：

```c
int SigPrepareStage3(DetectEngineCtx *de_ctx)
{
    // 解码器事件签名分组
    DetectEngineBuildDecoderEventSgh(de_ctx);

    // pre_flow 钩子签名分组
    DetectEngineBuildPreFlowHookSghs(de_ctx);

    // pre_stream 钩子签名分组
    DetectEngineBuildPreStreamHookSghs(de_ctx);
}
```

这些特殊分组用于在正常检测流程之外的检查点执行签名匹配。

### 9.4 Stage 4：预过滤引擎设置

`SigPrepareStage4()` 在 `src/detect-engine-build.c:2041-2100` 中定义，为每个 `SigGroupHead` 设置预过滤引擎：

```c
int SigPrepareStage4(DetectEngineCtx *de_ctx)
{
    for (uint32_t idx = 0; idx < de_ctx->sgh_array_cnt; idx++) {
        SigGroupHead *sgh = de_ctx->sgh_array[idx];
        if (sgh == NULL) continue;

        // 设置 filestore 信息
        SigGroupHeadSetupFiles(de_ctx, sgh);

        // 为 SGH 设置预过滤引擎
        PrefilterSetupRuleGroup(de_ctx, sgh);

        sgh->id = idx;
    }

    // 也为 decoder_event_sgh 设置预过滤
    if (de_ctx->decoder_event_sgh != NULL)
        PrefilterSetupRuleGroup(de_ctx, de_ctx->decoder_event_sgh);

    // 释放 SGH 的初始化数据
    for (uint32_t idx = 0; idx < de_ctx->sgh_array_cnt; idx++) {
        SigGroupHead *sgh = de_ctx->sgh_array[idx];
        if (sgh == NULL) continue;
        SigGroupHeadInitDataFree(sgh->init);
        sgh->init = NULL;
    }

    SigGroupHeadHashFree(de_ctx);
}
```

`PrefilterSetupRuleGroup()` 为每个 SGH 构建多种预过滤引擎：

- **MPM 引擎**：将 SGH 中所有签名的快速模式（Fast Pattern）注册到多模式匹配器
- **非 MPM 预过滤引擎**：对于不含 content 的签名，如果关键字实现了 `SupportsPrefilter`/`SetupPrefilter`，则注册为独立的预过滤引擎

### 9.5 SigMatchPrepare：最终准备

`SigMatchPrepare()` 在 `src/detect-engine-build.c:2110-2174` 中定义，执行最终的转换：

```c
static int SigMatchPrepare(DetectEngineCtx *de_ctx)
{
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        // 1. 设置应用层检测引擎
        DetectEngineAppInspectionEngine2Signature(de_ctx, s);

        // 2. 将 SigMatch 链表转为 SigMatchData 数组
        for (int type = 0; type < DETECT_SM_LIST_MAX; type++) {
            SigMatch *sm = s->init_data->smlists[type];
            s->sm_arrays[type] = SigMatchList2DataArray(sm);
        }

        // 3. 设置包检测引擎
        DetectEnginePktInspectionSetup(s);

        // 4. 释放 SigMatch 链表（ctx 已转移到 sm_arrays）
        for (uint32_t i = 0; i < DETECT_SM_LIST_MAX; i++) {
            SigMatch *sm = s->init_data->smlists[i];
            while (sm != NULL) {
                SigMatch *nsm = sm->next;
                SigMatchFree(de_ctx, sm);
                sm = nsm;
            }
        }

        // 5. 释放动态缓冲区中的 SigMatch 链表
        for (uint32_t x = 0; x < s->init_data->buffer_index; x++) {
            SigMatch *sm = s->init_data->buffers[x].head;
            // ... 释放链表
        }

        // 6. 释放 init_data
        SCFree(s->init_data);
        s->init_data = NULL;
    }
}
```

至此，签名从初始化阶段的"丰富但占内存"的形态，转变为运行时的"精简且高效"的形态。

---

## 10. 检测引擎初始化全景

将上述流程串联成完整的初始化时序：

```
main()
  └── SigLoadSignatures(de_ctx)
        ├── [1] 加载规则文件
        │     ├── ProcessSigFiles("local.rules")
        │     │     └── 逐行读取规则
        │     │           └── DetectEngineAppendSig(de_ctx, rule_str)
        │     │                 └── SigInit()
        │     │                       └── SigInitHelper()
        │     │                             ├── SigParse(requires=true)  ← 第一遍
        │     │                             ├── SigParse(requires=false) ← 第二遍
        │     │                             │     ├── SigParseBasics()
        │     │                             │     │     ├── SigParseAction()
        │     │                             │     │     ├── SigParseProto()
        │     │                             │     │     ├── SigParseAddress()
        │     │                             │     │     └── SigParsePort()
        │     │                             │     └── SigParseOptions() × N
        │     │                             │           └── sigmatch_table[kw].Setup()
        │     │                             ├── SigSetupPrefilter()
        │     │                             └── SigValidateConsolidate()
        │     │                                   ├── SignatureSetType()
        │     │                                   └── DetectRuleSetTable()
        │     └── ProcessSigFiles("et/open.rules")
        │           └── ...
        │
        ├── [2] SCSigOrderSignatures()    ← 排序
        │
        ├── [3] SCThresholdConfInitContext()
        │
        └── [4] SigGroupBuild()
              ├── DetectSetFastPatternAndItsId()
              ├── SigPrepareStage1()       ← 预处理
              │     ├── 构建 sig_array
              │     ├── SignatureCreateMask()
              │     └── RuleSetScore()
              ├── SigPrepareStage2()       ← 分组
              │     ├── RulesGroupByPorts() × 4  (TCP/UDP × to_s/to_c)
              │     ├── RulesGroupByIPProto()
              │     ├── IPOnlyAddSignature()
              │     └── IPOnlyPrepare()    ← 构建 Radix 树
              ├── SigPrepareStage3()       ← 特殊分组
              │     ├── DecoderEvent SGH
              │     ├── PreFlow hook SGH
              │     └── PreStream hook SGH
              ├── SigPrepareStage4()       ← 预过滤
              │     ├── PrefilterSetupRuleGroup() × N
              │     └── 释放 SGH init data
              ├── DetectMpmPrepare*()      ← MPM 编译
              └── SigMatchPrepare()        ← 最终转换
                    ├── DetectEngineAppInspectionEngine2Signature()
                    ├── SigMatchList2DataArray()
                    ├── DetectEnginePktInspectionSetup()
                    └── 释放 init_data
```

---

## 11. 检测引擎的检测引擎（Inspection Engine）

每条签名可以关联多个**检测引擎**，分为三种类型：

### 11.1 应用层检测引擎

`DetectEngineAppInspectionEngine` 定义在 `src/detect.h:416-442`，用于检查应用层 TX 的特定缓冲区：

```c
typedef struct DetectEngineAppInspectionEngine_ {
    AppProto alproto;              // 关联协议
    uint8_t dir;                   // 方向
    int16_t sm_list;               // 匹配列表 ID
    int16_t sm_list_base;          // 基础列表 ID（转换前）
    uint32_t id;                   // 引擎 ID
    bool mpm;                      // 是否有 MPM
    bool stream;                   // 是否检查流

    struct {
        InspectEngineFuncPtr Callback;           // 检测回调
        InspectionBufferGetDataPtr GetData;       // 数据获取回调
        const DetectEngineTransforms *transforms; // 转换操作
    } v2;

    SigMatchData *smd;             // 运行时匹配数据
    struct DetectEngineAppInspectionEngine_ *next;
} DetectEngineAppInspectionEngine;
```

例如，一条包含 `http.uri; content:"/evil";` 的规则会关联一个 `alproto=ALPROTO_HTTP1`、`sm_list=http.uri 的列表 ID` 的应用层检测引擎。运行时，引擎通过 `GetData` 回调从 TX 中提取 URI 缓冲区，然后用 `smd` 中的匹配数据（content 模式等）执行匹配。

### 11.2 包检测引擎

`DetectEnginePktInspectionEngine` 定义在 `src/detect.h:483-495`，用于检查包级别的缓冲区（如 `pkt_data`、`dns.response`）：

```c
typedef struct DetectEnginePktInspectionEngine {
    SigMatchData *smd;
    bool mpm;
    uint16_t sm_list;
    uint16_t sm_list_base;
    struct {
        InspectionBufferGetPktDataPtr GetData;
        InspectionBufferPktInspectFunc Callback;
        const DetectEngineTransforms *transforms;
    } v1;
    struct DetectEnginePktInspectionEngine *next;
} DetectEnginePktInspectionEngine;
```

### 11.3 帧检测引擎

`DetectEngineFrameInspectionEngine` 定义在 `src/detect.h:508-522`，用于检查协议帧数据：

```c
typedef struct DetectEngineFrameInspectionEngine {
    AppProto alproto;
    uint8_t dir;
    uint8_t type;             // 帧类型
    bool mpm;
    uint16_t sm_list;
    uint16_t sm_list_base;
    struct {
        InspectionBufferFrameInspectFunc Callback;
        const DetectEngineTransforms *transforms;
    } v1;
    SigMatchData *smd;
    struct DetectEngineFrameInspectionEngine *next;
} DetectEngineFrameInspectionEngine;
```

检测引擎在 `SigMatchPrepare()` 中由 `DetectEngineAppInspectionEngine2Signature()` 从全局注册表复制到每条签名上。

---

## 12. 引擎重载

Suricata 支持在运行时重载规则而不中断流量处理。重载通过 `DetectEngineReload()` 实现（`src/detect-engine.c:4788`），核心机制是：

1. 创建新的 `DetectEngineCtx`
2. 加载新的规则文件，完成所有初始化
3. 将新 `de_ctx` 注册到 `DetectEngineMasterCtx` 的活跃列表
4. 通知所有工作线程切换到新的 `de_ctx`
5. 等待旧 `de_ctx` 的引用计数降为 0 后释放

`DetectEngineMasterCtx`（`src/detect.h:1701-1726`）维护了活跃引擎列表和空闲列表：

```c
typedef struct DetectEngineMasterCtx_ {
    SCMutex lock;
    int multi_tenant_enabled;
    uint32_t version;                        // 每次 apply 递增
    DetectEngineCtx *list;                   // 活跃引擎列表
    DetectEngineCtx *free_list;              // 待释放列表
    enum DetectEngineTenantSelectors tenant_selector;
    DetectEngineTenantMapping *tenant_mapping_list;
} DetectEngineMasterCtx;
```

`version` 字段确保线程能感知到引擎更新并切换。

---

## 13. 本篇小结

本篇深入剖析了检测引擎的"静态"构建过程：

| 主题 | 核心要点 |
|------|---------|
| 关键字注册 | `sigmatch_table[]` 全局数组，每个关键字有 Setup/Match/Free 回调 |
| 签名结构 | `Signature` 包含 flags、type、alproto、mask、action、地址/端口、检测引擎链 |
| 匹配元素 | `SigMatch`（初始化用链表）→ `SigMatchData`（运行时用数组） |
| 签名分类 | 10 种 `SignatureType`：IPONLY、PDONLY、DEONLY、PKT、STREAM、APP_TX 等 |
| 规则解析 | 两遍解析：requires 扫描 → 完整解析（头部 + 选项循环） |
| 分组构建 | 四阶段：预处理 → 端口/协议分组 → 特殊分组 → 预过滤设置 |
| 运行时转换 | `SigMatchPrepare` 释放 init_data，生成紧凑的运行时结构 |

下一篇将聚焦检测引擎的"动态"部分：多模式匹配算法如何工作、预过滤引擎如何筛选候选签名、逐签名匹配的执行流程，以及告警的生成与处理。

---

## 源码索引

| 文件 | 关键内容 | 行号 |
|------|---------|------|
| `src/detect.h` | `SigMatch_` 结构 | 356-362 |
| `src/detect.h` | `SigMatchData_` 结构 | 365-369 |
| `src/detect.h` | `DetectEngineAppInspectionEngine` | 416-442 |
| `src/detect.h` | `DetectEnginePktInspectionEngine` | 483-495 |
| `src/detect.h` | `DetectEngineFrameInspectionEngine` | 508-522 |
| `src/detect.h` | `SignatureInitData_` | 589-665 |
| `src/detect.h` | `Signature_` 结构 | 668-751 |
| `src/detect.h` | `DetectEngineCtx_` | 932-1131 |
| `src/detect.h` | `SigGroupHead_` | 1627-1646 |
| `src/detect.h` | `SigTableElmt_`（sigmatch_table 元素） | 1417-1464 |
| `src/detect.h` | `SIG_FLAG_*` 标志定义 | 241-306 |
| `src/detect.h` | `DetectSigmatchListEnum` | 115-139 |
| `src/detect.h` | `SignatureType` 枚举 | 64-80 |
| `src/detect.h` | `SIGMATCH_*` 关键字标志 | 1648-1682 |
| `src/detect-engine-register.h` | `DetectKeywordId` 枚举 | 27-340+ |
| `src/detect-parse.c` | `SigParseBasics()` | 1738-1828 |
| `src/detect-parse.c` | `SigParse()` | 1862-1913 |
| `src/detect-parse.c` | `SigInitHelper()` | 2865-3012 |
| `src/detect-parse.c` | `SigSetupPrefilter()` | 2390-2456 |
| `src/detect-parse.c` | `SigValidateConsolidate()` | 2808-2859 |
| `src/detect-parse.c` | `DetectEngineAppendSig()` | 3439-3489 |
| `src/detect-engine-build.c` | `SignatureCreateMask()` | 440-530+ |
| `src/detect-engine-build.c` | `SignatureSetType()` | 1636-1704 |
| `src/detect-engine-build.c` | `SigPrepareStage1()` | 1714-1826 |
| `src/detect-engine-build.c` | `SigPrepareStage2()` | 1868-1902 |
| `src/detect-engine-build.c` | `SigPrepareStage3()` | 1944-1956 |
| `src/detect-engine-build.c` | `SigPrepareStage4()` | 2041-2100 |
| `src/detect-engine-build.c` | `SigMatchPrepare()` | 2110-2174 |
| `src/detect-engine-build.c` | `SigGroupBuild()` | 2185-2254 |
| `src/detect-engine-loader.c` | `SigLoadSignatures()` | 372-517 |
| `src/detect-engine.c` | `DetectEngineCtxInit()` | 2603 |
| `src/detect-engine.c` | `DetectEngineReload()` | 4788 |
