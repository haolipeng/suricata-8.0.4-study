# 14 - 检测引擎（下）：多模式匹配与检测执行

> **导读**：上一篇剖析了检测引擎的"静态"部分——规则如何解析为 `Signature` 结构、如何通过四阶段构建形成签名分组。本篇聚焦"动态"部分：每个数据包到达后，检测引擎如何高效地从数万条规则中找到匹配的那几条。核心机制包括多模式匹配（MPM）框架、预过滤引擎执行、逐签名精确匹配和告警生成流水线。

---

## 1. 检测执行总览

### 1.1 入口函数链

每个数据包经过解码、流处理和应用层解析后，进入检测引擎的入口函数 `Detect()`（`src/detect.c:2337-2401`）：

```c
// src/detect.c:2337-2401
TmEcode Detect(ThreadVars *tv, Packet *p, void *data)
{
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;
    DetectEngineCtx *de_ctx = NULL;

    // 多租户支持：根据 tenant_id 选择对应的检测引擎上下文
    if (det_ctx->mt_det_ctxs_cnt > 0 && det_ctx->TenantGetId != NULL) {
        uint32_t tenant_id = det_ctx->TenantGetId(det_ctx, p);
        det_ctx = GetTenantById(det_ctx->mt_det_ctxs_hash, tenant_id);
        de_ctx = det_ctx->de_ctx;
    } else {
        de_ctx = det_ctx->de_ctx;
    }

    // 分流：有流 vs 无流
    if (p->flow) {
        DetectFlow(tv, de_ctx, det_ctx, p);
    } else {
        DetectNoFlow(tv, de_ctx, det_ctx, p);
    }
    return TM_ECODE_OK;
}
```

`DetectFlow()` 和 `DetectNoFlow()` 做一些前置检查（如 flow drop、pass 策略等），最终都调用核心函数 `DetectRun()`。

### 1.2 DetectRun：核心执行流程

`DetectRun()` 是整个检测引擎的指挥中心（`src/detect.c:110-207`），按顺序执行六个阶段：

```
DetectRun()
    ① DetectRunSetup()           ← 初始化检测上下文
    ② DetectRunInspectIPOnly()   ← IP-only 签名检测
    ③ DetectRunGetRuleGroup()    ← 查找签名分组（SGH）
    ④ DetectRunPrefilterPkt()    ← 运行预过滤引擎
    ⑤ DetectRulePacketRules()    ← 逐签名匹配（包级别）
    ⑥ DetectRunTx()              ← 逐签名匹配（事务级别）
    ⑦ DetectRunPostRules()       ← 告警最终化
    ⑧ DetectRunCleanup()         ← 清理
```

核心代码：

```c
// src/detect.c:110-207（简化）
static void DetectRun(ThreadVars *th_v,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        Packet *p)
{
    Flow * const pflow = p->flow;

    // ① 初始化：获取 alproto、flow_flags、重置计数器
    DetectRunScratchpad scratch = DetectRunSetup(de_ctx, det_ctx, p, pflow, ACTION_DROP);

    // ② IP-only 签名检测（仅流的首包执行）
    DetectRunInspectIPOnly(th_v, de_ctx, det_ctx, pflow, p);

    // ③ 查找当前包对应的签名分组
    DetectRunGetRuleGroup(de_ctx, p, pflow, &scratch);
    if (scratch.sgh == NULL)
        goto end;

    // ④ 运行包/负载预过滤引擎
    DetectRunPrefilterPkt(th_v, de_ctx, det_ctx, p, &scratch);

    // ⑤ 逐签名匹配（包级别规则）
    const uint8_t pkt_policy = DetectRulePacketRules(th_v, de_ctx, det_ctx, p, pflow, &scratch);
    if (pkt_policy & (ACTION_DROP | ACTION_ACCEPT))
        goto end;

    // ⑥ 事务级别检测
    if (pflow && pflow->alstate && likely(pflow->proto == p->proto)) {
        DetectRunFrames(th_v, de_ctx, det_ctx, p, pflow, &scratch);
        DetectRunTx(th_v, de_ctx, det_ctx, p, pflow, &scratch);
        AppLayerParserSetTransactionInspectId(...);
    }

end:
    // ⑦ 告警最终化
    DetectRunPostRules(th_v, de_ctx, det_ctx, p, pflow, &scratch);
    // ⑧ 清理
    DetectRunCleanup(det_ctx, p, pflow);
}
```

---

## 2. 多模式匹配（MPM）框架

MPM 是检测引擎的性能基石。它能在一次扫描中同时搜索数千个模式字符串，避免逐条规则暴力匹配。

### 2.1 MPM 算法注册表：mpm_table

Suricata 通过全局数组 `mpm_table[]` 管理不同的 MPM 算法实现。每个算法注册一组函数指针：

```c
// src/util-mpm.h:150-185
typedef struct MpmTableElmt_ {
    const char *name;                    // 算法名称

    void (*InitCtx)(MpmCtx *);           // 初始化上下文
    void (*DestroyCtx)(MpmCtx *);        // 销毁上下文

    MpmConfig *(*ConfigInit)(void);      // 配置初始化（缓存等）
    void (*ConfigCacheDirSet)(MpmConfig *, const char *);

    // 添加模式
    int (*AddPattern)(MpmCtx *, uint8_t *, uint16_t,  // 区分大小写
                      uint16_t, uint16_t, uint32_t, SigIntId, uint8_t);
    int (*AddPatternNocase)(MpmCtx *, const uint8_t *, uint16_t,  // 不区分大小写
                            uint16_t, uint16_t, uint32_t, SigIntId, uint8_t);

    int (*Prepare)(MpmConfig *, MpmCtx *);    // 编译状态机
    int (*CacheRuleset)(MpmConfig *);         // 缓存到磁盘

    // 搜索：返回匹配的模式数量
    uint32_t (*Search)(const MpmCtx *, MpmThreadCtx *,
                       PrefilterRuleStore *, const uint8_t *, uint32_t);

    uint8_t feature_flags;               // 支持的特性标志
} MpmTableElmt;

extern MpmTableElmt mpm_table[MPM_TABLE_SIZE];
```

### 2.2 内置算法

Suricata 8.x 支持三种 MPM 算法（`src/util-mpm.h:32-41`）：

```c
enum {
    MPM_NOTSET = 0,
    MPM_AC,       // Aho-Corasick（标准实现）
    MPM_AC_KS,    // Aho-Corasick Kernel-Space 优化版
    MPM_HS,       // Intel Hyperscan
    MPM_TABLE_SIZE,
};
```

| 算法 | 实现文件 | 特点 | 默认 |
|------|---------|------|------|
| **AC** | `util-mpm-ac.c` | 标准 Aho-Corasick，支持 offset/depth | 无 Hyperscan 时默认 |
| **AC-KS** | `util-mpm-ac-ks.c` | 针对 Tile 架构优化的 AC | 平台特定 |
| **Hyperscan** | `util-mpm-hs.c` | Intel 正则引擎，SIMD 加速 | 有 SSSE3 时默认 |

算法选择在 `MpmTableSetup()` 中完成（`src/util-mpm.c:219-239`），默认优先 Hyperscan（如果编译并且 CPU 支持 SSSE3），否则回退到 AC。

### 2.3 MpmCtx：模式集合上下文

每个签名分组的每种缓冲区类型都有一个 `MpmCtx`，存储该组的所有 MPM 模式和编译后的状态机：

```c
// src/util-mpm.h:93-114
typedef struct MpmCtx_ {
    void *ctx;              // 算法私有上下文（SCACCtx / SCHSCtx）
    uint8_t mpm_type;       // 算法类型
    uint8_t flags;          // 标志（GLOBAL / NODEPTH / CACHE_TO_DISK）
    uint16_t maxdepth;      // 最大 depth
    uint32_t pattern_cnt;   // 模式数量
    uint16_t minlen;        // 最短模式长度
    uint16_t maxlen;        // 最长模式长度
    uint32_t memory_cnt;    // 内存分配次数
    uint32_t memory_size;   // 总内存大小
    uint32_t max_pat_id;    // 最大模式 ID
    MpmPattern **init_hash; // 初始化哈希表（去重用）
} MpmCtx;
```

### 2.4 MpmPattern：单个模式

```c
// src/util-mpm.h:54-80
typedef struct MpmPattern_ {
    uint16_t len;           // 模式长度
    uint8_t flags;          // 标志
    uint16_t offset;        // 偏移约束
    uint16_t depth;         // 深度约束
    uint8_t *original_pat;  // 原始模式
    uint8_t *cs;            // 区分大小写版本
    uint8_t *ci;            // 不区分大小写版本
    uint32_t id;            // 模式 ID
    uint32_t sids_size;     // 关联的签名数量
    SigIntId *sids;         // 关联的签名 ID 数组
    struct MpmPattern_ *next;
} MpmPattern;
```

关键：一个模式可以关联多个签名（`sids` 数组）。当 MPM 搜索匹配到一个模式时，所有关联的签名 ID 都会被添加到预过滤结果中。

### 2.5 Aho-Corasick 搜索流程

AC 搜索（`src/util-mpm-ac.c` `SCACSearch()`）的核心逻辑：

```
                    输入缓冲区
                    ↓
    ┌─────────── 状态机遍历 ──────────┐
    │  for each byte in buffer:       │
    │    state = delta_table[state][c] │
    │    if state has OUTPUT:          │
    │      for each pattern at state:  │
    │        check offset/depth        │
    │        check case-sensitivity    │
    │        PrefilterAddSids(pmq, sids)│
    └─────────────────────────────────┘
                    ↓
              PrefilterRuleStore
```

搜索通过状态转移表在 O(n) 时间内完成（n 为输入长度），与模式数量无关——这就是多模式匹配的核心优势。

---

## 3. 快速模式选择（Fast Pattern）

每条包含 `content` 关键字的规则，需要选择一个"最佳"模式作为 MPM 的代表。这个选择直接影响检测性能。

### 3.1 选择策略

快速模式选择在 `RetrieveFPForSig()` 中完成（`src/detect-engine-mpm.c:1140-1364`），策略如下：

```
RetrieveFPForSig() 快速模式选择策略：

    ① 用户显式指定 fast_pattern → 直接使用
    ② 按缓冲区优先级收集候选模式
       - 优先选择非取反（non-negated）模式
       - 优先选择 toserver 方向的缓冲区
    ③ 在候选中选择"最长"的模式
    ④ 如果长度相同，使用 PatternStrength() 评分选择
```

### 3.2 模式强度评分

`PatternStrength()` 对模式内容进行评分（`src/detect-engine-mpm.c:984-1007`）：

| 字节类型 | 首次出现得分 | 重复得分 |
|---------|------------|---------|
| 字母字符（a-z, A-Z） | 3 | 1 |
| 可打印字符 + null/0x01/0xFF | 4 | 1 |
| 其他字节（二进制数据） | 6 | 1 |

设计理念：二进制字节更独特、更少出现，得分更高；重复字符贡献递减。例如模式 `\x00\x01\x02\x03` 比 `AAAA` 评分高得多。

### 3.3 快速模式 ID 分配

选定快速模式后，`DetectSetFastPatternAndItsId()` 为所有签名的快速模式分配全局唯一 ID（`src/detect-engine-mpm.c:2506-2557`），相同内容和列表的模式共享同一 ID，减少 MPM 状态机的模式总数。

---

## 4. 签名分组查找

### 4.1 SigMatchSignaturesGetSgh

检测引擎需要为当前数据包找到对应的签名分组（SGH）。查找逻辑在 `SigMatchSignaturesGetSgh()` 中（`src/detect.c:282-327`）：

```c
// src/detect.c:282-327（简化）
const SigGroupHead *SigMatchSignaturesGetSgh(const DetectEngineCtx *de_ctx,
        const Packet *p)
{
    SigGroupHead *sgh = NULL;

    // 解码器事件包
    if (p->proto == 0 && p->events.cnt > 0)
        return de_ctx->decoder_event_sgh;

    // 根据方向选择查找表
    const int dir = (p->flowflags & FLOW_PKT_TOCLIENT) == 0;  // 1=toserver, 0=toclient

    int proto = PacketGetIPProto(p);
    if (proto == IPPROTO_TCP) {
        // TCP: 用目标端口在端口树中查找
        DetectPort *list = de_ctx->flow_gh[dir].tcp;
        uint16_t port = dir ? p->dp : p->sp;
        DetectPort *sghport = DetectPortLookupGroup(list, port);
        if (sghport != NULL)
            sgh = sghport->sh;
    } else if (proto == IPPROTO_UDP) {
        // UDP: 同 TCP
        DetectPort *list = de_ctx->flow_gh[dir].udp;
        uint16_t port = dir ? p->dp : p->sp;
        DetectPort *sghport = DetectPortLookupGroup(list, port);
        if (sghport != NULL)
            sgh = sghport->sh;
    } else {
        // 其他协议: 按协议号直接索引
        sgh = de_ctx->flow_gh[dir].sgh[proto];
    }
    return sgh;
}
```

查找路径为 `flow_gh[方向]` → 按协议查找 → 按端口查找端口树 → 返回 SGH。

### 4.2 流级别 SGH 缓存

首次查找的结果会缓存到流中（`pflow->sgh_toserver`/`pflow->sgh_toclient`），同一流的后续包直接使用缓存，避免重复查找（`src/detect.c:431-481`）：

```c
// src/detect.c:438-471
if (pflow) {
    // 优先使用流缓存的 SGH
    if (PacketGetIPProto(p) == pflow->proto) {
        if ((p->flowflags & FLOW_PKT_TOSERVER) && (pflow->flags & FLOW_SGH_TOSERVER)) {
            sgh = pflow->sgh_toserver;
            use_flow_sgh = true;
        } else if ((p->flowflags & FLOW_PKT_TOCLIENT) && (pflow->flags & FLOW_SGH_TOCLIENT)) {
            sgh = pflow->sgh_toclient;
            use_flow_sgh = true;
        }
    }
    // 未命中缓存则查找并存入流
    if (!use_flow_sgh) {
        sgh = SigMatchSignaturesGetSgh(de_ctx, p);
        DetectRunPostGetFirstRuleGroup(p, pflow, sgh);
    }
}
```

---

## 5. 预过滤执行

### 5.1 PrefilterRuleStore（PMQ）

预过滤结果存储在 `PrefilterRuleStore` 结构中（`src/util-prefilter.h:34-44`）：

```c
typedef struct PrefilterRuleStore_ {
    SigIntId *rule_id_array;      // 匹配的签名内部 ID 数组
    uint32_t rule_id_array_cnt;   // 当前数量
    uint32_t rule_id_array_size;  // 分配容量
} PrefilterRuleStore;
```

每个检测线程上下文（`det_ctx->pmq`）持有一个 PMQ 实例。预过滤引擎通过 `PrefilterAddSids()` 向其中添加候选签名 ID。

### 5.2 包级别预过滤

`DetectRunPrefilterPkt()` 完成包级别的预过滤（`src/detect.c:592-610`）：

```c
// src/detect.c:592-610
static inline void DetectRunPrefilterPkt(...)
{
    // 1. 为当前包生成签名掩码
    PacketCreateMask(p, &p->sig_mask, scratch->alproto, scratch->app_decoder_events);

    // 2. 运行预过滤引擎
    Prefilter(det_ctx, scratch->sgh, p, scratch->flow_flags, p->sig_mask);

    // 3. 将预过滤结果去重并拷贝到 match_array
    if (det_ctx->pmq.rule_id_array_cnt) {
        DetectPrefilterCopyDeDup(de_ctx, det_ctx);
    }
}
```

### 5.3 Prefilter() 引擎调度

`Prefilter()` 函数是预过滤引擎的调度中心（`src/detect-engine-prefilter.c:216-280`），按类型运行两类引擎：

```c
// src/detect-engine-prefilter.c:216-280（简化）
void Prefilter(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh,
        Packet *p, const uint8_t flags, const SignatureMask mask)
{
    // 第一类：包级别引擎（如 TCP flags 预过滤）
    if (sgh->pkt_engines) {
        PrefilterEngine *engine = sgh->pkt_engines;
        do {
            // 检查掩码兼容性
            if ((engine->ctx.pkt.mask & mask) == engine->ctx.pkt.mask) {
                engine->cb.Prefilter(det_ctx, p, engine->pectx);
            }
            if (engine->is_last) break;
            engine++;
        } while (1);
    }

    // 第二类：负载引擎（MPM 搜索）
    if (sgh->payload_engines &&
        (p->payload_len || (p->flags & PKT_DETECT_HAS_STREAMDATA)) &&
        !(p->flags & PKT_NOPAYLOAD_INSPECTION))
    {
        PrefilterEngine *engine = sgh->payload_engines;
        while (1) {
            engine->cb.Prefilter(det_ctx, p, engine->pectx);
            if (engine->is_last) break;
            engine++;
        }
    }

    // 排序结果
    if (det_ctx->pmq.rule_id_array_cnt > 1) {
        QuickSortSigIntId(det_ctx->pmq.rule_id_array,
                          det_ctx->pmq.rule_id_array_cnt);
    }
}
```

掩码检查是第一层过滤：如果包的签名掩码不包含引擎所需的位（如"需要负载"但包没有负载），则跳过该引擎。

### 5.4 事务预过滤

事务级别的预过滤在 `DetectRunPrefilterTx()` 中执行（`src/detect-engine-prefilter.c:95-185`）。与包预过滤的关键区别是**进度追踪**：

```c
// src/detect-engine-prefilter.c:110-176（核心逻辑）
PrefilterEngine *engine = sgh->tx_engines;
do {
    // 获取对应协议的事务指针
    void *tx_ptr = DetectGetInnerTx(tx->tx_ptr, alproto, engine->alproto, flow_flags);
    if (tx_ptr == NULL)
        goto next;

    // 进度检查：引擎需要事务达到特定状态
    if (engine->ctx.tx_min_progress > tx->tx_progress)
        break;  // 事务状态不够，后续引擎也不会满足

    // 避免重复执行：如果检测进度已超过引擎要求
    if (tx->detect_progress > engine->ctx.tx_min_progress)
        goto next;  // 已经跑过了

    // 执行预过滤回调
    engine->cb.PrefilterTx(det_ctx, engine->pectx, p, p->flow,
                           tx_ptr, tx->tx_id, tx->tx_data_ptr, flow_flags);

    // 更新检测进度
    if (tx->tx_progress > engine->ctx.tx_min_progress &&
        engine->is_last_for_progress) {
        tx->detect_progress = engine->ctx.tx_min_progress + 1;
    }

next:
    if (engine->is_last) break;
    engine++;
} while (1);
```

进度追踪机制确保同一事务在同一进度状态下不会重复运行预过滤引擎——当事务的应用层状态没有前进时，之前的预过滤结果仍然有效。

### 5.5 结果去重与候选列表构建

预过滤完成后，`DetectPrefilterCopyDeDup()` 将 PMQ 中的签名 ID 转换为 `Signature` 指针数组，同时去重（`src/detect.c:329-351`）：

```c
// src/detect.c:329-351
static inline void DetectPrefilterCopyDeDup(
        const DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    SigIntId *pf_ptr = det_ctx->pmq.rule_id_array;
    uint32_t final_cnt = det_ctx->pmq.rule_id_array_cnt;
    Signature **match_array = det_ctx->match_array;
    SigIntId previous_id = (SigIntId)-1;

    while (final_cnt-- > 0) {
        SigIntId id = *pf_ptr++;
        Signature *s = de_ctx->sig_array[id];
        // 由于数组已排序，相邻重复可以直接跳过
        if (likely(id != previous_id)) {
            *match_array++ = s;
            previous_id = id;
        }
    }
    det_ctx->match_array_cnt = (uint32_t)(match_array - det_ctx->match_array);
    PMQ_RESET(&det_ctx->pmq);
}
```

去重利用了排序后相邻重复的特性——简单的线性去重，O(n) 完成。结果存入 `det_ctx->match_array`，供后续逐签名检测使用。

---

## 6. 包级别签名检测

### 6.1 DetectRulePacketRules 主循环

包级别签名检测在 `DetectRulePacketRules()` 中完成（`src/detect.c:653-911`）。这是检测引擎中最核心的循环：

```c
// src/detect.c:653-911（关键路径简化）
static inline uint8_t DetectRulePacketRules(...)
{
    SigIntId match_cnt = det_ctx->match_array_cnt;
    Signature **match_array = det_ctx->match_array;

    while (match_cnt--) {
        const Signature *s = *match_array++;

        // ① 跳过 app_inspect 签名（留给 DetectRunTx 处理）
        if (s->app_inspect != NULL)
            goto next;

        // ② 掩码快速排除
        if ((s->mask & p->sig_mask) != s->mask)
            goto next;

        // ③ dsize 预过滤
        if (SigDsizePrefilter(p, s, sflags))
            goto next;

        // ④ 应用层协议匹配
        if (sflags & SIG_FLAG_APPLAYER) {
            if (s->alproto != ALPROTO_UNKNOWN &&
                !AppProtoEquals(s->alproto, scratch->alproto))
                goto next;
        }

        // ⑤ 规则头部检查（协议、端口、地址）
        if (!DetectRunInspectRuleHeader(p, pflow, s, sflags, s_proto_flags))
            goto next;

        // ⑥ 包检测引擎（content 匹配等）
        if (!DetectEnginePktInspectionRun(tv, det_ctx, s, pflow, p, &alert_flags))
            goto next;

        // ⑦ 匹配成功！运行后匹配动作
        DetectRunPostMatch(tv, det_ctx, p, s);

        // ⑧ 入队告警
        AlertQueueAppend(det_ctx, s, p, txid, alert_flags);

    next:
        DetectVarProcessList(det_ctx, pflow, p);
    }
    return action;
}
```

每条签名经过层层过滤：

| 层级 | 过滤机制 | 成本 | 排除率 |
|------|---------|------|--------|
| ① | 类型分流 | O(1) | 高（app 签名直接跳过） |
| ② | 掩码比对 | O(1) | 中（位运算） |
| ③ | dsize 比对 | O(1) | 低-中 |
| ④ | alproto 比对 | O(1) | 高 |
| ⑤ | 头部检查 | O(n) | 中（地址/端口匹配） |
| ⑥ | 内容匹配 | O(n) | 最终精确匹配 |

### 6.2 规则头部检查

`DetectRunInspectRuleHeader()` 检查签名的非内容条件（`src/detect.c:508-587`）：

```c
// src/detect.c:508-587（简化）
static inline bool DetectRunInspectRuleHeader(const Packet *p, const Flow *f,
        const Signature *s, ...)
{
    // 检查 flowvar 需求
    if ((sflags & SIG_FLAG_REQUIRE_FLOWVAR) && f->flowvar == NULL)
        return false;

    // 检查 IP 版本
    if ((s_proto_flags & DETECT_PROTO_IPV4) && !PacketIsIPv4(p))
        return false;

    // 检查 IP 协议
    if (DetectProtoContainsProto(&s->proto, PacketGetIPProto(p)) == 0)
        return false;

    // 检查端口
    if (!(sflags & SIG_FLAG_DP_ANY)) {
        if (DetectPortLookupGroup(s->dp, p->dp) == NULL)
            return false;
    }
    if (!(sflags & SIG_FLAG_SP_ANY)) {
        if (DetectPortLookupGroup(s->sp, p->sp) == NULL)
            return false;
    }

    // 检查目标/源地址
    if (!(sflags & SIG_FLAG_DST_ANY)) {
        if (PacketIsIPv4(p)) {
            if (DetectAddressMatchIPv4(s->addr_dst_match4,
                    s->addr_dst_match4_cnt, &p->dst) == 0)
                return false;
        }
    }
    return true;
}
```

### 6.3 包检测引擎执行

`DetectEnginePktInspectionRun()` 遍历签名的包检测引擎链（`src/detect-engine.c:1813-1830`）：

```c
// src/detect-engine.c:1813-1830
bool DetectEnginePktInspectionRun(ThreadVars *tv,
        DetectEngineThreadCtx *det_ctx, const Signature *s,
        Flow *f, Packet *p, uint8_t *alert_flags)
{
    for (DetectEnginePktInspectionEngine *e = s->pkt_inspect; e != NULL; e = e->next) {
        if (e->v1.Callback(det_ctx, e, s, p, alert_flags) !=
                DETECT_ENGINE_INSPECT_SIG_MATCH) {
            return false;  // 任一引擎不匹配即失败
        }
    }
    return true;  // 所有引擎都匹配
}
```

包检测引擎链中典型的回调包括：

- **MATCH 列表检测**：检查 `sm_arrays[DETECT_SM_LIST_MATCH]` 中的关键字（如 `flow`、`flags`、`ttl`）
- **PMATCH 列表检测**：检查 `sm_arrays[DETECT_SM_LIST_PMATCH]` 中的内容匹配（`content`、`pcre` 等）
- **流匹配**：检查流重组数据中的内容

---

## 7. 事务级别签名检测

### 7.1 DetectRunTx 事务遍历

`DetectRunTx()` 遍历流中的所有待检测事务（`src/detect.c:1702-1901`）：

```c
// src/detect.c:1702-1901（核心流程简化）
static void DetectRunTx(...)
{
    const uint64_t total_txs = AppLayerParserGetTxCnt(f, alstate);
    uint64_t tx_id_min = AppLayerParserGetTransactionInspectId(f->alparser, flow_flags);

    while (1) {
        // 获取下一个待检测事务
        AppLayerGetTxIterTuple ires = IterFunc(ipproto, alproto, alstate,
                                               tx_id_min, total_txs, &state);
        if (ires.tx_ptr == NULL)
            break;

        DetectTransaction tx = GetDetectTx(...);
        det_ctx->tx_id = tx.tx_id;

        // 构建候选列表（三个来源合并）

        // 来源 1：事务预过滤结果
        if (sgh->tx_engines) {
            DetectRunPrefilterTx(det_ctx, sgh, p, ...);
            for (uint32_t i = 0; i < det_ctx->pmq.rule_id_array_cnt; i++) {
                const Signature *s = de_ctx->sig_array[det_ctx->pmq.rule_id_array[i]];
                det_ctx->tx_candidates[array_idx].s = s;
                array_idx++;
            }
        }

        // 来源 2：包级别预过滤中带 app_inspect 的签名
        RuleMatchCandidateMergeStateRules(det_ctx, &array_idx);

        // 来源 3：持续检测状态（de_state）
        if (tx.de_state != NULL) {
            // 从 DeStateStore 链表中恢复之前部分匹配的签名
            for (/* each stored item */) {
                det_ctx->tx_candidates[array_idx].s = de_ctx->sig_array[item->sid];
                det_ctx->tx_candidates[array_idx].flags = &item->flags;
                array_idx++;
            }
        }

        // 排序合并后的候选列表
        if (do_sort) {
            qsort(det_ctx->tx_candidates, array_idx, sizeof(RuleMatchCandidateTx),
                  DetectRunTxSortHelper);
        }

        // 逐签名检测
        for (uint32_t i = 0; i < array_idx; i++) {
            const Signature *s = det_ctx->tx_candidates[i].s;
            // ... 去重、检查、调用 DetectRunTxInspectRule()
        }
    }
}
```

### 7.2 DetectRunTxInspectRule 单条签名检测

`DetectRunTxInspectRule()` 是事务签名检测的核心（`src/detect.c:1166-1365`），它遍历签名的应用层检测引擎链：

```c
// src/detect.c:1166-1365（关键逻辑简化）
static bool DetectRunTxInspectRule(...)
{
    // 首次检测：先运行包头部检查和包检测引擎
    if (stored_flags == NULL) {
        if (!DetectRunInspectRuleHeader(p, f, s, ...))
            return false;
        if (!DetectEnginePktInspectionRun(tv, det_ctx, s, f, p, NULL))
            return false;
    }

    // 遍历应用层检测引擎链
    const DetectEngineAppInspectionEngine *engine = s->app_inspect;
    do {
        // 检查方向和进度
        if (!(inspect_flags & BIT_U32(engine->id)) &&
                direction == engine->dir) {

            // 进度检查：事务状态必须达到引擎要求
            if (tx->tx_progress < engine->progress)
                break;

            // 执行检测回调
            uint8_t match = engine->v2.Callback(
                    de_ctx, det_ctx, engine, s, f, engine_flags,
                    alstate, tx_ptr, tx->tx_id);

            if (match == DETECT_ENGINE_INSPECT_SIG_MATCH) {
                inspect_flags |= BIT_U32(engine->id);
                total_matches++;
            } else if (match == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH) {
                inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                break;
            }
            // NO_MATCH: 中断，等待下次尝试
        }
        engine = engine->next;
    } while (engine != NULL);

    // 所有引擎都匹配 → 签名匹配成功
    if (engine == NULL && total_matches) {
        inspect_flags |= DE_STATE_FLAG_FULL_INSPECT;
        return true;
    }
    return false;
}
```

应用层检测引擎返回值有四种：

| 返回值 | 含义 | 处理 |
|--------|------|------|
| `SIG_MATCH` | 匹配成功 | 标记该引擎完成，继续下一个 |
| `SIG_NO_MATCH` | 暂时不匹配 | 中断，保存状态等下次 |
| `SIG_CANT_MATCH` | 永远不会匹配 | 标记永久失败，不再尝试 |
| `SIG_MATCH_MORE_FILES` | 匹配但还有更多文件 | 继续但不标记完成 |

**持续检测（Stateful Detection）**的关键：当事务的应用层状态不够时（如 HTTP 请求头还没解析完），签名检测会中断，`inspect_flags` 被保存到 `DeStateStore` 中。当事务状态推进后，下次检测从中断点继续，避免重复检测已匹配的引擎。

---

## 8. 告警生成流水线

### 8.1 告警入队

当签名匹配成功后，通过 `AlertQueueAppend()` 将告警加入线程级别的告警队列（`src/detect-engine-alert.c:368-391`）：

```c
// src/detect-engine-alert.c:368-391
void AlertQueueAppend(DetectEngineThreadCtx *det_ctx, const Signature *s,
        Packet *p, uint64_t tx_id, uint8_t alert_flags)
{
    // 首次遇到 drop 动作，立即记录到 packet
    if (p->alerts.drop.action == 0 && s->action & ACTION_DROP) {
        p->alerts.drop = PacketAlertSet(det_ctx, s, tx_id, alert_flags);
    }

    // 入队
    uint16_t pos = det_ctx->alert_queue_size;
    if (pos == det_ctx->alert_queue_capacity) {
        if (pos == AlertQueueExpand(det_ctx)) {
            p->alerts.discarded++;
            return;
        }
    }
    det_ctx->alert_queue[pos] = PacketAlertSet(det_ctx, s, tx_id, alert_flags);
    det_ctx->alert_queue_size++;
}
```

告警先进入临时队列（`det_ctx->alert_queue`），而非直接写入包。这允许后续的排序和阈值处理。

### 8.2 告警最终化

`PacketAlertFinalize()` 在所有检测完成后执行（`src/detect-engine-alert.c:593-615`），由 `DetectRunPostRules()` 调用：

```c
// src/detect-engine-alert.c:593-615
void PacketAlertFinalize(const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Packet *p)
{
    if (det_ctx->alert_queue_size > 0) {
        PacketAlertFinalizeProcessQueue(de_ctx, det_ctx, p);
    }
    // 处理 tag 关键字
    if (!(p->flags & PKT_PSEUDO_STREAM_END))
        TagHandlePacket(de_ctx, det_ctx, p);
    // 设置流告警标志
    if (p->flow != NULL && p->alerts.cnt > 0) {
        FlowSetHasAlertsFlag(p->flow);
    }
}
```

### 8.3 告警处理队列

`PacketAlertFinalizeProcessQueue()` 完成告警的最终处理（`src/detect-engine-alert.c:472-582`）：

```
PacketAlertFinalizeProcessQueue() 处理流程：

    ① 按优先级排序告警队列
    ② 逐条处理：
       a. PacketAlertHandle() — 阈值检查（threshold/rate_filter）
       b. 如果通过阈值 → 执行 TMATCH 列表（tag 关键字）
       c. FlowApplySignatureActions() — 设置流级别动作
       d. PacketApplySignatureActions() — 设置包级别动作
       e. 拷贝到 p->alerts.alerts[] 数组
    ③ 遇到 pass 规则 → 后续告警被跳过
    ④ 遇到 drop 规则 → 标记已丢弃
```

**pass 规则的优先级**：排序后 pass 规则排在最前面。一旦 pass 规则匹配，后续的 alert/drop 规则都会被跳过——这是 Suricata "pass 优先"策略的实现。

---

## 9. 后匹配预过滤（Post-Rule Match）

Suricata 8.x 引入了一种特殊的预过滤机制——**后匹配预过滤**，用于处理 `flowbits:set` 等动态依赖。

当一条规则包含 `flowbits:set,foo` 并匹配成功后，依赖 `flowbits:isset,foo` 的其他规则需要被加入检测列表。这通过 `PrefilterPostRuleMatch()` 实现（`src/detect-engine-prefilter.c:193-214`）：

```c
// src/detect-engine-prefilter.c:193-214
void PrefilterPostRuleMatch(DetectEngineThreadCtx *det_ctx,
        const SigGroupHead *sgh, Packet *p, Flow *f)
{
    if (sgh->post_rule_match_engines) {
        PrefilterEngine *engine = sgh->post_rule_match_engines;
        do {
            engine->cb.PrefilterPostRule(det_ctx, engine->pectx, p, f);
            if (engine->is_last) break;
            engine++;
        } while (1);
    }
}
```

在 `DetectRulePacketRules()` 的主循环中，每次签名匹配后都会检查是否有后匹配工作（`src/detect.c:787-840`）：

```c
if (det_ctx->post_rule_work_queue.len > 0) {
    PrefilterPostRuleMatch(det_ctx, scratch->sgh, p, pflow);
    if (det_ctx->pmq.rule_id_array_cnt > 0) {
        // 将新发现的规则合并到当前检测循环中
        // 排序、去重后继续检测
    }
}
```

这意味着检测循环是**动态扩展**的——规则匹配可以触发更多规则被加入检测。

---

## 10. 防火墙模式特殊处理

Suricata 8.x 引入了防火墙模式（`EngineModeIsFirewall()`），检测引擎有专门的处理逻辑：

```
防火墙模式检测流程：
    ① 防火墙规则优先执行
    ② accept:hook → 跳过剩余防火墙规则，继续 TD 规则
    ③ accept:packet → 立即接受，跳过所有后续检测
    ④ accept:flow → 立即接受，后续包也跳过
    ⑤ drop → 立即丢弃
    ⑥ 无规则匹配 → 执行默认丢弃策略
```

关键代码在 `DetectRulePacketRules()` 中（`src/detect.c:852-884`）：

```c
if (s->flags & SIG_FLAG_FIREWALL) {
    if (s->action & ACTION_ACCEPT) {
        fw_verdict = true;
        if (s->action_scope == ACTION_SCOPE_HOOK) {
            skip_fw = true;  // 跳过剩余 FW 规则
        } else if (s->action_scope == ACTION_SCOPE_PACKET) {
            action |= s->action;
            break;  // 立即退出
        } else if (s->action_scope == ACTION_SCOPE_FLOW) {
            action |= s->action;
            pflow->flags |= FLOW_ACTION_ACCEPT;
            break;
        }
    } else if (s->action & ACTION_DROP) {
        fw_verdict = true;
        action |= s->action;
        break;
    }
}
```

如果遍历完所有防火墙规则都没有明确的 accept/drop，会执行默认策略（通常是 drop）。

---

## 11. 检测执行全景图

```
                        数据包到达
                            │
                    ┌───────┴───────┐
                    │   Detect()    │
                    │  多租户选择    │
                    └───────┬───────┘
                            │
                    ┌───────┴───────┐
                    │ DetectRun()   │
                    └───────┬───────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
   ① IP-Only          ② SGH 查找          ③ 预过滤
   IPOnlyMatch     GetRuleGroup()       Prefilter()
   (Radix 树)      (端口树查找)         ├── pkt_engines
        │               │              ├── payload_engines (MPM)
        │               │              └── → PMQ 排序去重
        │               │                      │
        │          ┌────┴────┐           ┌─────┴─────┐
        │          │  SGH    │           │match_array │
        │          │(签名分组)│           │(候选签名)   │
        │          └────┬────┘           └─────┬─────┘
        │               │                     │
        │          ┌────┴─────────────────────┴────┐
        │          │  ④ DetectRulePacketRules()      │
        │          │  逐签名检测（包级别）              │
        │          │  mask → dsize → alproto →       │
        │          │  header → PktInspection →       │
        │          │  AlertQueueAppend()              │
        │          └──────────────┬─────────────────┘
        │                        │
        │          ┌─────────────┴─────────────┐
        │          │  ⑤ DetectRunTx()           │
        │          │  遍历事务：                  │
        │          │  PrefilterTx → 合并候选 →   │
        │          │  TxInspectRule → Alert      │
        │          └─────────────┬─────────────┘
        │                        │
        │          ┌─────────────┴─────────────┐
        │          │  ⑥ DetectRunPostRules()    │
        │          │  PacketAlertFinalize()     │
        │          │  排序 → 阈值 → 动作应用     │
        │          └───────────────────────────┘
```

---

## 12. 性能关键点

### 12.1 预过滤的排除效果

典型场景下，预过滤能排除 95%+ 的签名：

- **MPM 排除**：数万条规则中，通常只有少量模式匹配流量内容
- **掩码排除**：无负载的 SYN 包直接排除所有需要负载的签名
- **dsize 排除**：小于签名最小 dsize 要求的包被排除
- **alproto 排除**：HTTP 签名不会应用于 DNS 流量

### 12.2 缓存友好设计

- `SigMatchData` 使用紧凑数组而非链表，提高缓存命中率
- `PrefilterEngine` 数组使用 `CLS`（cache line size）对齐分配
- SGH 在流中缓存，避免重复查找

### 12.3 状态保持与增量检测

事务级别的持续检测（`de_state`/`inspect_flags`）避免了在事务状态未变化时重复检测——这对长连接（如 HTTP/2、WebSocket）尤为重要。

---

## 13. 小结与源码索引

本篇和上篇共同覆盖了 Suricata 检测引擎的完整生命周期：初始化阶段将规则文本编译为高效的运行时数据结构，运行时阶段通过多层过滤和精确匹配实现高性能检测。

下一篇将聚焦输出框架——匹配成功的告警如何被格式化为 EVE JSON 并输出到日志文件。

### 关键源码索引

| 文件 | 关键内容 | 行号 |
|------|---------|------|
| `src/detect.c` | `Detect()` 入口函数 | 2337-2401 |
| `src/detect.c` | `DetectRun()` 核心流程 | 110-207 |
| `src/detect.c` | `DetectRunGetRuleGroup()` SGH 查找 | 431-481 |
| `src/detect.c` | `SigMatchSignaturesGetSgh()` 端口树查找 | 282-327 |
| `src/detect.c` | `DetectRunPrefilterPkt()` 包预过滤调度 | 592-610 |
| `src/detect.c` | `DetectPrefilterCopyDeDup()` 结果去重 | 329-351 |
| `src/detect.c` | `DetectRulePacketRules()` 包级签名检测循环 | 653-911 |
| `src/detect.c` | `DetectRunInspectRuleHeader()` 规则头检查 | 508-587 |
| `src/detect.c` | `DetectRunTx()` 事务级检测 | 1702-1901 |
| `src/detect.c` | `DetectRunTxInspectRule()` 单条事务签名检测 | 1166-1365 |
| `src/detect.c` | `DetectRunPostMatch()` 后匹配动作 | 252-271 |
| `src/detect.c` | `DetectRunPostRules()` 告警最终化调度 | 1019-1049 |
| `src/detect-engine-prefilter.c` | `Prefilter()` 预过滤引擎调度 | 216-280 |
| `src/detect-engine-prefilter.c` | `DetectRunPrefilterTx()` 事务预过滤 | 95-185 |
| `src/detect-engine-prefilter.c` | `PrefilterPostRuleMatch()` 后匹配预过滤 | 193-214 |
| `src/detect-engine.c` | `DetectEnginePktInspectionRun()` 包检测引擎 | 1813-1830 |
| `src/detect-engine-alert.c` | `AlertQueueAppend()` 告警入队 | 368-391 |
| `src/detect-engine-alert.c` | `PacketAlertFinalize()` 告警最终化 | 593-615 |
| `src/detect-engine-alert.c` | `PacketAlertFinalizeProcessQueue()` 队列处理 | 472-582 |
| `src/util-mpm.h` | `MpmTableElmt` MPM 算法注册表 | 150-185 |
| `src/util-mpm.h` | `MpmCtx` 模式集合上下文 | 93-114 |
| `src/util-mpm.h` | `MpmPattern` 单个模式结构 | 54-80 |
| `src/util-mpm.h` | MPM 算法枚举（AC/AC-KS/HS） | 32-41 |
| `src/util-prefilter.h` | `PrefilterRuleStore` 预过滤结果存储 | 34-44 |
| `src/util-mpm-ac.c` | `SCACSearch()` AC 搜索实现 | 854-973 |
| `src/detect-engine-mpm.c` | `RetrieveFPForSig()` 快速模式选择 | 1140-1364 |
| `src/detect-engine-mpm.c` | `GetMpmForList()` 按强度选择模式 | 1081-1116 |
| `src/detect-engine-mpm.c` | `PatternStrength()` 模式强度评分 | 984-1007 |
| `src/detect-engine-mpm.c` | `DetectSetFastPatternAndItsId()` 模式 ID 分配 | 2506-2557 |
| `src/detect-engine-mpm.c` | `MpmStoreSetup()` MPM 上下文构建 | 1625-1718 |
