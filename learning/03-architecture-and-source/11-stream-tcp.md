# 11 - 流处理与 TCP 重组

> **导读**：上一篇剖析了解码层如何将原始帧逐层解析为结构化的 `Packet`。本篇深入 Suricata 的**流处理子系统**和 **TCP 重组引擎**，这是整个检测能力的基石——没有可靠的流跟踪和 TCP 重组，应用层协议检测和签名匹配就无从谈起。我们将跟踪一个 TCP 连接从 SYN 到 FIN 的完整生命周期，理解流哈希表、TCP 状态机、段重组算法和内存管理策略。

---

## 1. 流处理在流水线中的位置

回顾 FlowWorker 的处理流程（第 9 篇），流处理处于解码之后、检测之前：

```
[Decode] → FlowWorker {
    ① FlowHandlePacket()         ← 流查找/创建（本篇重点）
    ② FlowUpdate()               ← 更新流状态
    ③ StreamTcpPacket()           ← TCP 流处理（本篇重点）
    ④ AppLayerHandleUdp()         ← UDP 应用层
    ⑤ Detect()                    ← 规则检测
    ⑥ OutputLoggerLog()           ← 日志输出
}
```

流处理子系统的核心任务是：将**无状态的网络数据包**转化为**有状态的网络流**，为上层应用层解析和规则检测提供会话上下文。

---

## 2. Flow 结构体

`Flow` 是 Suricata 中第二重要的数据结构（仅次于 `Packet`），代表一条双向网络流，定义在 `src/flow.h:347-493`。

### 2.1 核心字段

```c
// src/flow.h:347-493（简化展示）
typedef struct Flow_ {
    /* ====== 流"头部"：初始化后只读，无需加锁 ====== */
    FlowAddress src, dst;              // 源/目的地址（128 位，兼容 IPv6）
    union {
        Port sp;                       // TCP/UDP 源端口
        struct { uint8_t type, code; } icmp_s;  // ICMP 类型/代码
        struct { uint32_t spi; } esp;  // ESP SPI
    };
    union {
        Port dp;                       // TCP/UDP 目的端口
        struct { uint8_t type, code; } icmp_d;
    };
    uint8_t proto;                     // 协议号（6=TCP, 17=UDP...）
    uint8_t recursion_level;           // 隧道嵌套层数
    uint16_t vlan_id[VLAN_MAX_LAYERS]; // VLAN ID（最多 3 层）

    /* ====== 链表与哈希 ====== */
    struct Flow_ *next;                // 哈希桶中的下一个 Flow
    uint32_t flow_hash;                // 原始哈希值（未取模）
    struct FlowBucket_ *fb;            // 所属哈希桶指针

    /* ====== 状态管理 ====== */
    FlowStateType flow_state;          // NEW / ESTABLISHED / CLOSED / BYPASSED
    uint32_t timeout_policy;           // 超时策略（秒）
    SCTime_t lastts;                   // 最后更新时间戳
    uint32_t flags;                    // 流标志位（32 位，全部用满）

    /* ====== 锁保护 ====== */
    SCMutex m;                         // 流级互斥锁（默认配置）

    /* ====== 协议上下文 ====== */
    void *protoctx;                    // 协议上下文（TCP: TcpSession *）
    AppProto alproto;                  // 检测到的应用层协议
    AppProto alproto_ts, alproto_tc;   // 各方向的应用层协议
    AppLayerParserState *alparser;     // 应用层解析器状态
    void *alstate;                     // 应用层状态数据

    /* ====== 检测引擎 ====== */
    const struct SigGroupHead_ *sgh_toserver;  // toserver 方向的规则组
    const struct SigGroupHead_ *sgh_toclient;  // toclient 方向的规则组
    uint32_t de_ctx_version;           // 检测引擎版本（用于热重载）

    /* ====== 统计 ====== */
    uint32_t todstpktcnt, tosrcpktcnt;
    uint64_t todstbytecnt, tosrcbytecnt;

    /* ====== 扩展存储 ====== */
    Storage storage[];                 // 柔性数组，动态扩展存储
} Flow;
```

### 2.2 设计要点

**头部只读**：五元组（`src/dst/sp/dp/proto`）在 `FlowInit()` 后不再改变。这意味着其他线程可以安全读取这些字段进行哈希查找，而不需要获取流锁。这是两级锁设计的基础。

**两级锁**：Suricata 对流使用两级锁：
- **桶锁**（`FlowBucket.m`）：保护哈希链表的遍历和修改
- **流锁**（`Flow.m`）：保护流的内部状态

桶锁在查找到目标流后即释放，只持有流锁进行后续处理。

**柔性数组存储**：`Storage storage[]` 允许通过 `FlowStorageRegister()` 在编译时动态扩展每个 Flow 的存储空间，用于存放第三方模块的数据（如 Lua 脚本状态）。

### 2.3 流状态机

```c
// src/flow.h:495-503
enum FlowState {
    FLOW_STATE_NEW = 0,             // 刚创建，只见过一个方向的包
    FLOW_STATE_ESTABLISHED,          // 双向都有包（TCP: 三次握手完成）
    FLOW_STATE_CLOSED,               // 已关闭（TCP: FIN/RST）
    FLOW_STATE_LOCAL_BYPASSED,       // 本地旁路（不再检测）
    FLOW_STATE_CAPTURE_BYPASSED,     // 硬件旁路（网卡层面跳过）
};
```

**超时策略**按协议和状态分别配置（`src/flow.h:510-515`）：

```c
typedef struct FlowProtoTimeout_ {
    uint32_t new_timeout;              // NEW 状态超时（默认 TCP: 30s）
    uint32_t est_timeout;              // ESTABLISHED 超时（默认 TCP: 3600s）
    uint32_t closed_timeout;           // CLOSED 超时（默认 TCP: 120s）
    uint32_t bypassed_timeout;         // BYPASSED 超时
} FlowProtoTimeout;
```

### 2.4 流标志位

32 个标志位全部使用，覆盖流的方方面面（`src/flow.h:50-123`）：

| 标志 | 含义 |
|------|------|
| `FLOW_TO_SRC_SEEN` / `FLOW_TO_DST_SEEN` | 是否见过该方向的包 |
| `FLOW_ACTION_DROP` | 流级别 DROP 动作 |
| `FLOW_ACTION_PASS` | 流级别 PASS 动作 |
| `FLOW_HAS_ALERTS` | 流上有告警 |
| `FLOW_SGH_TOSERVER/TOCLIENT` | 规则组已设置 |
| `FLOW_TS_PM_ALPROTO_DETECT_DONE` | 协议检测完成（多个方向×多种方法）|
| `FLOW_IPV4` / `FLOW_IPV6` | IP 版本 |
| `FLOW_CHANGE_PROTO` | 协议变更（STARTTLS 场景）|
| `FLOW_DIR_REVERSED` | 方向已反转（midstream 场景）|

---

## 3. 流哈希表

流哈希表是 Suricata 流管理的核心数据结构，定义在 `src/flow-hash.c`。

### 3.1 全局哈希桶数组

```c
// src/flow-hash.c:59
FlowBucket *flow_hash;   // 全局哈希桶数组
```

`FlowBucket` 结构（`src/flow-hash.h:43-62`）：

```c
typedef struct FlowBucket_ {
    Flow *head;                        // 活跃流链表头
    Flow *evicted;                     // 已驱逐流链表（等待 FlowManager 回收）
    SCMutex m;                         // 桶级互斥锁
    SC_ATOMIC_DECLARE(uint32_t, next_ts);  // 最早可能超时的时间戳
} __attribute__((aligned(CLS))) FlowBucket;
```

**缓存行对齐**：`__attribute__((aligned(CLS)))` 确保每个 `FlowBucket` 占据完整的缓存行（通常 64 字节），避免**伪共享**（false sharing）——多个线程修改相邻桶时不会互相污染缓存行。

**双链表设计**：每个桶有两个链表：`head`（活跃流）和 `evicted`（已超时但尚未清理的流）。`evicted` 链表由工作线程在查找时顺便维护，FlowManager 线程负责最终清理。

**next_ts 优化**：原子变量 `next_ts` 记录该桶中最早可能超时的时间。工作线程可以通过比较当前时间和 `next_ts` 快速跳过不需要超时检查的桶，显著减少锁竞争。

### 3.2 哈希计算：FlowGetHash()

哈希计算使用 Bob Jenkins 的 `hashword()` 算法（lookup3），输入是**规范化的五元组 + 附加字段**：

```c
// src/flow-hash.c:87-115
typedef struct FlowHashKey4_ {
    union {
        struct {
            uint32_t addrs[2];         // 源/目的 IP（规范化排序）
            uint16_t ports[2];         // 源/目的端口（规范化排序）
            uint8_t proto;             // 协议号
            uint8_t recur;             // 隧道递归层
            uint16_t livedev;          // 抓包设备 ID
            uint16_t vlan_id[3];       // VLAN ID
            uint16_t pad[1];           // 对齐填充
        };
        const uint32_t u32[6];         // 作为 uint32 数组传给 hashword()
    };
} FlowHashKey4;
```

**规范化**是关键设计：源 IP 和目的 IP 按大小排序，端口号同理。这确保正向包 `(A→B)` 和反向包 `(B→A)` 产生**相同的哈希值**，映射到同一个 Flow。

```c
// src/flow-hash.c:200-225
static inline uint32_t FlowGetHash(const Packet *p)
{
    // IPv4 + TCP/UDP 场景
    FlowHashKey4 fhk = { .pad[0] = 0 };

    // 规范化：较大的 IP 放在前面
    int ai = (p->src.addr_data32[0] > p->dst.addr_data32[0]);
    fhk.addrs[1-ai] = p->src.addr_data32[0];
    fhk.addrs[ai] = p->dst.addr_data32[0];

    // 规范化：较大的端口放在前面
    const int pi = (p->sp > p->dp);
    fhk.ports[1-pi] = p->sp;
    fhk.ports[pi] = p->dp;

    fhk.proto = p->proto;
    fhk.recur = p->recursion_level & g_recurlvl_mask;
    fhk.livedev = devid & g_livedev_mask;
    fhk.vlan_id[0] = p->vlan_id[0] & g_vlan_mask;
    fhk.vlan_id[1] = p->vlan_id[1] & g_vlan_mask;
    fhk.vlan_id[2] = p->vlan_id[2] & g_vlan_mask;

    hash = hashword(fhk.u32, ARRAY_SIZE(fhk.u32), flow_config.hash_rand);
    return hash;
}
```

**配置掩码**：`g_vlan_mask`、`g_recurlvl_mask`、`g_livedev_mask` 允许管理员通过配置禁用某些字段参与哈希计算。例如 `vlan.use-for-tracking: false` 会将 `g_vlan_mask` 设为 0，使不同 VLAN 的相同五元组映射到同一个 Flow。

**ICMP 特殊处理**：ICMP 不可达报文中嵌入了原始 IP 头，Suricata 从嵌入的头中提取五元组来计算哈希，从而将 ICMP 错误关联到原始流。

### 3.3 流查找与创建：FlowGetFlowFromHash()

这是整个流系统最关键的函数（`src/flow-hash.c:907-1014`），在**每个数据包**处理时调用。以下是简化后的核心逻辑：

```c
// src/flow-hash.c:907-1014
Flow *FlowGetFlowFromHash(ThreadVars *tv, FlowLookupStruct *fls,
                          Packet *p, Flow **dest)
{
    const uint32_t hash = p->flow_hash;
    FlowBucket *fb = &flow_hash[hash % flow_config.hash_size];  // 定位桶
    FBLOCK_LOCK(fb);                                              // 锁桶

    /* ===== 空桶：直接创建新流 ===== */
    if (fb->head == NULL) {
        Flow *f = FlowGetNew(tv, fls, p);      // 从 spare pool 获取 Flow
        fb->head = f;
        FlowInit(tv, f, p);                     // 初始化五元组、时间等
        f->flow_hash = hash;
        f->fb = fb;
        FlowUpdateState(f, FLOW_STATE_NEW);
        FlowReference(dest, f);
        FBLOCK_UNLOCK(fb);
        return f;                                // 返回时流锁已持有
    }

    /* ===== 非空桶：遍历链表查找 ===== */
    Flow *prev_f = NULL;
    Flow *f = fb->head;
    do {
        Flow *next_f = NULL;
        const bool our_flow = FlowCompare(f, p) != 0;

        if (our_flow || timeout_check) {
            FLOWLOCK_WRLOCK(f);                  // 获取流锁

            // 检查是否超时
            if (FlowIsTimedOut(...)) {
                MoveToWorkQueue(tv, fls, fb, f, prev_f);  // 超时→移到工作队列
                FLOWLOCK_UNLOCK(f);
                goto flow_removed;
            }

            if (our_flow) {
                // 检查 TCP 会话复用（SYN on CLOSED flow）
                if (TcpSessionPacketSsnReuse(p, f, f->protoctx)) {
                    // 创建新流替换旧流
                    Flow *new_f = TcpReuseReplace(...);
                    MoveToWorkQueue(..., f, ...);  // 旧流移到清理队列
                    f = new_f;
                }
                FlowReference(dest, f);
                FBLOCK_UNLOCK(fb);               // 释放桶锁
                return f;                         // 返回匹配流（流锁已持有）
            }
            FLOWLOCK_UNLOCK(f);
        }

        prev_f = f;
        next_f = f->next;

    flow_removed:
        if (next_f == NULL) {
            // 链表末尾未找到：创建新流，插入链表头部
            f = FlowGetNew(tv, fls, p);
            f->next = fb->head;
            fb->head = f;
            FlowInit(tv, f, p);
            f->flow_hash = hash;
            f->fb = fb;
            FlowUpdateState(f, FLOW_STATE_NEW);
            FlowReference(dest, f);
            FBLOCK_UNLOCK(fb);
            return f;
        }
        f = next_f;
    } while (f != NULL);
}
```

**设计亮点**：

1. **头插法**：新流插入链表头部（`f->next = fb->head; fb->head = f`），因为新流更可能被后续包命中
2. **顺便超时**：在遍历查找时顺便检查已超时的流并移出链表，利用了"你需要遍历反正都要看"的机会
3. **TCP 会话复用**：检测到 SYN 打到一个已关闭的 TCP 流时，自动创建新流替换旧流
4. **流锁持有返回**：函数返回时流锁已被持有，调用者负责在处理完毕后释放

### 3.4 流比较：CmpFlowPacket()

```c
// src/flow-hash.c:414-424
static inline bool CmpFlowPacket(const Flow *f, const Packet *p)
{
    return CmpAddrsAndPorts(f_src, f_dst, f->sp, f->dp,
                            p_src, p_dst, p->sp, p->dp) &&
           f->proto == p->proto &&
           (f->recursion_level == p->recursion_level || g_recurlvl_mask == 0) &&
           CmpVlanIds(f->vlan_id, p->vlan_id) &&
           (f->livedev == p->livedev || g_livedev_mask == 0);
}
```

`CmpAddrsAndPorts()` 同时比较正向和反向匹配（`src==src && dst==dst` 或 `src==dst && dst==src`），使正反向包都能命中同一个 Flow。

### 3.5 流表配置

```c
// src/flow.h:283-297
typedef struct FlowCnf_ {
    uint32_t hash_rand;           // 随机种子（启动时生成）
    uint32_t hash_size;           // 哈希表大小（桶数量）
    uint32_t prealloc;            // 预分配流数量
    uint32_t timeout_new;         // NEW 状态默认超时
    uint32_t timeout_est;         // ESTABLISHED 默认超时
    uint32_t emergency_recovery;  // 紧急模式恢复阈值
    enum ExceptionPolicy memcap_policy;  // 内存超限策略
    SC_ATOMIC_DECLARE(uint64_t, memcap); // 内存上限
} FlowConfig;
```

对应的 `suricata.yaml` 配置：

```yaml
flow:
  memcap: 128mb                # 流表内存上限
  hash-size: 65536             # 哈希桶数量（建议为 2 的幂）
  prealloc: 10000              # 预分配的 Flow 对象数
  emergency-recovery: 30       # 紧急模式恢复比例（%）
```

---

## 4. FlowManager：流超时管理

FlowManager 是一个后台管理线程（`src/flow-manager.c`），负责扫描流哈希表，清理超时的流。

### 4.1 超时判定

```c
// src/flow-manager.c:190-220
static bool FlowManagerFlowTimeout(Flow *f, SCTime_t ts,
                                   uint32_t *next_ts, const bool emerg)
{
    SCTime_t timesout_at;
    if (emerg) {
        // 紧急模式：使用缩短的超时值
        timesout_at = SCTIME_ADD_SECS(f->lastts,
            FlowGetFlowTimeoutDirect(flow_timeouts_emerg, f->flow_state, f->protomap));
    } else {
        // 正常模式：使用流的 timeout_policy
        timesout_at = SCTIME_ADD_SECS(f->lastts, f->timeout_policy);
    }

    // 更新下次超时时间（用于优化扫描）
    if (*next_ts == 0 || (uint32_t)SCTIME_SECS(timesout_at) < *next_ts)
        *next_ts = (uint32_t)SCTIME_SECS(timesout_at);

    // 在线模式：使用当前时间比较
    // 离线模式：使用"拥有"该流的线程的时间
    if (SCTIME_CMP_LT(ts, timesout_at))
        return false;  // 未超时
    return true;       // 已超时
}
```

**在线 vs 离线超时**：在线模式（实时抓包）使用系统时间，离线模式（PCAP 回放）使用数据包时间。离线模式下取"拥有"该流的工作线程最后处理的数据包时间，防止回放结束后所有流立即超时。

### 4.2 紧急模式

当流表内存使用量超过 `memcap` 时，Suricata 进入**紧急模式**（Emergency Mode）：

1. 超时值大幅缩短（使用 `flow_timeouts_emerg` 表）
2. 扫描速度加快
3. 新流创建时可能驱逐最旧的流（`FlowGetUsedFlow()`）

当内存使用量降回 `memcap × (1 - emergency_recovery/100)` 以下时，退出紧急模式。

### 4.3 FlowRecycler

FlowRecycler 是另一个管理线程，负责回收已完成清理的 Flow 对象：

- FlowManager 将超时流移到工作队列
- FlowWorker 在处理完最后一个伪包后将流移到回收队列
- FlowRecycler 从回收队列中取出 Flow，释放其应用层状态、TCP 会话等资源，然后将 Flow 对象归还到 spare pool

这种三级清理流程确保不会在持有关键锁时执行耗时的释放操作。

---

## 5. TCP 会话：TcpSession 与 TcpStream

TCP 流的协议上下文存储在 `TcpSession` 结构中，通过 `Flow.protoctx` 指针关联。

### 5.1 TcpSession 结构

```c
// src/stream-tcp-private.h:283-299
typedef struct TcpSession_ {
    PoolThreadId pool_id;           // 内存池线程 ID
    uint8_t state:4;                // 当前 TCP 状态（4 位，0-15）
    uint8_t pstate:4;               // 上一个状态（用于 RST 后恢复）
    uint8_t queue_len;              // SYN 队列长度
    int8_t data_first_seen_dir;     // 首次见到数据的方向
    uint8_t tcp_packet_flags;       // 累积的 TCP 标志位
    uint32_t flags;                 // 会话标志位
    uint32_t reassembly_depth;      // 重组深度限制
    TcpStream server;               // 服务端流（toclient 方向的数据）
    TcpStream client;               // 客户端流（toserver 方向的数据）
    TcpStateQueue *queue;           // SYN/SYN-ACK 候选队列
} TcpSession;
```

**关键设计**：
- `state` 和 `pstate` 各占 4 位，共享一个字节，节省空间
- `server` 存储的是**服务端发送的数据**（即 toclient 方向），`client` 存储**客户端发送的数据**（即 toserver 方向）
- `queue` 是 SYN/SYN-ACK 重传时的候选队列，用于处理 SYN 重传携带不同选项的情况

### 5.2 TcpStream 结构

```c
// src/stream-tcp-private.h:106-142
typedef struct TcpStream_ {
    uint16_t flags:12;              // 流方向标志（12 位）
    uint16_t wscale:4;              // 窗口缩放因子（0-14）
    uint8_t os_policy;              // 操作系统策略（用于重叠处理）
    uint8_t tcp_flags;              // 累积的 TCP 标志位

    uint32_t isn;                   // 初始序列号
    uint32_t next_seq;              // 期望的下一个序列号
    uint32_t last_ack;              // 最后确认的序列号
    uint32_t next_win;              // 窗口右边界（last_ack + window）
    uint32_t window;                // 当前窗口大小（应用 wscale 后）

    uint32_t last_ts;               // 最后的 TSVAL（时间戳选项）
    uint32_t last_pkt_ts;           // 最后包的系统时间（用于 PAWS）

    /* ====== 重组状态 ====== */
    uint32_t base_seq;              // 重组基准序列号
    uint32_t app_progress_rel;      // 应用层已消费的相对偏移
    uint32_t raw_progress_rel;      // 原始重组进度的相对偏移
    uint32_t log_progress_rel;      // 日志进度的相对偏移
    uint32_t min_inspect_depth;     // 应用层要求的最小检测深度
    uint32_t data_required;         // 再次调用应用层前需要的最小数据量

    StreamingBuffer sb;             // 流式缓冲区（存储重组后的数据）
    struct TCPSEG seg_tree;         // TCP 段的红黑树
    uint32_t segs_right_edge;       // 已见段的最右序列号

    uint32_t sack_size;             // SACK 范围的累积大小
    struct TCPSACK sack_tree;       // SACK 记录的红黑树
} TcpStream;
```

### 5.3 TcpSegment 结构

```c
// src/stream-tcp-private.h:72-79
typedef struct TcpSegment {
    PoolThreadId pool_id;           // 段所属的内存池线程
    uint16_t payload_len;           // 载荷长度
    uint32_t seq;                   // 起始序列号
    RB_ENTRY(TcpSegment) rb;        // 红黑树节点
    StreamingBufferSegment sbseg;   // 在 StreamingBuffer 中的位置
    TcpSegmentPcapHdrStorage *pcap_hdr_storage;  // 可选的 PCAP 头存储
} __attribute__((__packed__)) TcpSegment;
```

**红黑树排序**：段按序列号排序，相同序列号的段按长度排序（小到大）。红黑树保证了 O(log n) 的插入和查找性能，这对于大量乱序段的场景至关重要。

**段数据分离**：`TcpSegment` 本身不存储数据，数据存在 `TcpStream.sb`（`StreamingBuffer`）中。`sbseg` 记录了数据在 `StreamingBuffer` 中的偏移和长度。这种分离设计允许多个段共享一个连续的缓冲区，减少内存碎片。

### 5.4 序列号比较宏

TCP 序列号是 32 位无符号整数，会回绕。Suricata 使用经典的有符号比较技巧（来自 *TCP/IP Illustrated* Vol.2 Page 810）：

```c
// src/stream-tcp-private.h:256-262
#define SEQ_EQ(a,b)  ((int32_t)((a) - (b)) == 0)
#define SEQ_LT(a,b)  ((int32_t)((a) - (b)) <  0)
#define SEQ_LEQ(a,b) ((int32_t)((a) - (b)) <= 0)
#define SEQ_GT(a,b)  ((int32_t)((a) - (b)) >  0)
#define SEQ_GEQ(a,b) ((int32_t)((a) - (b)) >= 0)
```

通过将差值转为 `int32_t`，利用补码算术正确处理序列号回绕。例如：`SEQ_LT(0xFFFFFFFF, 0x00000001)` 结果为 `true`（差值 = -2，是负数）。

---

## 6. TCP 状态机

Suricata 实现了完整的 RFC 793 TCP 状态机，加上 midstream 和异步模式的扩展。

### 6.1 TCP 状态枚举

```c
// src/stream-tcp-private.h:150-163
enum TcpState {
    TCP_NONE = 0,           // 无会话
    TCP_SYN_SENT = 2,       // 已发送 SYN
    TCP_SYN_RECV = 3,       // 已收到 SYN（等待 ACK）
    TCP_ESTABLISHED = 4,    // 连接已建立
    TCP_FIN_WAIT1 = 5,      // 主动关闭方发送了 FIN
    TCP_FIN_WAIT2 = 6,      // 主动关闭方收到了 FIN 的 ACK
    TCP_TIME_WAIT = 7,      // 等待超时（2MSL）
    TCP_LAST_ACK = 8,       // 被动关闭方等待最后的 ACK
    TCP_CLOSE_WAIT = 9,     // 被动关闭方等待应用关闭
    TCP_CLOSING = 10,       // 双方同时关闭
    TCP_CLOSED = 11,        // 已关闭
};
```

### 6.2 入口函数：StreamTcpPacket()

`StreamTcpPacket()` 是 TCP 状态机的主入口（`src/stream-tcp.c:5669-5865`），每个 TCP 包都经过它处理：

```c
// src/stream-tcp.c:5669-5865（简化）
int StreamTcpPacket(ThreadVars *tv, Packet *p, StreamTcpThread *stt,
                    PacketQueueNoLock *pq)
{
    TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    // ① 跟踪 TCP 标志位
    if (ssn != NULL) {
        ssn->tcp_packet_flags |= tcph->th_flags;
        if (PKT_IS_TOSERVER(p))
            ssn->client.tcp_flags |= tcph->th_flags;
        else
            ssn->server.tcp_flags |= tcph->th_flags;
    }

    // ② 检查流级别 DROP 动作
    if (StreamTcpCheckFlowDrops(p) == 1) {
        StreamTcpSessionPktFree(p);
        return 0;
    }

    // ③ 无会话状态：处理 SYN / midstream
    if (ssn == NULL || ssn->state == TCP_NONE) {
        StreamTcpPacketStateNone(tv, p, stt, ssn);
        return 0;
    }

    // ④ 特殊包处理
    if (p->flags & PKT_PSEUDO_STREAM_END) {
        StreamTcpReassembleHandleSegment(...);  // 伪包只做重组
        goto skip;
    }

    // ⑤ Keep-Alive / Window Update / 重复 ACK 等过滤
    if (StreamTcpPacketIsKeepAlive(ssn, p))      goto skip;
    if (StreamTcpPacketIsKeepAliveACK(ssn, p))   goto skip;
    if (StreamTcpPacketIsWindowUpdate(ssn, p))    goto skip;
    if (StreamTcpPacketIsSpuriousRetransmission(ssn, p)) goto skip;

    // ⑥ 核心：根据当前状态分发处理
    StreamTcpStateDispatch(tv, p, stt, ssn, ssn->state);

skip:
    // ⑦ 设置 PKT_STREAM_EST 标志
    if (ssn->state >= TCP_ESTABLISHED) {
        p->flags |= PKT_STREAM_EST;
    }

    return 0;
}
```

### 6.3 状态分发：StreamTcpStateDispatch()

```c
// src/stream-tcp.c:5572-5647
static inline int StreamTcpStateDispatch(
    ThreadVars *tv, Packet *p, StreamTcpThread *stt,
    TcpSession *ssn, const uint8_t state)
{
    switch (state) {
        case TCP_SYN_SENT:
            return StreamTcpPacketStateSynSent(tv, p, stt, ssn);
        case TCP_SYN_RECV:
            return StreamTcpPacketStateSynRecv(tv, p, stt, ssn);
        case TCP_ESTABLISHED:
            return StreamTcpPacketStateEstablished(tv, p, stt, ssn);
        case TCP_FIN_WAIT1:
            return StreamTcpPacketStateFinWait1(tv, p, stt, ssn);
        case TCP_FIN_WAIT2:
            return StreamTcpPacketStateFinWait2(tv, p, stt, ssn);
        case TCP_CLOSING:
            return StreamTcpPacketStateClosing(tv, p, stt, ssn);
        case TCP_CLOSE_WAIT:
            return StreamTcpPacketStateCloseWait(tv, p, stt, ssn);
        case TCP_LAST_ACK:
            return StreamTcpPacketStateLastAck(tv, p, stt, ssn);
        case TCP_TIME_WAIT:
            return StreamTcpPacketStateTimeWait(tv, p, stt, ssn);
        case TCP_CLOSED:
            return StreamTcpPacketStateClosed(tv, p, stt, ssn);
    }
    return 0;
}
```

### 6.4 三次握手：SYN → SYN/ACK → ACK

**第一步：SYN（StreamTcpPacketStateNone）**

```c
// src/stream-tcp.c:1195（简化）
static int StreamTcpPacketStateNone(ThreadVars *tv, Packet *p,
                                    StreamTcpThread *stt, TcpSession *ssn)
{
    if (tcph->th_flags & TH_RST) {
        // RST 无会话 → 设事件，返回错误
        StreamTcpSetEvent(p, STREAM_RST_BUT_NO_SESSION);
        return -1;
    }

    if (tcph->th_flags & TH_SYN) {
        // ① 创建新会话
        ssn = StreamTcpNewSession(tv, stt, p, stt->ssn_pool_id);

        // ② 设置状态为 SYN_SENT
        StreamTcpPacketSetState(p, ssn, TCP_SYN_SENT);

        // ③ 记录客户端 ISN 和窗口
        ssn->client.isn = TCP_GET_RAW_SEQ(tcph);
        ssn->client.next_seq = ssn->client.isn + 1;
        ssn->client.window = TCP_GET_RAW_WINDOW(tcph);

        // ④ 解析 TCP 选项（窗口缩放、时间戳、SACK、MSS）
        StreamTcp3whsHandleSynOptions(ssn, p);

        // ⑤ 记录 SYN 选项到 queue（用于重传比较）
        StreamTcp3whsSynQueueAdd(ssn, p);
    }
    // ... midstream 处理 ...
}
```

**第二步：SYN/ACK（StreamTcpPacketStateSynSent）**

```c
// src/stream-tcp.c:2137（简化）
static int StreamTcpPacketStateSynSent(ThreadVars *tv, Packet *p,
                                       StreamTcpThread *stt, TcpSession *ssn)
{
    if ((tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)
        && PKT_IS_TOCLIENT(p))
    {
        // ① 验证 ACK 号匹配客户端 ISN+1
        if (TCP_GET_RAW_ACK(tcph) != ssn->client.isn + 1) {
            return -1;  // ACK 不匹配
        }

        // ② 记录服务端 ISN、窗口、选项
        ssn->server.isn = TCP_GET_RAW_SEQ(tcph);
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.window = TCP_GET_RAW_WINDOW(tcph);

        // ③ 状态转移到 SYN_RECV
        StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
        // ④ 更新客户端的 last_ack 和 next_win
        ssn->client.last_ack = TCP_GET_RAW_ACK(tcph);
    }
}
```

**第三步：ACK（StreamTcpPacketStateSynRecv）**

收到三次握手的最后一个 ACK 后，状态转移到 `TCP_ESTABLISHED`，Flow 状态也从 `FLOW_STATE_NEW` 变为 `FLOW_STATE_ESTABLISHED`。

### 6.5 Midstream 会话捡拾

Suricata 支持在连接中间开始跟踪（midstream），这在以下场景中很重要：

- 引擎启动时已有活跃连接
- 交换机/路由器做了不对称路由，只看到一个方向
- 从 PCAP 文件中间开始分析

Midstream 模式通过 `stream.midstream: true` 配置启用。在此模式下：
- 收到非 SYN 的 TCP 数据包时会创建会话
- 窗口缩放因子假设为最大值 14
- 序列号从看到的第一个包推算 ISN
- 设置 `STREAMTCP_FLAG_MIDSTREAM` 标志

### 6.6 会话标志位

会话标志位（`src/stream-tcp-private.h:169-210`）记录了会话的各种状态：

| 标志 | 含义 |
|------|------|
| `STREAMTCP_FLAG_MIDSTREAM` | 中间流捡拾 |
| `STREAMTCP_FLAG_TIMESTAMP` | 启用时间戳选项 |
| `STREAMTCP_FLAG_SERVER_WSCALE` | 服务端支持窗口缩放 |
| `STREAMTCP_FLAG_CLOSED_BY_RST` | 被 RST 关闭 |
| `STREAMTCP_FLAG_ASYNC` | 异步模式（只见单方向）|
| `STREAMTCP_FLAG_4WHS` | 四次握手（SYN→SYN→SYN/ACK→ACK）|
| `STREAMTCP_FLAG_SACKOK` | 双方都支持 SACK |
| `STREAMTCP_FLAG_APP_LAYER_DISABLED` | 应用层已禁用 |
| `STREAMTCP_FLAG_BYPASS` | 流可旁路 |
| `STREAMTCP_FLAG_TCP_FAST_OPEN` | TCP Fast Open |

---

## 7. TCP 重组引擎

重组引擎是 TCP 流处理中最复杂的部分，负责将乱序、重叠、带间隙的 TCP 段重组为连续的字节流。

### 7.1 入口：StreamTcpReassembleHandleSegment()

```c
// src/stream-tcp-reassemble.c:2003-2085（简化）
int StreamTcpReassembleHandleSegment(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                                     TcpSession *ssn, TcpStream *stream, Packet *p)
{
    // ① 确定更新方向
    enum StreamUpdateDir dir = UPDATE_DIR_OPPOSING;  // 默认：ACK 触发对端更新
    if (StreamTcpInlineMode())
        dir = UPDATE_DIR_PACKET;                     // IPS 模式：同方向立即更新
    if (tcph->th_flags & TH_RST)
        dir = UPDATE_DIR_PACKET;
    if ((tcph->th_flags & TH_FIN) && (tcph->th_flags & TH_ACK))
        dir = UPDATE_DIR_BOTH;

    // ② 处理 ACK：更新对端流的进度
    if (dir == UPDATE_DIR_OPPOSING || dir == UPDATE_DIR_BOTH) {
        TcpStream *opposing_stream = (stream == &ssn->client) ?
            &ssn->server : &ssn->client;
        StreamTcpReassembleHandleSegmentUpdateACK(tv, ra_ctx, ssn,
            opposing_stream, p);
    }

    // ③ 插入段数据
    if (p->payload_len > 0 &&
        !(stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY))
    {
        StreamTcpReassembleHandleSegmentHandleData(tv, ra_ctx, ssn, stream, p);
        p->flags |= PKT_STREAM_ADD;
    }

    // ④ 更新本方向流（触发应用层解析）
    if (dir == UPDATE_DIR_PACKET || dir == UPDATE_DIR_BOTH) {
        StreamTcpReassembleHandleSegmentUpdateACK(tv, ra_ctx, ssn, stream, p);
    }

    return 0;
}
```

### 7.2 段插入：HandleSegmentHandleData

```c
// src/stream-tcp-reassemble.c:746-880（简化）
int StreamTcpReassembleHandleSegmentHandleData(ThreadVars *tv,
    TcpReassemblyThreadCtx *ra_ctx, TcpSession *ssn,
    TcpStream *stream, Packet *p)
{
    // ① 首次见到数据的方向记录
    if (ssn->data_first_seen_dir == 0) {
        ssn->data_first_seen_dir = PKT_IS_TOSERVER(p) ?
            STREAM_TOSERVER : STREAM_TOCLIENT;
    }

    // ② 设置 OS 重叠处理策略
    if (stream->os_policy == 0)
        StreamTcpSetOSPolicy(stream, p);

    // ③ 重组深度检查
    // 超过 stream.reassembly.depth 后停止重组

    // ④ URG（紧急数据）处理
    // 根据 urgent_policy 决定是否将紧急字节从流中剥离

    // ⑤ 创建 TcpSegment 并插入红黑树
    TcpSegment *seg = SegmentAlloc(ra_ctx, ...);
    seg->seq = seg_seq;
    seg->payload_len = payload_len;

    int r = StreamTcpReassembleInsertSegment(tv, ra_ctx, stream,
        seg, p, p->payload, payload_len);
}
```

### 7.3 红黑树段管理

`TcpSegment` 使用红黑树（`TCPSEG`）而非链表来管理：

```c
// src/stream-tcp-private.h:88-92
int TcpSegmentCompare(struct TcpSegment *a, struct TcpSegment *b);
RB_HEAD(TCPSEG, TcpSegment);
RB_PROTOTYPE(TCPSEG, TcpSegment, rb, TcpSegmentCompare);
```

**排序规则**：主排序键是序列号（`seq`），序列号相同时按载荷长度（`payload_len`）从小到大排序。这确保了相同序列号的段中，较短的段（可能是重传的部分段）排在前面。

**插入流程**：
1. 检查 `memcap`（内存上限），超限则拒绝
2. 将段数据写入 `StreamingBuffer`
3. 将 `TcpSegment` 节点插入红黑树
4. 更新 `segs_right_edge`

### 7.4 StreamingBuffer：连续缓冲区

段的实际数据不存储在 `TcpSegment` 中，而是存储在 `TcpStream.sb`（`StreamingBuffer`）中。`StreamingBuffer` 是一个按需增长的连续缓冲区：

- 新数据追加到缓冲区末尾
- 乱序数据可能导致缓冲区中间留有间隙
- 当应用层消费数据后，可以滑动释放前面的空间
- `STREAM_BASE_OFFSET` 记录缓冲区起始位置对应的绝对字节偏移

### 7.5 IDS vs IPS 模式的重组差异

**IDS 模式**（默认）：
- 重组由 **ACK** 触发：收到 ACK 时处理对端流的数据
- 这意味着数据在被确认后才传递给应用层
- 优点：只处理被对端确认的可靠数据
- 缺点：有一个 RTT 的延迟

**IPS 模式**（inline）：
- 重组由 **数据包本身** 触发：收到数据时立即处理
- 这意味着数据在收到时就传递给应用层
- 优点：零延迟，可以在数据到达对端前做出判决
- 缺点：可能处理被对端丢弃的数据

### 7.6 GAP 处理

当检测到序列号间隙（缺少中间的段）时：

1. 设置 `STREAMTCP_STREAM_FLAG_HAS_GAP` 标志
2. 通知应用层解析器有间隙
3. 应用层可以决定是否继续解析（某些协议如 HTTP 可以跨 GAP 继续）
4. 如果间隙被后续重传填补，重组正常继续

### 7.7 重组深度

```yaml
stream:
  reassembly:
    depth: 1mb    # 每个方向最多重组 1MB 数据
```

超过深度后：
- 设置 `STREAMTCP_STREAM_FLAG_DEPTH_REACHED`
- 停止接收新段
- 应用层停止解析
- 可以触发流旁路（如果启用）

---

## 8. 重组进度追踪

每个 `TcpStream` 维护三个独立的进度指针：

```
数据流方向 →
─────────────────────────────────────────────
| 已释放 |    已消费    | 已重组但未消费 | 未确认 |
─────────────────────────────────────────────
         ↑              ↑                ↑
    base_seq    app_progress_rel    last_ack / next_seq
                         ↑
                raw_progress_rel
                         ↑
                log_progress_rel
```

- **`base_seq`**：重组基准序列号。低于此值的数据已被释放
- **`app_progress_rel`**：应用层已消费的相对偏移（相对于 `STREAM_BASE_OFFSET`）
- **`raw_progress_rel`**：原始重组（用于 payload 检测规则）的进度
- **`log_progress_rel`**：流式日志（如 PCAP 日志）的进度

三个进度独立推进，互不影响。只有当三个进度都推过某个位置后，该位置的数据才可以被释放。

---

## 9. 内存管理

TCP 流处理是 Suricata 中最大的内存消费者之一。有两个独立的 memcap 控制：

### 9.1 流引擎 memcap

```yaml
stream:
  memcap: 64mb    # TCP 会话本身的内存上限
```

控制 `TcpSession` 对象的总内存使用。超限时新连接的 SYN 会被丢弃或触发异常策略。

通过原子计数器跟踪（`src/stream-tcp.c:229`）：

```c
SC_ATOMIC_DECLARE(uint64_t, st_memuse);

void StreamTcpIncrMemuse(uint64_t size) {
    SC_ATOMIC_ADD(st_memuse, size);
}
```

### 9.2 重组 memcap

```yaml
stream:
  reassembly:
    memcap: 256mb   # 重组缓冲区的内存上限
```

控制 `StreamingBuffer` 中段数据的总内存使用。这通常比流引擎 memcap 大得多，因为每个活跃连接可能缓存数 KB 到数 MB 的数据。

### 9.3 对象池

`TcpSession` 和 `TcpSegment` 都使用线程本地对象池（`PoolThread`）管理，避免频繁的 malloc/free：

- **TcpSession 池**：全局 `PoolThread *ssn_pool`，���个工作线程有独立的池分区
- **TcpSegment 池**：在 `TcpReassemblyThreadCtx` 中管理

对象池预分配一批对象，回收时不释放内存，而是归还到池中供后续复用。

---

## 10. 流处理与 FlowWorker 的集成

回顾 FlowWorker 中 TCP 处理的调用链：

```c
// src/flow-worker.c（简化）
static TmEcode FlowWorker(ThreadVars *tv, Packet *p, void *data)
{
    // ... 流查找 ...

    if (PacketIsTCP(p)) {
        // ① TCP 流处理（状态机 + 重组）
        FlowWorkerStreamTCPUpdate(tv, fw, p, det_ctx, false);

        // ② 更新应用层标志
        PacketAppUpdate2FlowFlags(p);
    } else if (p->proto == IPPROTO_UDP) {
        // UDP 直接走应用层
        AppLayerHandleUdp(tv, ..., p, p->flow);
    }

    // ③ 检测
    Detect(tv, p, det_ctx);

    // ④ 输出
    OutputLoggerLog(tv, p, ...);
}
```

`FlowWorkerStreamTCPUpdate()` 内部调用 `StreamTcpPacket()`，完成：
1. TCP 状态机转换
2. 段插入与重组
3. 触发应用层协议检测和解析

重组后的数据通过 `StreamTcpReassembleAppLayer()` 传递给应用层解析器。这一步发生在 `StreamTcpReassembleHandleSegmentUpdateACK()` 内部——当 ACK 推进时，将新确认的数据交给应用层处理。

---

## 11. 完整的 TCP 连接生命周期

以一个典型的 HTTP 请求为例，跟踪完整的生命周期：

```
时刻    数据包               Flow 状态        TCP 状态        重组动作
─────────────────────────────────────────────────────────────────────
T1      C→S: SYN             NEW              SYN_SENT        创建 TcpSession
T2      S→C: SYN/ACK         NEW              SYN_RECV        记录服务端 ISN
T3      C→S: ACK             ESTABLISHED      ESTABLISHED     三次握手完成
T4      C→S: GET /           ESTABLISHED      ESTABLISHED     插入段，等待 ACK
T5      S→C: ACK             ESTABLISHED      ESTABLISHED     ACK 触发客户端流重组
                                                               → AppLayer: HTTP 请求
T6      S→C: 200 OK          ESTABLISHED      ESTABLISHED     插入段
T7      C→S: ACK             ESTABLISHED      ESTABLISHED     ACK 触发服务端流重组
                                                               → AppLayer: HTTP 响应
T8      C→S: FIN/ACK         ESTABLISHED      FIN_WAIT1       --
T9      S→C: FIN/ACK         ESTABLISHED      CLOSING         --
T10     C→S: ACK             CLOSED           TIME_WAIT       最终状态
        ...                  (超时后)          --              FlowManager 回收
```

---

## 12. 关键配置参数

```yaml
# suricata.yaml

flow:
  memcap: 128mb              # 流表内存上限
  hash-size: 65536           # 哈希桶数量
  prealloc: 10000            # 预分配 Flow 数量
  emergency-recovery: 30     # 紧急模式恢复阈值 (%)

  timeouts:
    default:
      new: 30                # NEW 状态超时 (秒)
      established: 300       # ESTABLISHED 超时 (秒)
      closed: 0
      bypassed: 100
    tcp:
      new: 60
      established: 600
      closed: 60
      bypassed: 100
      emergency-new: 10
      emergency-established: 100
      emergency-closed: 0

stream:
  memcap: 64mb               # TCP 会话内存上限
  midstream: false            # 是否启用 midstream 捡拾
  async-oneside: false        # 是否启用异步单侧模式
  checksum-validation: yes    # 是否验证 TCP 校验和
  inline: auto                # IPS 模式（auto/yes/no）

  reassembly:
    memcap: 256mb             # 重组缓冲区内存上限
    depth: 1mb                # 每方向最大重组深度
    toserver-chunk-size: 2560 # toserver 方向的块大小
    toclient-chunk-size: 2560 # toclient 方向的块大小

  # VLAN 和设备追踪
  vlan:
    use-for-tracking: true    # VLAN ID 是否参与流匹配
```

### 调优要点

1. **hash-size**：过小导致链表过长（查找慢），过大浪费内存。经验值：预期并发流数 / 2

2. **stream.memcap vs stream.reassembly.memcap**：前者控制 TcpSession 数量，后者控制重组缓冲区。高带宽场景下 `reassembly.memcap` 通常是瓶颈

3. **reassembly.depth**：减小可以降低内存使用，但会导致大文件传输的尾部数据无法被检测

4. **midstream**：启用会增加 CPU 和内存开销，但在非对称路由或引擎重启场景下是必要的

---

## 13. 设计总结

| 设计决策 | 原因 |
|----------|------|
| 两级锁（桶锁 + 流锁） | 桶锁保护链表结构，流锁保护内部状态，减少锁竞争 |
| 哈希规范化（IP/端口排序） | 正反向包产生相同哈希，无需双向查找 |
| 缓存行对齐 FlowBucket | 消除多线程伪共享 |
| `next_ts` 优化 | 跳过未超时的桶，减少 FlowManager 的锁争用 |
| 红黑树存储 TCP 段 | O(log n) 插入，处理大量乱序段 |
| 段数据分离（StreamingBuffer） | 减少内存碎片，支持连续缓冲区 |
| 三级进度指针 | 应用层、raw 检测、日志各自独立推进 |
| ACK 触发重组（IDS） | 只处理被确认的可靠数据 |
| 对象池 | 避免频繁 malloc/free |
| 三级清理（超时→工作队列→回收池） | 不在热路径上做耗时的释放操作 |

流处理子系统是 Suricata 中代码量最大、复杂度最高的部分之一。`stream-tcp.c` 单文件超过 6000 行，`stream-tcp-reassemble.c` 也有 2000+ 行。理解了本篇的核心设计，后续深入任何一个细节都会更加顺畅。

下一篇我们将进入应用层协议检测与解析，看重组后的字节流如何被识别为 HTTP、TLS、DNS 等具体协议。
