# 10 - 解码层：协议栈逐层解包

> **导读**：上一篇建立了 Suricata 的全局架构认知。本篇深入解码层（Decode Layer），剖析 `decode-*.c` 源码，看 Suricata 如何将原始网络帧逐层解析为结构化的 `Packet` 对象。我们将跟踪一个数据包从 Ethernet 头到 TCP 载荷的完整解码过程，理解隧道解封装与伪包机制，以及解码器的防御性设计。

---

## 1. 解码层在流水线中的位置

回顾第 9 篇的数据包旅程，解码层处于 Receive（抓包）之后、FlowWorker（流处理+检测）之前：

```
PacketPool → [Receive] → [Decode] → [FlowWorker] → [RespondReject] → PacketPool
                            ↑
                         本篇重点
```

抓包模块（如 `ReceiveAFP`）将原始网络帧写入 `Packet` 的 `pkt_data[]` 缓冲区，并设置数据长度和时间戳。解码模块的任务是：

1. **逐层解析协议头**：Ethernet → IPv4/IPv6 → TCP/UDP/ICMP
2. **填充 Packet 的分层结构**：`l2`、`l3`、`l4` 字段
3. **提取五元组**：`src`、`dst`、`sp`、`dp`、`proto`
4. **定位载荷**：设置 `payload` 指针和 `payload_len`
5. **处理隧道**：GRE/VXLAN/Geneve 等封装协议的解封装
6. **处理分片**：IPv4/IPv6 分片的重组

---

## 2. 分层数据结构：PacketL2 / L3 / L4

Suricata 用三个结构体分别存储二层、三层、四层的解码结果，定义在 `src/decode.h:414-482`。

### 2.1 PacketL2 — 二层

```c
// src/decode.h:414-424
enum PacketL2Types {
    PACKET_L2_UNKNOWN = 0,
    PACKET_L2_ETHERNET,
};

struct PacketL2 {
    enum PacketL2Types type;
    union L2Hdrs {
        EthernetHdr *ethh;         // 指向原始帧中的 Ethernet 头
    } hdrs;
};
```

目前只支持 Ethernet 一种二层类型。`ethh` 是指向 `Packet.pkt_data[]` 内部的指针（零拷贝），不会单独分配内存。

### 2.2 PacketL3 — 三层

```c
// src/decode.h:433-451
struct PacketL3 {
    enum PacketL3Types type;       // IPV4 / IPV6 / ARP
    bool csum_set;                 // 校验和是否已计算
    uint16_t csum;                 // 校验和值
    union Hdrs {
        IPV4Hdr *ip4h;             // IPv4 头指针
        IPV6Hdr *ip6h;             // IPv6 头指针
        ARPHdr *arph;              // ARP 头指针
    } hdrs;
    union {
        IPV4Vars ip4;              // IPv4 解析变量（选项等）
        struct {
            IPV6Vars v;            // IPv6 基本变量
            IPV6ExtHdrs eh;        // IPv6 扩展头解析结果
        } ip6;
    } vars;
};
```

**设计要点**：

- `hdrs` 和 `vars` 都用 union，因为一个包不可能同时是 IPv4 和 IPv6
- `csum_set` 标记校验和是否已被网卡 offload 验证过，避免重复计算
- `vars` 中存放解析后的结构化数据（如 IPv4 选项、IPv6 扩展头），供后续规则匹配使用

### 2.3 PacketL4 — 四层

```c
// src/decode.h:464-482
struct PacketL4 {
    enum PacketL4Types type;       // TCP / UDP / ICMPV4 / ICMPV6 / SCTP / GRE / ESP
    bool csum_set;
    uint16_t csum;
    union L4Hdrs {
        TCPHdr *tcph;
        UDPHdr *udph;
        ICMPV4Hdr *icmpv4h;
        ICMPV6Hdr *icmpv6h;
        SCTPHdr *sctph;
        GREHdr *greh;
        ESPHdr *esph;
    } hdrs;
    union L4Vars {
        TCPVars tcp;               // TCP 选项解析结果（窗口缩放、时间戳、SACK 等）
        ICMPV4Vars icmpv4;         // ICMPv4 解析结果（嵌入的 IP 头信息）
        ICMPV6Vars icmpv6;         // ICMPv6 解析结果
    } vars;
};
```

七种四层协议共享头指针 union，其中 GRE 和 ESP 虽然在四层结构中有位置，但它们实际上是隧道协议，解码后会创建新的伪包（pseudo packet）。

### 2.4 三层合体

这三个结构体嵌入在 `Packet` 结构体中（`src/decode.h:599-601`）：

```c
struct PacketL2 l2;    // p->l2.hdrs.ethh
struct PacketL3 l3;    // p->l3.hdrs.ip4h 或 p->l3.hdrs.ip6h
struct PacketL4 l4;    // p->l4.hdrs.tcph 或 p->l4.hdrs.udph
```

解码器通过 `PacketSetEthernet()`、`PacketSetIPV4()`、`PacketSetTCP()` 等 inline 函数设置这些字段。这些函数同时设置 `type` 枚举和 `hdrs` 指针，保证类型安全。

---

## 3. 事件机制：解码器的错误报告

解码器不使用异常或错误返回码来报告协议违规，而是使用**事件（event）**机制。这是 Suricata 解码层最重要的设计特征之一。

### 3.1 两个关键宏

```c
// src/decode.h:1186-1197

// 非致命事件：记录异常但继续处理
#define ENGINE_SET_EVENT(p, e) do { \
    if ((p)->events.cnt < PACKET_ENGINE_EVENT_MAX) { \
        (p)->events.events[(p)->events.cnt] = e; \
        (p)->events.cnt++; \
    } \
} while(0)

// 致命事件：记录异常并标记包为无效
#define ENGINE_SET_INVALID_EVENT(p, e) do { \
    p->flags |= PKT_IS_INVALID; \
    ENGINE_SET_EVENT(p, e); \
} while(0)
```

**区别**：`ENGINE_SET_INVALID_EVENT` 额外设置 `PKT_IS_INVALID` 标志，标记数据包无效。两者都将事件追加到 `Packet.events` 数组中，最多 15 个事件（`PACKET_ENGINE_EVENT_MAX = 15`）。

### 3.2 事件类型

所有解码器事件定义在 `src/decode-events.h:29-319`，按协议分类，共 200+ 种：

```c
// src/decode-events.h（部分）
enum {
    // IPv4 事件
    IPV4_PKT_TOO_SMALL,            // 包太小
    IPV4_HLEN_TOO_SMALL,           // 头部长度太小
    IPV4_IPLEN_SMALLER_THAN_HLEN,  // IP 总长度小于头部长度
    IPV4_TRUNC_PKT,                // 截断的包
    IPV4_WRONG_IP_VER,             // IP 版本号错误
    IPV4_WITH_ICMPV6,              // IPv4 中包含 ICMPv6（不合法）

    // TCP 事件
    TCP_PKT_TOO_SMALL,             // TCP 包太小
    TCP_HLEN_TOO_SMALL,            // TCP 头部太小
    TCP_INVALID_OPTLEN,            // TCP 选项长度无效
    TCP_OPT_INVALID_LEN,           // 特定选项长度无效
    TCP_OPT_DUPLICATE,             // 重复的 TCP 选项

    // 隧道事件
    GRE_PKT_TOO_SMALL,
    VXLAN_UNKNOWN_PAYLOAD_TYPE,
    GENERIC_TOO_MANY_LAYERS,       // 解码层数超限
    ...
};
```

这些事件可以在 Suricata 规则中使用 `decode-event` 关键字匹配：

```
alert pkthdr any any -> any any (msg:"IPv4 truncated"; decode-event:ipv4.trunc_pkt; sid:1; rev:1;)
```

### 3.3 事件统计

每个包处理完后，`PacketUpdateEngineEventCounters()`（`src/decode.c:243`）遍历包上的所有事件，更新对应的计数器：

```c
// src/decode.c:243-254
void PacketUpdateEngineEventCounters(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p)
{
    for (uint8_t i = 0; i < p->events.cnt; i++) {
        const uint8_t e = p->events.events[i];
        StatsIncr(tv, dtv->counter_engine_events[e]);
    }
}
```

这些计数器会出现在 `stats.log` 和 EVE JSON 的 `stats` 事件中，是排查解码问题的重要工具。

---

## 4. 层数防护：防止解码层耗尽栈

恶意构造的数据包可能包含大量嵌套层（如 Ethernet → VLAN → VLAN → ... → IPv4），导致递归解码耗尽栈空间。Suricata 通过 `PacketIncreaseCheckLayers()` 防护：

```c
// src/decode.h:1327-1338
#define PKT_DEFAULT_MAX_DECODED_LAYERS 16
extern uint8_t decoder_max_layers;

static inline bool PacketIncreaseCheckLayers(Packet *p)
{
    p->nb_decoded_layers++;
    if (p->nb_decoded_layers >= decoder_max_layers) {
        ENGINE_SET_INVALID_EVENT(p, GENERIC_TOO_MANY_LAYERS);
        return false;
    }
    return true;
}
```

每个解码器函数入口处都调用此函数。默认上限 16 层，可通过 `decoder.max-layers` 配置。超过限制时设置 `GENERIC_TOO_MANY_LAYERS` 事件并终止解码。

---

## 5. 逐层解码流程

### 5.1 入口：抓包模块调用解码函数

以 AF_PACKET 为例，抓包模块在收到一帧后调用 `DecodeAFP()`，该函数是一个薄封装：

```c
// 伪代码，简化
int DecodeAFP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
              const uint8_t *pkt, uint32_t len)
{
    PacketDecodeFinalize(tv, dtv, p);   // 设置基本信息
    DecodeLinkLayer(tv, dtv, p->datalink, p, pkt, len);  // 分发到链路层解码
    return TM_ECODE_OK;
}
```

### 5.2 链路层分发：DecodeLinkLayer()

```c
// src/decode.h:1418-1451
static inline void DecodeLinkLayer(ThreadVars *tv, DecodeThreadVars *dtv,
        const int datalink, Packet *p, const uint8_t *data, const uint32_t len)
{
    switch (datalink) {
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p, data, len);
            break;
        case LINKTYPE_LINUX_SLL:
            DecodeSll(tv, dtv, p, data, len);
            break;
        case LINKTYPE_LINUX_SLL2:
            DecodeSll2(tv, dtv, p, data, len);
            break;
        case LINKTYPE_PPP:
            DecodePPP(tv, dtv, p, data, len);
            break;
        case LINKTYPE_RAW:
        case LINKTYPE_GRE_OVER_IP:
            DecodeRaw(tv, dtv, p, data, len);      // 无链路层头，直接是 IP
            break;
        case LINKTYPE_NULL:
            DecodeNull(tv, dtv, p, data, len);
            break;
        case LINKTYPE_CISCO_HDLC:
            DecodeCHDLC(tv, dtv, p, data, len);
            break;
        default:
            SCLogError("datalink type %" PRId32 " not yet supported", datalink);
            break;
    }
}
```

`datalink` 值由抓包模块在初始化时从网卡/文件中读取。以太网环境下固定为 `LINKTYPE_ETHERNET`。

### 5.3 第一层：DecodeEthernet() — 以太网帧解析

```c
// src/decode-ethernet.c:42-65
int DecodeEthernet(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   const uint8_t *pkt, uint32_t len)
{
    // ① 更新统计计数器
    StatsIncr(tv, dtv->counter_eth);

    // ② 验证最小长度：Ethernet 头 = 14 字节
    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    // ③ 检查解码层数
    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    // ④ 设置 L2 头指针（零拷贝）
    EthernetHdr *ethh = PacketSetEthernet(p, pkt);

    // ⑤ 根据 EtherType 分发到网络层解码器
    DecodeNetworkLayer(tv, dtv, SCNtohs(ethh->eth_type), p,
            pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN);

    return TM_ECODE_OK;
}
```

**关键点**：Ethernet 头只有 14 字节（6 字节目的 MAC + 6 字节源 MAC + 2 字节 EtherType），解码极其简单。`PacketSetEthernet()` 将 `p->l2.type` 设为 `PACKET_L2_ETHERNET`，将 `p->l2.hdrs.ethh` 指向帧数据起始位置。

### 5.4 网络层分发：DecodeNetworkLayer()

```c
// src/decode.h:1455-1515
static inline bool DecodeNetworkLayer(ThreadVars *tv, DecodeThreadVars *dtv,
        const uint16_t proto, Packet *p, const uint8_t *data, const uint32_t len)
{
    switch (proto) {
        case ETHERNET_TYPE_IP:                    // 0x0800
            DecodeIPV4(tv, dtv, p, data, (uint16_t)len);
            break;
        case ETHERNET_TYPE_IPV6:                  // 0x86DD
            DecodeIPV6(tv, dtv, p, data, (uint16_t)len);
            break;
        case ETHERNET_TYPE_VLAN:                  // 0x8100
        case ETHERNET_TYPE_8021AD:                // 0x88A8
        case ETHERNET_TYPE_8021QINQ:              // 0x9100
            DecodeVLAN(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_MPLS_UNICAST:          // 0x8847
        case ETHERNET_TYPE_MPLS_MULTICAST:        // 0x8848
            DecodeMPLS(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_PPPOE_SESS:            // 0x8864
            DecodePPPOESession(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_ARP:                   // 0x0806
            DecodeARP(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_8021AH:                // 0x88E7（MAC-in-MAC）
            DecodeIEEE8021ah(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_NSH:                   // 0x894F（Network Service Header）
            DecodeNSH(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_VNTAG:                 // VN-Tag
            DecodeVNTag(tv, dtv, p, data, len);
            break;
        default:
            StatsIncr(tv, dtv->counter_ethertype_unknown);
            ENGINE_SET_EVENT(p, ETHERNET_UNKNOWN_ETHERTYPE);
            return false;
    }
    return true;
}
```

这是一个二次分发点，根据 EtherType 进入不同的协议解码器。注意 VLAN 有三种 EtherType（802.1Q / 802.1ad / QinQ），都路由到同一个 `DecodeVLAN()` 函数。

---

## 6. IPv4 解码：DecodeIPV4()

IPv4 解码是最典型、最完整的三层解码器，定义在 `src/decode-ipv4.c:520-622`。

### 6.1 头部验证：DecodeIPV4Packet()

先看内部验证函数（`src/decode-ipv4.c:473-518`）：

```c
static const IPV4Hdr *DecodeIPV4Packet(Packet *p, const uint8_t *pkt, uint16_t len)
{
    // ① 最小长度检查（20 字节）
    if (unlikely(len < IPV4_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_PKT_TOO_SMALL);
        return NULL;
    }

    // ② 版本号检查（必须为 4）
    if (unlikely(IP_GET_RAW_VER(pkt) != 4)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_WRONG_IP_VER);
        return NULL;
    }

    // ③ 设置 L3 头指针
    const IPV4Hdr *ip4h = PacketSetIPV4(p, pkt);

    // ④ IHL（头部长度）检查：必须 >= 20 字节
    if (unlikely(IPV4_GET_RAW_HLEN(ip4h) < IPV4_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_HLEN_TOO_SMALL);
        return NULL;
    }

    // ⑤ 总长度 vs 头部长度一致性检查
    if (unlikely(IPV4_GET_RAW_IPLEN(ip4h) < IPV4_GET_RAW_HLEN(ip4h))) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_IPLEN_SMALLER_THAN_HLEN);
        return NULL;
    }

    // ⑥ 实际数据长度 vs IP 声明长度
    if (unlikely(len < IPV4_GET_RAW_IPLEN(ip4h))) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_TRUNC_PKT);
        return NULL;
    }

    // ⑦ 提取源/目的 IP 地址到 Packet.src / Packet.dst
    SET_IPV4_SRC_ADDR(ip4h, &p->src);
    SET_IPV4_DST_ADDR(ip4h, &p->dst);

    // ⑧ 解析 IP 选项（如果头部 > 20 字节）
    uint8_t ip_opt_len = IPV4_GET_RAW_HLEN(ip4h) - IPV4_HEADER_LEN;
    if (ip_opt_len > 0) {
        IPV4Options opts;
        memset(&opts, 0x00, sizeof(opts));
        DecodeIPV4Options(p, pkt + IPV4_HEADER_LEN, ip_opt_len, &opts);
    }

    return ip4h;
}
```

五道防线层层验证：最小长度 → 版本号 → 头部长度 → 长度一致性 → 截断检测。任何一步失败都设置对应的 `INVALID_EVENT` 并返回 NULL。

### 6.2 主函数：协议分发与分片处理

```c
// src/decode-ipv4.c:520-622
int DecodeIPV4(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint16_t len)
{
    StatsIncr(tv, dtv->counter_ipv4);              // 统计计数

    if (!PacketIncreaseCheckLayers(p))              // 层数检查
        return TM_ECODE_FAILED;

    const IPV4Hdr *ip4h = DecodeIPV4Packet(p, pkt, len);  // 头部验证
    if (unlikely(ip4h == NULL)) {
        PacketClearL3(p);                           // 验证失败，清除 L3
        return TM_ECODE_FAILED;
    }
    p->proto = IPV4_GET_RAW_IPPROTO(ip4h);         // 提取上层协议号

    /* ===== 分片处理 ===== */
    if (unlikely(IPV4_GET_RAW_FRAGOFFSET(ip4h) > 0 || IPV4_GET_RAW_FLAG_MF(ip4h))) {
        Packet *rp = Defrag(tv, dtv, p);           // 送入重组引擎
        if (rp != NULL) {
            PacketEnqueueNoLock(&tv->decode_pq, rp);  // 重组完成，入队
        }
        p->flags |= PKT_IS_FRAGMENT;               // 标记为分片
        return TM_ECODE_OK;                         // 分片不继续解码上层
    }

    /* ===== 计算载荷偏移 ===== */
    const uint8_t *data = pkt + IPV4_GET_RAW_HLEN(ip4h);
    const uint16_t data_len = IPV4_GET_RAW_IPLEN(ip4h) - IPV4_GET_RAW_HLEN(ip4h);

    /* ===== 上层协议分发 ===== */
    switch (p->proto) {
        case IPPROTO_TCP:
            DecodeTCP(tv, dtv, p, data, data_len);
            break;
        case IPPROTO_UDP:
            DecodeUDP(tv, dtv, p, data, data_len);
            break;
        case IPPROTO_ICMP:
            DecodeICMPV4(tv, dtv, p, data, data_len);
            break;
        case IPPROTO_GRE:
            DecodeGRE(tv, dtv, p, data, data_len);
            break;
        case IPPROTO_SCTP:
            DecodeSCTP(tv, dtv, p, data, data_len);
            break;
        case IPPROTO_ESP:
            DecodeESP(tv, dtv, p, data, data_len);
            break;
        case IPPROTO_IPV6:                          // IPv6-in-IPv4 隧道
            PacketTunnelPktSetup(tv, dtv, p, data, data_len, DECODE_TUNNEL_IPV6);
            break;
        case IPPROTO_IPIP:                          // IPv4-in-IPv4 隧道
            PacketTunnelPktSetup(tv, dtv, p, data, data_len, DECODE_TUNNEL_IPV4);
            break;
        case IPPROTO_ICMPV6:                        // 非法：IPv4 中出现 ICMPv6
            ENGINE_SET_INVALID_EVENT(p, IPV4_WITH_ICMPV6);
            break;
    }
    return TM_ECODE_OK;
}
```

**关键设计**：

1. **分片提前返回**：检测到分片后立即送入 `Defrag()` 重组引擎，不再解析上层协议。重组完成的包会作为伪包重新进入解码流水线
2. **隧道创建伪包**：`IPPROTO_IPV6`（协议号 41）和 `IPPROTO_IPIP`（协议号 4）会调用 `PacketTunnelPktSetup()` 创建新的伪包
3. **协议合法性检查**：IPv4 中出现 ICMPv6 会触发 `IPV4_WITH_ICMPV6` 事件

---

## 7. TCP 解码：DecodeTCP()

TCP 解码定义在 `src/decode-tcp.c:273-286`，内部实现在 `DecodeTCPPacket()`（`src/decode-tcp.c:217-271`）：

```c
static int DecodeTCPPacket(ThreadVars *tv, DecodeThreadVars *dtv,
        Packet *p, const uint8_t *pkt, uint16_t len)
{
    // ① 最小长度检查（20 字节）
    if (unlikely(len < TCP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, TCP_PKT_TOO_SMALL);
        return -1;
    }

    // ② 设置 L4 头指针
    TCPHdr *tcph = PacketSetTCP(p, pkt);

    // ③ 验证数据偏移（头部长度）
    uint8_t hlen = TCP_GET_RAW_HLEN(tcph);          // 数据偏移字段 × 4
    if (unlikely(len < hlen)) {
        ENGINE_SET_INVALID_EVENT(p, TCP_HLEN_TOO_SMALL);
        return -1;
    }

    // ④ 验证选项长度（最大 40 字节 = 60 - 20）
    uint8_t tcp_opt_len = hlen - TCP_HEADER_LEN;
    if (unlikely(tcp_opt_len > TCP_OPTLENMAX)) {
        ENGINE_SET_INVALID_EVENT(p, TCP_INVALID_OPTLEN);
        return -1;
    }

    // ⑤ 解析 TCP 选项
    if (likely(tcp_opt_len > 0)) {
        DecodeTCPOptions(p, pkt + TCP_HEADER_LEN, tcp_opt_len);
    }

    // ⑥ 提取端口号和载荷
    p->sp = TCP_GET_RAW_SRC_PORT(tcph);
    p->dp = TCP_GET_RAW_DST_PORT(tcph);
    p->proto = IPPROTO_TCP;
    p->payload = (uint8_t *)pkt + hlen;
    p->payload_len = len - hlen;

    // ⑦ 标志位统计
    if ((tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
        StatsIncr(tv, dtv->counter_tcp_synack);
    else if (tcph->th_flags & TH_SYN)
        StatsIncr(tv, dtv->counter_tcp_syn);
    if (tcph->th_flags & TH_RST)
        StatsIncr(tv, dtv->counter_tcp_rst);

    return 0;
}
```

外层的 `DecodeTCP()` 很简单：

```c
// src/decode-tcp.c:273-286
int DecodeTCP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint16_t len)
{
    StatsIncr(tv, dtv->counter_tcp);

    if (unlikely(DecodeTCPPacket(tv, dtv, p, pkt, len) < 0)) {
        PacketClearL4(p);          // 解码失败，清除 L4 状态
        return TM_ECODE_FAILED;
    }

    FlowSetupPacket(p);            // 设置流查找标志（PKT_WANTS_FLOW）
    return TM_ECODE_OK;
}
```

**TCP 选项解析**（`DecodeTCPOptions()`，`src/decode-tcp.c:42-215`）：

解析器遍历选项缓冲区，识别以下选项并存储到 `p->l4.vars.tcp`：

| 选项 | 值 | 存储位置 |
|------|-----|---------|
| MSS | 最大段大小 | `tcp.mss` |
| Window Scale | 窗口缩放因子 | `tcp.wscale` |
| SACK Permitted | 是否允许 SACK | `tcp.sack_ok` |
| SACK | 选择确认块 | `tcp.sack_cnt`, `tcp.sack_offset` |
| Timestamp | 时间戳 | `tcp.ts_val`, `tcp.ts_ecr` |
| TFO | TCP Fast Open | `tcp.tfo` |
| MD5 | TCP-MD5 签名 | `tcp.md5_option_present` |
| AO | TCP 认证选项 | `tcp.ao_option_present` |

每个选项都有长度验证和重复检测，异常时设置 `TCP_OPT_INVALID_LEN` 或 `TCP_OPT_DUPLICATE` 事件。

---

## 8. UDP 解码：DecodeUDP()

UDP 解码定义在 `src/decode-udp.c:75-117`，是所有解码器中最简洁的，但它有一个独特功能——**内联隧道检测**：

```c
// src/decode-udp.c:45-117
static int DecodeUDPPacket(ThreadVars *t, Packet *p, const uint8_t *pkt, uint16_t len)
{
    if (unlikely(len < UDP_HEADER_LEN)) {                    // 最小 8 字节
        ENGINE_SET_INVALID_EVENT(p, UDP_HLEN_TOO_SMALL);
        return -1;
    }

    const UDPHdr *udph = PacketSetUDP(p, pkt);

    if (unlikely(len < UDP_GET_RAW_LEN(udph))) {            // 实际数据不够
        ENGINE_SET_INVALID_EVENT(p, UDP_PKT_TOO_SMALL);
        return -1;
    }
    if (unlikely(UDP_GET_RAW_LEN(udph) < UDP_HEADER_LEN)) { // UDP 声明长度 < 8
        ENGINE_SET_INVALID_EVENT(p, UDP_LEN_INVALID);
        return -1;
    }

    p->sp = UDP_GET_RAW_SRC_PORT(udph);
    p->dp = UDP_GET_RAW_DST_PORT(udph);
    p->payload = (uint8_t *)pkt + UDP_HEADER_LEN;
    p->payload_len = UDP_GET_RAW_LEN(udph) - UDP_HEADER_LEN;
    p->proto = IPPROTO_UDP;
    return 0;
}

int DecodeUDP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint16_t len)
{
    StatsIncr(tv, dtv->counter_udp);

    if (unlikely(DecodeUDPPacket(tv, p, pkt, len) < 0)) {
        PacketClearL4(p);
        return TM_ECODE_FAILED;
    }

    // ===== 隧道协议检测（按端口号）=====

    // Teredo（IPv6-over-UDP，默认端口 3544）
    if (DecodeTeredoEnabledForPort(p->sp, p->dp) &&
            likely(DecodeTeredo(tv, dtv, p, p->payload, p->payload_len) == TM_ECODE_OK)) {
        FlowSetupPacket(p);
        return TM_ECODE_OK;
    }

    // Geneve（通用网络虚拟化封装使用默认端口 6081）
    if (DecodeGeneveEnabledForPort(p->sp, p->dp) &&
            unlikely(DecodeGeneve(tv, dtv, p, p->payload, p->payload_len) == TM_ECODE_OK)) {
        FlowSetupPacket(p);
        return TM_ECODE_OK;
    }

    // VXLAN（虚拟可扩展局域网，默认端口 4789）
    if (DecodeVXLANEnabledForPort(p->dp) &&
            unlikely(DecodeVXLAN(tv, dtv, p, p->payload, p->payload_len) == TM_ECODE_OK)) {
        FlowSetupPacket(p);
        return TM_ECODE_OK;
    }

    FlowSetupPacket(p);
    return TM_ECODE_OK;
}
```

**设计要点**：UDP 解码器在完成基本解码后，会依次探测三种 UDP 隧道协议。探测顺序固定：Teredo → Geneve → VXLAN。每种隧道都有端口白名单检查（`DecodeXxxEnabledForPort()`），只有匹配端口才会尝试解析。如果识别为隧道，内层数据包会通过伪包机制独立处理。

---

## 9. VLAN 解码

VLAN（802.1Q）是二层和三层之间的中间协议，定义在 `src/decode-vlan.c:54`：

```c
// src/decode-vlan.c:54-87（简化）
int DecodeVLAN(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint32_t len)
{
    // 统计：区分单层 VLAN、QinQ、QinQinQ
    if (p->vlan_idx == 0)
        StatsIncr(tv, dtv->counter_vlan);
    else if (p->vlan_idx == 1)
        StatsIncr(tv, dtv->counter_vlan_qinq);
    else if (p->vlan_idx == 2)
        StatsIncr(tv, dtv->counter_vlan_qinqinq);

    if (len < VLAN_HEADER_LEN) {                           // 4 字节头部
        ENGINE_SET_INVALID_EVENT(p, VLAN_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
    if (!PacketIncreaseCheckLayers(p))
        return TM_ECODE_FAILED;
    if (p->vlan_idx > VLAN_MAX_LAYER_IDX) {               // 最多 3 层 VLAN
        ENGINE_SET_EVENT(p, VLAN_HEADER_TOO_MANY_LAYERS);
        return TM_ECODE_FAILED;
    }

    VLANHdr *vlan_hdr = (VLANHdr *)pkt;
    uint16_t proto = GET_VLAN_PROTO(vlan_hdr);

    // 存储 VLAN ID（12 位）
    p->vlan_id[p->vlan_idx] = GET_VLAN_ID(vlan_hdr);
    p->vlan_idx++;

    // 递归到下一层（可能又是 VLAN → QinQ）
    DecodeNetworkLayer(tv, dtv, proto, p,
            pkt + VLAN_HEADER_LEN, len - VLAN_HEADER_LEN);

    return TM_ECODE_OK;
}
```

**关键点**：

- `Packet.vlan_id[3]` 数组支持最多 3 层 VLAN 嵌套（VLAN + QinQ + QinQinQ）
- `vlan_idx` 记录当前 VLAN 层数
- 解析完 VLAN 头后回到 `DecodeNetworkLayer()`，形成递归结构

---

## 10. 隧道解码与伪包机制

### 10.1 隧道类型枚举

```c
// src/decode.h:1101-1113
enum DecodeTunnelProto {
    DECODE_TUNNEL_ETHERNET,
    DECODE_TUNNEL_ERSPANII,
    DECODE_TUNNEL_ERSPANI,
    DECODE_TUNNEL_VLAN,
    DECODE_TUNNEL_IPV4,
    DECODE_TUNNEL_IPV6,
    DECODE_TUNNEL_IPV6_TEREDO,
    DECODE_TUNNEL_PPP,
    DECODE_TUNNEL_NSH,
    DECODE_TUNNEL_ARP,
    DECODE_TUNNEL_UNSET
};
```

### 10.2 伪包创建：PacketTunnelPktSetup()

当解码器遇到隧道封装时，需要为内层数据包创建一个新的 `Packet` 对象（伪包），定义在 `src/decode.c:397-461`：

```c
Packet *PacketTunnelPktSetup(ThreadVars *tv, DecodeThreadVars *dtv, Packet *parent,
                             const uint8_t *pkt, uint32_t len, enum DecodeTunnelProto proto)
{
    // ① 层数检查
    if (parent->nb_decoded_layers + 1 >= decoder_max_layers) {
        ENGINE_SET_INVALID_EVENT(parent, GENERIC_TOO_MANY_LAYERS);
        return NULL;
    }

    // ② 从包池或 malloc 获取新 Packet
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL))
        return NULL;

    // ③ 复制内层数据到新 Packet 的缓冲区
    PacketCopyData(p, pkt, len);

    // ④ 设置递归层级和基本属性
    p->recursion_level = parent->recursion_level + 1;  // 递归层 +1
    p->nb_decoded_layers = parent->nb_decoded_layers + 1;
    p->ts = parent->ts;                                 // 继承时间戳
    p->datalink = DLT_RAW;                             // 内层默认无链路层
    p->tenant_id = parent->tenant_id;                   // 继承租户 ID
    p->livedev = parent->livedev;                       // 继承抓包设备

    // ⑤ 建立父子关系
    if (parent->root != NULL) {
        p->root = parent->root;       // 多层隧道：指向最底层（根）
    } else {
        p->root = parent;             // 第一层隧道：父即根
        parent->ttype = PacketTunnelRoot;
    }
    p->ttype = PacketTunnelChild;

    // ⑥ 解码内层协议
    int ret = DecodeTunnel(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), proto);

    // ⑦ 解码失败处理
    if (unlikely(ret != TM_ECODE_OK) ||
            (proto == DECODE_TUNNEL_IPV6_TEREDO && (p->flags & PKT_IS_INVALID))) {
        p->root = NULL;
        TmqhOutputPacketpool(tv, p);  // 释放回包池
        return NULL;
    }

    // ⑧ 更新隧道引用计数
    TUNNEL_INCR_PKT_TPR(p);

    // ⑨ 禁止父包的载荷检测
    DecodeSetNoPayloadInspectionFlag(parent);

    return p;
}
```

**核心流程图**：

```
外层包（parent）           内层包（child / 伪包）
┌──────────────────┐     ┌──────────────────┐
│ Ethernet         │     │                  │
│ IPv4             │     │ IPv4（内层）       │
│ GRE              │     │ TCP              │
│ [IPv4][TCP][HTTP]│────→│ [HTTP payload]   │
│                  │     │                  │
│ ttype = Root     │     │ ttype = Child    │
│ tunnel_tpr_cnt++ │     │ root → parent    │
│ NO_PAYLOAD_INSP  │     │ recursion_level+1│
└──────────────────┘     └──────────────────┘
         │                        │
         │                        ↓
         │               入队 decode_pq
         │               后续作为独立包处理
         ↓
   只做头部匹配
   （不检测载荷）
```

### 10.3 DecodeTunnel() — 隧道内层分发

```c
// src/decode.c:188-218
static int DecodeTunnel(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint32_t len, enum DecodeTunnelProto proto)
{
    switch (proto) {
        case DECODE_TUNNEL_PPP:
            return DecodePPP(tv, dtv, p, pkt, len);
        case DECODE_TUNNEL_IPV4:
            return DecodeIPV4(tv, dtv, p, pkt, (uint16_t)len);
        case DECODE_TUNNEL_IPV6:
        case DECODE_TUNNEL_IPV6_TEREDO:
            return DecodeIPV6(tv, dtv, p, pkt, (uint16_t)len);
        case DECODE_TUNNEL_VLAN:
            return DecodeVLAN(tv, dtv, p, pkt, len);
        case DECODE_TUNNEL_ETHERNET:
            return DecodeEthernet(tv, dtv, p, pkt, len);
        case DECODE_TUNNEL_ERSPANII:
            return DecodeERSPAN(tv, dtv, p, pkt, len);
        case DECODE_TUNNEL_ERSPANI:
            return DecodeERSPANTypeI(tv, dtv, p, pkt, len);
        case DECODE_TUNNEL_NSH:
            return DecodeNSH(tv, dtv, p, pkt, len);
        case DECODE_TUNNEL_ARP:
            return DecodeARP(tv, dtv, p, pkt, len);
        default:
            break;
    }
    return TM_ECODE_OK;
}
```

内层伪包复用与外层包完全相同的解码函数。换句话说，`DecodeIPV4()` 不关心自己处理的是原始包还是隧道解封装后的伪包——这就是递归解码的优雅之处。

### 10.4 隧道引用计数与判决

IPS 模式下，外层包和内层包的判决需要协调。Suricata 使用引用计数机制（`src/decode.h:1378-1415`）：

- `tunnel_tpr_cnt`：隧道内创建的伪包总数
- `tunnel_rtv_cnt`：已完成判决的伪包数

```c
// src/decode.h:1378-1396（简化）
static inline bool VerdictTunnelPacketInternal(const Packet *p)
{
    const uint16_t outstanding = TUNNEL_PKT_TPR(p) - TUNNEL_PKT_RTV(p);

    // 根包 + 没有未完成的子包 → 可以判决
    if (PacketIsTunnelRoot(p) && !PacketTunnelIsVerdicted(p) && !outstanding)
        return true;

    // 子包 + 是最后一个 + 根包已处理 → 可以判决
    if (PacketIsTunnelChild(p) && outstanding == 1 &&
            p->root && PacketTunnelIsVerdicted(p->root))
        return true;

    return false;
}
```

只有当所有子包都处理完毕后，才能对原始数据包（根包）做最终判决（ACCEPT/DROP）。

### 10.5 重组伪包：PacketDefragPktSetup()

IP 分片重组使用另一个伪包创建函数（`src/decode.c:477-508`），与隧道伪包的关键区别：

```c
Packet *PacketDefragPktSetup(Packet *parent, const uint8_t *pkt,
                              uint32_t len, uint8_t proto)
{
    ...
    p->recursion_level = parent->recursion_level; // 注意：不递增！
    ...
    memcpy(&p->vlan_id[0], &parent->vlan_id[0], sizeof(p->vlan_id));
    p->vlan_idx = parent->vlan_idx;               // 继承 VLAN 信息
    ...
}
```

重组伪包**不递增 `recursion_level`**，因为重组后的包与分片在同一逻辑层，需要进入相同的流查找。

---

## 11. GRE 解码

GRE（Generic Routing Encapsulation）是最常见的隧道协议之一，定义在 `src/decode-gre.c:47-280`。

### 11.1 版本处理

GRE 有两个版本：

```c
// src/decode-gre.c:70-201（简化）
switch (GRE_GET_VERSION(greh)) {
    case GRE_VERSION_0:   // RFC 1701/2784
        // 可选字段：Checksum、Key、Sequence、Routing
        if (GRE_FLAG_ISSET_KY(greh))    header_len += GRE_KEY_LEN;
        if (GRE_FLAG_ISSET_SQ(greh))    header_len += GRE_SEQ_LEN;
        if (GRE_FLAG_ISSET_CHKSUM(greh)) header_len += GRE_CHKSUM_LEN + GRE_OFFSET_LEN;
        // Routing 头处理（变长）
        if (GRE_FLAG_ISSET_ROUTE(greh)) {
            while (1) { /* 遍历 SRE 链 */ }
        }
        break;

    case GRE_VERSION_1:   // RFC 2637（PPTP 使用）
        // 必须包含 Key，协议必须是 PPP
        if (GRE_GET_PROTO(greh) != GRE_PROTO_PPP) {
            ENGINE_SET_INVALID_EVENT(p, GRE_VERSION1_WRONG_PROTOCOL);
            return TM_ECODE_OK;
        }
        header_len += GRE_KEY_LEN;
        if (GRE_FLAG_ISSET_SQ(greh))    header_len += GRE_SEQ_LEN;
        if (GREV1_FLAG_ISSET_ACK(greh)) header_len += GREV1_ACK_LEN;
        break;

    default:
        ENGINE_SET_INVALID_EVENT(p, GRE_WRONG_VERSION);
        return TM_ECODE_OK;
}
```

### 11.2 内层协议分发

GRE 头部解析完后，根据 Protocol Type 字段创建伪包：

```c
// src/decode-gre.c:203-278（简化）
switch (GRE_GET_PROTO(greh)) {
    case ETHERNET_TYPE_IP:          // IPv4-in-GRE
        tp = PacketTunnelPktSetup(tv, dtv, p, pkt + header_len,
                len - header_len, DECODE_TUNNEL_IPV4);
        break;
    case ETHERNET_TYPE_IPV6:        // IPv6-in-GRE
        tp = PacketTunnelPktSetup(..., DECODE_TUNNEL_IPV6);
        break;
    case GRE_PROTO_PPP:             // PPP-in-GRE（PPTP VPN）
        tp = PacketTunnelPktSetup(..., DECODE_TUNNEL_PPP);
        break;
    case ETHERNET_TYPE_VLAN:        // VLAN-in-GRE
        tp = PacketTunnelPktSetup(..., DECODE_TUNNEL_VLAN);
        break;
    case ETHERNET_TYPE_ERSPAN:      // ERSPAN（网络镜像）
        tp = PacketTunnelPktSetup(...,
                GRE_FLAG_ISSET_SQ(greh) == 0
                    ? DECODE_TUNNEL_ERSPANI      // Type I（无 Seq）
                    : DECODE_TUNNEL_ERSPANII);   // Type II（有 Seq）
        break;
    case ETHERNET_TYPE_BRIDGE:      // Transparent Ethernet Bridging
        tp = PacketTunnelPktSetup(..., DECODE_TUNNEL_ETHERNET);
        break;
}

if (tp != NULL) {
    PKT_SET_SRC(tp, PKT_SRC_DECODER_GRE);
    PacketEnqueueNoLock(&tv->decode_pq, tp);     // 伪包入队
}
```

---

## 12. VXLAN 解码

VXLAN（Virtual eXtensible LAN）是数据中心常用的 overlay 网络协议，定义在 `src/decode-vxlan.c`。

### 12.1 端口配置

```c
// src/decode-vxlan.c:50-53
static bool g_vxlan_enabled = true;
static int g_vxlan_ports[VXLAN_MAX_PORTS] = { VXLAN_DEFAULT_PORT, ... };
// 默认端口 4789，最多配置 4 个端口
```

通过 `decoder.vxlan.enabled` 和 `decoder.vxlan.ports` 配置：

```yaml
# suricata.yaml
decoder:
  vxlan:
    enabled: true
    ports: $VXLAN_PORTS     # 默认 4789
```

### 12.2 解码逻辑

```c
// src/decode-vxlan.c:122-178（简化）
int DecodeVXLAN(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint32_t len)
{
    // 基本验证
    if (len < (VXLAN_HEADER_LEN + sizeof(EthernetHdr)))
        return TM_ECODE_FAILED;
    if (!PacketIncreaseCheckLayers(p))
        return TM_ECODE_FAILED;

    const VXLANHeader *vxlanh = (const VXLANHeader *)pkt;

    // VXLAN 标志验证：I 位必须置 1，Reserved 必须为 0
    if ((vxlanh->flags[0] & 0x08) == 0 || vxlanh->res != 0)
        return TM_ECODE_FAILED;

    StatsIncr(tv, dtv->counter_vxlan);

    // 查看内层 Ethernet 帧的 EtherType，决定隧道类型
    EthernetHdr *ethh = (EthernetHdr *)(pkt + VXLAN_HEADER_LEN);
    uint16_t eth_type = SCNtohs(ethh->eth_type);

    int decode_tunnel_proto = DECODE_TUNNEL_UNSET;
    switch (eth_type) {
        case ETHERNET_TYPE_IP:    decode_tunnel_proto = DECODE_TUNNEL_IPV4; break;
        case ETHERNET_TYPE_IPV6:  decode_tunnel_proto = DECODE_TUNNEL_IPV6; break;
        case ETHERNET_TYPE_VLAN:  decode_tunnel_proto = DECODE_TUNNEL_VLAN; break;
        default:
            ENGINE_SET_INVALID_EVENT(p, VXLAN_UNKNOWN_PAYLOAD_TYPE);
    }

    // 创建伪包（跳过 VXLAN 头 + Ethernet 头）
    if (decode_tunnel_proto != DECODE_TUNNEL_UNSET) {
        Packet *tp = PacketTunnelPktSetup(tv, dtv, p,
                pkt + VXLAN_HEADER_LEN + ETHERNET_HEADER_LEN,
                len - VXLAN_HEADER_LEN - ETHERNET_HEADER_LEN,
                decode_tunnel_proto);
        if (tp != NULL) {
            PKT_SET_SRC(tp, PKT_SRC_DECODER_VXLAN);
            PacketEnqueueNoLock(&tv->decode_pq, tp);
        }
    }
    return TM_ECODE_OK;
}
```

**VXLAN 封装结构**：

```
外层 Ethernet | 外层 IP | 外层 UDP(4789) | VXLAN(8B) | 内层 Ethernet | 内层 IP | ...
                                                       ↑
                                                  伪包从这里开始解码
```

---

## 13. 完整解码流程图

以一个 GRE 隧道中的 TCP 数据包为例，展示完整的解码调用链：

```
DecodeLinkLayer(LINKTYPE_ETHERNET)
  └── DecodeEthernet()
        │  设置 p->l2 = Ethernet
        │  提取 EtherType = 0x0800
        └── DecodeNetworkLayer(0x0800)
              └── DecodeIPV4()           ← 外层 IPv4
                    │  设置 p->l3 = IPv4
                    │  提取 proto = 47 (GRE)
                    └── DecodeGRE()       ← GRE 隧道
                          │  设置 p->l4 = GRE
                          │  解析 GRE 头部字段
                          │  提取内层 Protocol = 0x0800
                          │
                          └── PacketTunnelPktSetup()    ← 创建伪包
                                │  分配新 Packet
                                │  复制内层数据
                                │  设置 root/child 关系
                                │
                                └── DecodeTunnel(DECODE_TUNNEL_IPV4)
                                      └── DecodeIPV4()   ← 内层 IPv4（伪包上）
                                            │  设置 p->l3 = IPv4
                                            │  提取 proto = 6 (TCP)
                                            └── DecodeTCP()
                                                  │  设置 p->l4 = TCP
                                                  │  解析选项
                                                  │  设置 payload
                                                  └── FlowSetupPacket()
```

**原始包（外层）**：只保留到 GRE 层的解码结果，载荷检测被禁止
**伪包（内层）**：包含完整的 IPv4 → TCP 解码结果，进入流处理和检测引擎

---

## 14. 解码器统一模式

纵观所有解码器，它们遵循一个统一的编码模式：

```c
int DecodeXxx(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
              const uint8_t *pkt, uint16_t len)
{
    // 1. 统计计数
    StatsIncr(tv, dtv->counter_xxx);

    // 2. 层数检查（部分解码器）
    if (!PacketIncreaseCheckLayers(p))
        return TM_ECODE_FAILED;

    // 3. 最小长度验证
    if (unlikely(len < XXX_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, XXX_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    // 4. 设置头指针（零拷贝）
    XxxHdr *hdr = PacketSetXxx(p, pkt);

    // 5. 协议特定验证
    // （版本号、头部长度、校验和等）

    // 6. 提取关键字段
    // （地址、端口号、协议号等）

    // 7. 分发到下一层 / 设置载荷
    switch (next_proto) {
        case PROTO_A: DecodeA(tv, dtv, p, data, data_len); break;
        case PROTO_B: DecodeB(tv, dtv, p, data, data_len); break;
    }

    // 8. 设置流查找标志（四层解码器）
    FlowSetupPacket(p);

    return TM_ECODE_OK;
}
```

**核心设计原则**：

| 原则 | 说明 |
|------|------|
| **防御性验证** | 每层都验证长度，绝不访问越界内存 |
| **事件优先于错误码** | 协议违规通过事件报告，不一定终止处理 |
| **零拷贝** | 头部指针直接指向 `pkt_data[]`，不复制数据 |
| **统一接口** | 所有解码器签名一致：`(tv, dtv, p, pkt, len)` |
| **递归解码** | 隧道包通过伪包机制复用相同的解码函数 |
| **层数保护** | `PacketIncreaseCheckLayers()` 防止无限递归 |

---

## 15. 实验：观察解码事件

### 15.1 触发解码事件

构造一个截断的 IPv4 包，观察 Suricata 如何报告：

```bash
# 使用 scapy 生成截断包
python3 -c "
from scapy.all import *
# 正常 IPv4 头但声明长度大于实际
pkt = IP(len=100)/TCP()  # 声明 100 字节但实际更短
wrpcap('/tmp/trunc.pcap', pkt)
"

# 运行 Suricata
suricata -r /tmp/trunc.pcap -l /tmp/suricata-test/ \
    -S /dev/null --set outputs.0.eve-log.types.0=anomaly
```

在 `eve.json` 中会看到：

```json
{
  "event_type": "anomaly",
  "anomaly": {
    "type": "decode",
    "event": "ipv4.trunc_pkt",
    "layer": "ipv4"
  }
}
```

### 15.2 查看解码统计

运行后查看 `stats.log`：

```bash
grep "decoder\." /tmp/suricata-test/stats.log | head -20
```

输出类似：

```
decoder.pkts                  | Total                 | 15234
decoder.bytes                 | Total                 | 8234567
decoder.ipv4                  | Total                 | 14890
decoder.ipv6                  | Total                 | 344
decoder.tcp                   | Total                 | 12456
decoder.udp                   | Total                 | 2100
decoder.vlan                  | Total                 | 0
decoder.gre                   | Total                 | 28
decoder.vxlan                 | Total                 | 0
decoder.invalid               | Total                 | 3
decoder.event.ipv4.trunc_pkt  | Total                 | 2
```

---

## 16. 配置选项

解码层的可配置项在 `suricata.yaml` 中：

```yaml
# 解码器配置
decoder:
  # 解码最大层数（防止嵌套攻击）
  max-layers: 16

  # Teredo 隧道
  teredo:
    enabled: true
    ports: $TEREDO_PORTS        # 默认 3544

  # VXLAN 隧道
  vxlan:
    enabled: true
    ports: $VXLAN_PORTS         # 默认 4789

  # Geneve 隧道
  geneve:
    enabled: true
    ports: $GENEVE_PORTS        # 默认 6081

  # ERSPAN
  erspan:
    typeI:
      enabled: true
```

---

## 17. 本篇小结与后续预告

本篇深入剖析了 Suricata 解码层的实现，核心知识点总结如下：

| 知识点 | 关键源码 |
|--------|---------|
| 分层数据结构 PacketL2/L3/L4 | `src/decode.h:414-482` |
| 事件机制 ENGINE_SET_EVENT | `src/decode.h:1186-1197` |
| 事件类型定义 | `src/decode-events.h:29-319` |
| 层数保护 PacketIncreaseCheckLayers | `src/decode.h:1330-1338` |
| Ethernet 解码 | `src/decode-ethernet.c:42-65` |
| 网络层分发 DecodeNetworkLayer | `src/decode.h:1455-1515` |
| IPv4 解码（含分片处理） | `src/decode-ipv4.c:520-622` |
| TCP 解码（含选项解析） | `src/decode-tcp.c:217-286` |
| UDP 解码（含隧道探测） | `src/decode-udp.c:45-117` |
| VLAN 解码 | `src/decode-vlan.c:54` |
| GRE 隧道解码 | `src/decode-gre.c:47-280` |
| VXLAN 隧道解码 | `src/decode-vxlan.c:122-178` |
| 隧道伪包创建 PacketTunnelPktSetup | `src/decode.c:397-461` |
| 隧道内层分发 DecodeTunnel | `src/decode.c:188-218` |
| 重组伪包创建 PacketDefragPktSetup | `src/decode.c:477-508` |
| 隧道判决协调 VerdictTunnelPacket | `src/decode.h:1378-1415` |

**后续文章预告**：

- **第 11 篇：流处理与 TCP 重组**：深入 `flow-hash.c` 和 `stream-tcp*.c`，了解流表的哈希实现、TCP 状态机和流重组算法
- **第 12 篇：应用层协议检测与解析**：深入 `app-layer-*.c`，理解协议自动检测（probing parser）和解析器框架

---

> **参考源码版本**：Suricata 8.0.3（commit: 3bd9f773b）
> **核心文件清单**：`src/decode.h`(1500+行), `src/decode.c`(530+行), `src/decode-ethernet.c`(180行), `src/decode-ipv4.c`(850+行), `src/decode-tcp.c`(680+行), `src/decode-udp.c`(200+行), `src/decode-vlan.c`(130行), `src/decode-gre.c`(350行), `src/decode-vxlan.c`(220行), `src/decode-events.h`(320行)
