---
title: "运行模式深入"
series: "Suricata 深度解析"
number: 04
author: ""
date: 2026-03-12
version: "Suricata 8.0.3"
keywords: [suricata, 运行模式, AF_PACKET, NFQueue, IDS, IPS, worker, autofp]
---

# 04 - 运行模式深入

> 运行模式决定了 Suricata 如何获取数据包、如何分配处理线程、是否拦截恶意流量。本文将深入对比各种运行模式的实现差异，从源码角度理解 worker 与 autofp 两种线程模型。

## 运行模式的两个维度

Suricata 的运行模式由两个维度组合决定：

**维度一：数据包来源（capture method）**

| 来源 | 枚举值 | 默认线程模型 | 典型场景 |
|------|--------|-------------|---------|
| AF_PACKET | `RUNMODE_AFP_DEV` | workers | Linux IDS/IPS |
| pcap live | `RUNMODE_PCAP_DEV` | workers | 跨平台 IDS |
| pcap file | `RUNMODE_PCAP_FILE` | autofp | 离线分析 |
| NFQueue | `RUNMODE_NFQ` | autofp | Linux IPS |
| DPDK | `RUNMODE_DPDK` | workers | 高速抓包 |
| AF_XDP | `RUNMODE_AFXDP_DEV` | workers | XDP 抓包 |
| Netmap | `RUNMODE_NETMAP` | workers | 高速抓包 |
| PF_RING | (via plugin) | workers | 高速抓包 |
| Unix Socket | `RUNMODE_UNIX_SOCKET` | autofp | 自动化分析 |

> **源码对应**：枚举定义在 `src/runmodes.h:27`。

**维度二：线程模型（threading model）**

| 模型 | 说明 |
|------|------|
| `workers` | 每个线程独立完成从抓包到输出的全部工作 |
| `autofp` | 抓包线程和处理线程分离，按流分发数据包 |
| `single` | 单线程完成所有工作（仅用于调试） |

## 线程模型深入

### 核心概念：TmSlot 管道

Suricata 的线程处理采用管道（pipeline）架构。整个线程由一系列 `TmSlot` 组成，数据包依次经过每个 slot 的处理函数：

```c
// src/tm-threads.h:53
typedef struct TmSlot_ {
    union {
        TmSlotFunc SlotFunc;                    // 普通处理函数
        TmEcode (*PktAcqLoop)(ThreadVars *, void *, void *);  // 抓包循环
        TmEcode (*Management)(ThreadVars *, void *);           // 管理任务
    };
    struct TmSlot_ *slot_next;                 // 下一个 slot（链表）
    int tm_id;                                  // 模块 ID
    TmEcode (*SlotThreadInit)(...);            // 线程初始化
    void (*SlotThreadExitPrintStats)(...);     // 退出时打印统计
    TmEcode (*SlotThreadDeinit)(...);          // 线程清理
} TmSlot;
```

### Workers 模式

Workers 模式是最简单高效的模型。每个线程独立运行完整的处理管道：

```
Workers 模式（以 AF_PACKET 为例）

线程 W#01-eth0:                线程 W#02-eth0:
┌─────────────┐               ─────────────┐
│ ReceiveAFP  │ (抓包)        │ ReceiveAFP  │ (抓包)
├─────────────┤               ├─────────────┤
│ DecodeAFP   │ (解码)        │ DecodeAFP   │ (解码)
├─────────────┤               ├─────────────┤
│ FlowWorker  │ (流+检测+输出) │ FlowWorker  │ (流+检测+输出)
├─────────────┤               ├─────────────┤
│RespondReject│ (IPS回应)     │RespondReject│ (IPS回应)
└─────────────┘               └─────────────┘
```

从源码看线程创建（`src/util-runmodes.c:245`）：

```c
// Workers 模式的线程管道构建
TmSlotSetFuncAppend(tv, recv_module, aconf);      // Slot 1: ReceiveAFP
TmSlotSetFuncAppend(tv, decode_module, NULL);      // Slot 2: DecodeAFP
TmSlotSetFuncAppend(tv, flowworker_module, NULL);  // Slot 3: FlowWorker
TmSlotSetFuncAppend(tv, reject_module, NULL);      // Slot 4: RespondReject
```

**优点**：
- 无线程间数据传递开销
- 每个线程的缓存命中率高（数据局部性好）
- 实现简单，调试容易

**缺点**：
- 每个线程都需要独立的检测引擎实例（内存开销更大）
- 流状态需要跨线程共享（通过流哈希表的锁）

**适用场景**：高速实时抓包（AF_PACKET、DPDK、Netmap）

### AutoFP 模式

AutoFP（Auto Flow Pinning）将收包和处理分离，按流将数据包分发到固定的处理线程：

```
AutoFP 模式（以 pcap file 为例）

收包线程 RX#01:
┌─────────────────┐
│ ReceivePcapFile │ (读取 pcap)
├─────────────────┤          ┌──────────── flow queue ────────────┐
│ DecodePcapFile  │ (解码)   │                                    │
└────────┬────────┘          │                                    │
         │                   ▼                                    ▼
         │          处理线程 W#01:                       处理线程 W#02:
         │          ┌─────────────┐                     ┌─────────────┐
         ├─────────▶│ FlowWorker  │ (流+检测+输出)      │ FlowWorker  │
         │ (按流    ├─────────────┤                     ├─────────────┤
         │  分发)   │RespondReject│                     │RespondReject│
         │          └─────────────┘                     └─────────────┘
         │                                                      ▲
         └──────────────────────────────────────────────────────┘
```

从源码看线程创建（`src/util-runmodes.c:85`）：

```c
// AutoFP 模式 - 收包线程
TmSlotSetFuncAppend(tv_receive, recv_module, aconf);   // ReceivePcapFile
TmSlotSetFuncAppend(tv_receive, decode_module, NULL);  // DecodePcapFile
// 输出到 flow queue（按流哈希分发到 pickup1, pickup2, ...）

// AutoFP 模式 - 处理线程
TmSlotSetFuncAppend(tv_detect, flowworker_module, NULL);  // FlowWorker
TmSlotSetFuncAppend(tv_detect, reject_module, NULL);      // RespondReject
```

**流分发机制**：收包线程解码后，根据数据包的五元组（src_ip, dst_ip, src_port, dst_port, proto）计算流哈希值，将同一流的所有数据包发送到同一个处理线程的队列中。这保证了同一连接的数据包总是由同一个线程处理，避免了流状态的并发竞争。

**优点**：
- 检测线程数量可独立于抓包线程调整
- 适合单一数据源利用多核处理的场景

**缺点**：
- 线程间队列带来额外的延迟和锁开销
- 某些大流量流可能导致处理线程负载不均

**适用场景**：离线分析（pcap file）、IPS 模式（NFQueue）

### IPS 模式的特殊之处

IPS（Intrusion Prevention System）模式需要对数据包做出裁决（accept/drop）。这引入了 Verdict 模块：

```
IPS 模式（NFQueue Workers）

线程 W-0:
┌─────────────┐
│ ReceiveNFQ  │  ← 从 iptables/nftables NFQueue 接收数据包
├─────────────┤
│ DecodeNFQ   │
├─────────────┤
│ FlowWorker  │  → 流处理 + 检测（判定 accept/drop）
├─────────────┤
│ VerdictNFQ  │  → 将裁决结果返回内核
├─────────────┤
│RespondReject│  → 发送 TCP RST / ICMP unreachable
└─────────────┘
```

IPS AutoFP 模式中，Verdict 线程独立运行：

```c
// src/util-runmodes.c:448 (IPS AutoFP)
// 处理线程输出到 verdict-queue
TmThreadCreatePacketHandler(tname, qname, "flow",
                            "verdict-queue", "simple",  // 输出到 verdict queue
                            "varslot");

// src/util-runmodes.c:487 (IPS AutoFP verdict thread)
// Verdict 线程从 verdict-queue 读取并返回裁决
TmSlotSetFuncAppend(tv_verdict, verdict_module, NULL);   // VerdictNFQ
TmSlotSetFuncAppend(tv_verdict, reject_module, NULL);    // RespondReject
```

## 各抓包方式详解

### AF_PACKET（Linux 推荐）

AF_PACKET 是 Linux 上的推荐抓包方式，直接从内核获取数据包副本。

**工作原理**：

```
网络接口 eth0
     │
     ▼
  NIC 驱动
     │
     ▼
  Linux 内核协议栈
     │
     ├──▶ 正常网络处理
     │
     └──▶ AF_PACKET socket（旁路抓包）
          │
          ├── mmap 环形缓冲区（零拷贝）
          │
          ├── TPACKET_V3（块级别）
          │
          ├── fanout（内核级流量分发）
          │   ├── PACKET_FANOUT_HASH（按流哈希）
          │   ├── PACKET_FANOUT_CPU（按 CPU）
          │   ├── PACKET_FANOUT_QM（按 RSS 队列）
          │   └── PACKET_FANOUT_EBPF（自定义 eBPF）
          │
          └──▶ Suricata 线程
```

**关键配置项**（`suricata.yaml` 中 `af-packet` 段）：

```yaml
af-packet:
  - interface: eth0
    threads: auto               # 线程数（auto = CPU 核心数）
    cluster-id: 99              # fanout 组 ID
    cluster-type: cluster_flow  # 分发方式
    defrag: yes                 # 内核态分片重组
    use-mmap: yes               # 使用 mmap（零拷贝）
    tpacket-v3: yes             # TPACKET_V3 协议版本
    ring-size: 2048             # 环形缓冲区帧数
    block-size: 32768           # 块大小
    block-timeout: 10           # 块超时（ms）
```

**cluster-type 对应源码**（`src/source-af-packet.c`）：

| 配置值 | 内核常量 | 说明 |
|--------|----------|------|
| `cluster_flow` | `PACKET_FANOUT_HASH` | 按流五元组哈希分发（推荐） |
| `cluster_cpu` | `PACKET_FANOUT_CPU` | 按 CPU 分发 |
| `cluster_qm` | `PACKET_FANOUT_QM` | 按 RSS 队列分发 |
| `cluster_ebpf` | `PACKET_FANOUT_EBPF` | 使用 eBPF 程序分发 |

**AF_PACKET IPS 模式**：

AF_PACKET 的 IPS 模式使用 `copy-mode` 实现。将两个接口配对，一个接收流量，一个转发流量。匹配 `drop` 规则的数据包不会被转发。

```yaml
af-packet:
  - interface: eth0
    copy-mode: ips          # ips 或 tap
    copy-iface: eth1        # 配对接口
  - interface: eth1
    copy-mode: ips
    copy-iface: eth0
```

源码中的 IPS 检测（`src/runmode-af-packet.c:69`）：

```c
static bool AFPRunModeIsIPS(void)
{
    // 检查所有接口的 copy-mode 配置
    // 如果任何接口配置了 copy-mode: ips，则启用 IPS 模式
    if (strcmp(copymodestr, "ips") == 0) {
        has_ips = true;
    }
    // 不允许混合 IPS 和 IDS 模式
    if (has_ids && has_ips) {
        SCLogError("using both IPS and TAP/IDS mode is not allowed");
        return false;
    }
}
```

### NFQueue（Linux IPS）

NFQueue 是 Linux 内核的数据包排队机制，允许用户态程序对数据包做出裁决。这是 Suricata 最常用的 IPS 方式。

**工作原理**：

```
网络流量
     │
     ▼
  iptables/nftables 规则
  -j NFQUEUE --queue-num 0
     │
     ▼
  内核 NFQueue
     │
     ▼
  Suricata（用户态）
     ├── 分析数据包
     ├── 匹配规则
     └── 返回裁决
         ├── NF_ACCEPT（放行）
         ├── NF_DROP（丢弃）
         └── NF_REPEAT（重新处理）
     │
     ▼
  继续内核协议栈处理
```

**配置步骤**：

```bash
# 1. 配置 iptables 将流量导入 NFQueue
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
# 或使用多队列（多线程）
sudo iptables -I FORWARD -j NFQUEUE --queue-balance 0:3

# 2. 启动 Suricata
suricata -c /etc/suricata/suricata.yaml -q 0
# 多队列
suricata -c /etc/suricata/suricata.yaml -q 0:3
```

**NFQueue 配置**：

```yaml
nfq:
  mode: accept                 # accept|repeat|route
  repeat-mark: 1               # repeat 模式的标记值
  repeat-mask: 1               # repeat 模式的掩码
  bypass-mark: 1               # bypass 标记
  bypass-mask: 1               # bypass 掩码
  route-queue: 2               # route 模式的目标队列
  batchcount: 20               # 批量处理数量
  fail-open: yes               # 队列满时放行流量（防止网络中断）
```

`fail-open` 是一个关键的安全/可用性权衡选项。生产环境中建议设为 `yes`，避免 Suricata 处理不过来时导致网络中断。

### pcap 实时抓包

pcap 是最通用的抓包方式，使用 libpcap 库，支持所有平台。

```yaml
pcap:
  - interface: eth0
    buffer-size: 16777216       # 16MB 缓冲区
    bpf-filter: "tcp or udp"   # BPF 过滤器
    checksum-checks: auto
    threads: auto
    promisc: yes                # 混杂模式
    snaplen: 1518               # 截断长度
```

pcap 模式性能不如 AF_PACKET，主要用于：
- 非 Linux 平台（macOS、Windows）
- 开发和调试
- 简单的测试场景

### pcap 文件（离线分析）

```bash
suricata -c suricata.yaml -r capture.pcap -l /tmp/output/
```

默认使用 `autofp` 模式（`src/runmode-pcap-file.c:37`）：

```c
const char *RunModeFilePcapGetDefaultMode(void)
{
    return "autofp";
}
```

**单线程模式的管道**（`src/runmode-pcap-file.c:53`）：

```c
// 单线程 pcap file 模式
TmSlotSetFuncAppend(tv, ReceivePcapFile, file);   // 读取 pcap
TmSlotSetFuncAppend(tv, DecodePcapFile, NULL);     // 解码
TmSlotSetFuncAppend(tv, FlowWorker, NULL);         // 流处理+检测+输出
```

**AutoFP 模式的管道**（`src/runmode-pcap-file.c:118`）：

```c
// 收包线程：ReceivePcapFile → DecodePcapFile → flow queue 分发
// 处理线程（N 个）：FlowWorker → RespondReject
```

### Unix Socket 模式

Unix Socket 模式允许通过命令行工具动态提交 pcap 文件进行分析，是自动化分析的理想选择。

```bash
# 启动 Unix Socket 模式
suricata -c suricata.yaml --unix-socket=/var/run/suricata/suricata-command.socket

# 使用 suricatasc 客户端
suricatasc
>>> pcap-file /path/to/file.pcap /var/log/suricata/
>>> pcap-file-list
>>> iface-stat
>>> shutdown
```

Unix Socket 模式的独特之处在于它可以：
- 动态提交多个 pcap 文件排队处理
- 每个文件可以指定不同的输出目录
- 支持多租户（tenant_id）
- 处理完一个文件后自动清理状态，准备处理下一个

源码中的文件队列结构（`src/runmode-unix-socket.c:63`）：

```c
typedef struct PcapFiles_ {
    char *filename;
    char *output_dir;
    uint32_t tenant_id;        // 多租户支持
    time_t delay;
    time_t poll_interval;
    bool continuous;
    bool should_delete;
    TAILQ_ENTRY(PcapFiles_) next;
} PcapFiles;
```

## 管理线程

除了数据处理线程，Suricata 还运行多个管理线程：

| 线程名 | 缩写 | 职责 | 源码 |
|--------|------|------|------|
| Flow Manager | FM | 流超时管理、过期流清理 | `src/flow-manager.c` |
| Flow Recycler | FR | 回收已关闭的流对象 | `src/flow-manager.c` |
| Flow Bypass | FB | 处理被 bypass 的流 | `src/flow-bypass.c` |
| Counter Stats | CS | 收集和输出性能统计 | `src/counters.c` |
| Counter Wakeup | CW | 定时唤醒统计线程 | `src/counters.c` |
| Detect Loader | DL | 热加载检测规则 | `src/detect-engine-loader.c` |
| Unix Socket | US | 处理 Unix Socket 命令 | `src/unix-manager.c` |
| Heartbeat | HB | 心跳管理 | `src/log-flush.c` |

线程名缩写定义（`src/runmodes.c:66`）：

```c
const char *thread_name_autofp = "RX";       // 收包线程
const char *thread_name_workers = "W";       // 工作线程
const char *thread_name_verdict = "TX";      // 裁决线程（IPS）
const char *thread_name_flow_mgr = "FM";     // 流管理
const char *thread_name_flow_rec = "FR";     // 流回收
const char *thread_name_flow_bypass = "FB";  // 流旁路
```

## FlowWorker：核心处理模块

无论使用哪种运行模式和线程模型，数据包的核心处理逻辑都在 `FlowWorker` 模块中。FlowWorker 整合了流处理、应用层解析、检测和输出：

```
FlowWorker 内部流程:

Packet
  │
  ▼
Flow Lookup（流查找/创建）
  │
  ▼
Stream TCP（TCP 重组）
  │
  ├── 重组后的数据传递给 App Layer
  │
  ▼
App Layer Parser（应用层协议解析）
  │
  ├── HTTP / DNS / TLS / SSH / ...
  │
  ▼
Detection（规则匹配）
  │
  ├── 预过滤 → MPM 匹配 → 全匹配
  │
  ▼
Output（日志输出）
  │
  ├── EVE JSON / fast.log / ...
  │
  ▼
Done
```

## 运行模式注册机制

所有运行模式在启动时通过 `RunModeRegisterRunModes()` 注册（`src/runmodes.c:231`）：

```c
void RunModeRegisterRunModes(void)
{
    RunModeIdsPcapRegister();           // pcap live
    RunModeFilePcapRegister();          // pcap file
    RunModeIpsNFQRegister();            // NFQueue
    RunModeIpsIPFWRegister();           // IPFW
    RunModeIdsAFPRegister();            // AF_PACKET
    RunModeIdsAFXDPRegister();          // AF_XDP
    RunModeIdsNetmapRegister();         // Netmap
    RunModeDpdkRegister();              // DPDK
    RunModeUnixSocketRegister();        // Unix Socket
    RunModeIpsWinDivertRegister();      // WinDivert
    // ...
}
```

每个注册函数调用 `RunModeRegisterNewRunMode()` 注册具体的子模式。以 AF_PACKET 为例（`src/runmode-af-packet.c:133`）：

```c
void RunModeIdsAFPRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "single",
        "Single threaded af-packet mode",
        RunModeIdsAFPSingle, AFPRunModeEnableIPS);

    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "workers",
        "Workers af-packet mode, each thread does all tasks",
        RunModeIdsAFPWorkers, AFPRunModeEnableIPS);

    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "autofp",
        "Multi socket AF_PACKET mode. Packets from each flow "
        "are assigned to a single detect thread.",
        RunModeIdsAFPAutoFp, AFPRunModeEnableIPS);
}
```

## 运行模式选择指南

### 场景对照表

| 场景 | 推荐模式 | 命令 |
|------|---------|------|
| Linux IDS（高速） | AF_PACKET + workers | `suricata -i eth0` |
| Linux IPS | NFQueue + autofp | `suricata -q 0` |
| Linux IPS（高速） | AF_PACKET IPS + workers | `suricata --af-packet` (配置 copy-mode) |
| macOS/Windows IDS | pcap + workers | `suricata -i en0` |
| 离线 pcap 分析 | pcap file + autofp | `suricata -r file.pcap` |
| 自动化批量分析 | unix socket + autofp | `suricata --unix-socket` |
| DPDK 高速抓包 | DPDK + workers | `suricata --dpdk` |
| 调试/开发 | 任意 + single | `suricata -i eth0 --runmode single` |

### 手动指定线程模型

```bash
# 使用 --runmode 参数覆盖默认线程模型
suricata -i eth0 --runmode workers     # 强制 workers 模式
suricata -i eth0 --runmode autofp      # 强制 autofp 模式
suricata -i eth0 --runmode single      # 强制单线程（调试用）
```

### 查看可用的运行模式

```bash
suricata --list-runmodes
```

输出示例：

```
PCAP_DEV:
  single - Single threaded pcap live mode
  workers - Workers pcap live mode
  autofp - Multi threaded pcap live mode

PCAP_FILE:
  single - Single threaded pcap file mode
  autofp - Multi-threaded pcap file mode

NFQ:
  autofp - Multi threaded NFQ IPS mode with respect to flow
  workers - Multi queue NFQ IPS mode with one thread per queue

AFP_DEV:
  single - Single threaded af-packet mode
  workers - Workers af-packet mode
  autofp - Multi socket AF_PACKET mode
```

## 实操：观察线程运行状态

### 通过 suricata.log

启动时的日志会显示线程创建信息：

```
<Notice> - all 4 packet processing threads, 4 management threads initialized
```

### 通过 stats.log

```bash
# 查看每个线程的包处理量
grep "capture.kernel_packets" /var/log/suricata/stats.log
```

### 通过 top/htop

```bash
# 查看 Suricata 线程
top -H -p $(pidof suricata)
```

你会看到类似以下线程：

```
W#01-eth0    (worker 线程 1)
W#02-eth0    (worker 线程 2)
W#03-eth0    (worker 线程 3)
W#04-eth0    (worker 线程 4)
FM#01        (flow manager)
FR#01        (flow recycler)
CS#01        (counter stats)
```

### 通过 Unix Socket

```bash
suricatasc -c "iface-list"
suricatasc -c "iface-stat eth0"
```

## IDS vs IPS 模式的安全考量

| 维度 | IDS 模式 | IPS 模式 |
|------|---------|---------|
| 流量影响 | 无（旁路监听） | 有（内联处理） |
| 丢包后果 | 漏检 | 漏检 + 漏拦 |
| 引擎崩溃后果 | 告警中断 | **网络中断**（如未配置 fail-open） |
| 性能要求 | 可容忍一定丢包 | 必须实时处理所有流量 |
| 规则动作 | `alert`（告警） | `alert` + `drop`（丢弃） + `reject`（拒绝） |

**IPS 部署注意事项**：

1. **fail-open 必须开启**：NFQueue 的 `fail-open: yes` 确保 Suricata 挂掉时不会断网
2. **充分测试**：先在 IDS 模式下运行一段时间，确认无误报后再切换到 IPS
3. **使用 `simulate-ips`**：`suricata --simulate-ips -i eth0` 可以模拟 IPS 行为但不实际丢包
4. **监控性能**：IPS 模式下任何性能瓶颈都可能导致网络延迟

## 小结

本文我们完成了：

- 理解运行模式的两个维度：数据包来源 × 线程模型
- 深入对比 workers 和 autofp 两种线程模型的实现差异
- 从源码理解 TmSlot 管道架构和 FlowWorker 核心处理模块
- 掌握 AF_PACKET、NFQueue、pcap、Unix Socket 四种主要运行方式
- 了解 IDS 和 IPS 模式的安全考量

## 下一篇预告

**05 - 规则编写进阶**

深入 Suricata 规则语法，覆盖多缓冲区匹配、flowbits 状态跟踪、datasets 数据集、Lua 脚本规则等进阶特性。
