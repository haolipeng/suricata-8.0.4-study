---
title: "性能调优实战"
series: "Suricata 深度解析"
number: 06
author: ""
date: 2026-03-12
version: "Suricata 8.0.3"
keywords: [suricata, 性能, CPU亲和性, 内存, Hyperscan, profiling, 调优]
---

# 06 - 性能调优实战

> Suricata 能否在 10Gbps 甚至 40Gbps 网络环境下稳定运行，关键在于正确的性能调优。本文深入源码，解析线程配置、CPU 亲和性、内存管理、Hyperscan 加速等核心调优手段。

## 性能瓶颈分析框架

在开始调优之前，需要明确瓶颈在哪里：

```
性能瓶颈排查流程

1. 是否丢包？
   └─ 检查 capture.kernel_drops（stats.log）

2. CPU 是否饱和？
   └─ 检查各工作线程 CPU 使用率（top -H）

3. 内存是否不足？
   └─ 检查 memcap 相关计数器

4. 规则是否低效？
   └─ 启用 rule profiling

5. 应用层解析是否成为瓶颈？
   └─ 检查 app_layer 统计
```

### 关键性能指标

```bash
# 查看丢包率
grep "capture.kernel_drops" /var/log/suricata/stats.log | tail -1

# 查看各线程处理的包数
grep "capture.kernel_packets" /var/log/suricata/stats.log | tail -1

# 查看流表状态
grep "flow\." /var/log/suricata/stats.log | tail -20
```

## 线程配置

### 线程数量

线程数量是最基础的性能参数。在 workers 模式下，线程数通常等于 AF_PACKET 的线程数。

**suricata.yaml 配置**：

```yaml
af-packet:
  - interface: eth0
    threads: auto    # auto = CPU 核心数
    # 或手动指定
    # threads: 4
```

`auto` 模式下，线程数来自配置解析。每个线程对应一个独立的 AF_PACKET socket。

**一般建议**：
- workers 线程数 = 可用 CPU 核心数 - 预留给管理线程的核心数
- 通常预留 1-2 个核心给管理线程（FM、FR、CS 等）
- NUMA 感知：尽量将线程绑定到与网卡同一 NUMA 节点的 CPU

### detect-thread-ratio

在 autofp 模式下，`detect-thread-ratio` 控制检测线程数与 CPU 核心数的比例（`src/runmodes.c:952`）：

```yaml
threading:
  detect-thread-ratio: 1.0    # 默认值
```

```c
// src/runmodes.c:970
SCConfGetFloat("threading.detect-thread-ratio", &threading_detect_ratio);
// 检测线程数 = ncpus * threading_detect_ratio
```

通常不需要修改此值。如果 CPU 支持超线程，可以考虑设为 1.5。

### 线程栈大小

```yaml
threading:
  stack-size: 8mb   # 默认值，通常不需要修改
```

Lua 规则或复杂的应用层解析可能需要更大的栈空间。

## CPU 亲和性

CPU 亲和性（affinity）将特定线程绑定到特定 CPU 核心，减少上下文切换和缓存失效。

### 亲和性配置结构

Suricata 定义了四类 CPU 集合（`src/util-affinity.h:56`）：

```c
enum {
    RECEIVE_CPU_SET,     // 收包线程（autofp 模式的 RX 线程）
    WORKER_CPU_SET,      // 工作线程
    VERDICT_CPU_SET,     // 裁决线程（IPS 模式）
    MANAGEMENT_CPU_SET,  // 管理线程
    MAX_CPU_SET
};
```

亲和性模式（`src/util-affinity.h:64`）：

```c
enum {
    BALANCED_AFFINITY,   // 平衡分配：线程在指定 CPU 集合中轮询分配
    EXCLUSIVE_AFFINITY,  // 独占分配：每个线程独占一个 CPU 核心
    MAX_AFFINITY
};
```

### 配置示例

**基础配置（推荐起点）**：

```yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    management-cpu-set:
      cpu: [0]               # 管理线程绑定到 CPU 0
    receive-cpu-set:
      cpu: [0]               # autofp 模式的收包线程
    worker-cpu-set:
      cpu: [1-7]             # 工作线程绑定到 CPU 1-7
      mode: exclusive        # 每个线程独占一个核心
      prio:
        default: high
```

**NUMA 感知配置（双路服务器）**：

假设网卡在 NUMA 节点 0，CPU 0-7 属于 NUMA 0，CPU 8-15 属于 NUMA 1：

```yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    management-cpu-set:
      cpu: [0]
    worker-cpu-set:
      cpu: [1-7]             # 只使用与网卡同 NUMA 节点的 CPU
      mode: exclusive
      prio:
        default: high
```

查看 NUMA 拓扑：

```bash
# 查看网卡所在 NUMA 节点
cat /sys/class/net/eth0/device/numa_node

# 查看 CPU 与 NUMA 的映射
lscpu | grep NUMA

# 使用 lstopo（需要 hwloc）
lstopo --no-io
```

### 按接口配置亲和性

当有多个网卡时，可以为每个接口单独配置 CPU 亲和性：

```yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    management-cpu-set:
      cpu: [0]
    worker-cpu-set:
      cpu: ["all"]
      mode: exclusive
      prio:
        default: high
      interface:
        eth0:
          cpu: [1-4]
        eth1:
          cpu: [5-8]
```

### 中断亲和性

仅配置 Suricata 的 CPU 亲和性还不够，网卡中断也需要绑定到对应的 CPU：

```bash
# 查看网卡中断
cat /proc/interrupts | grep eth0

# 设置 IRQ 亲和性（将中断分配到 CPU 1-7）
# 假设 eth0 有 8 个队列，IRQ 为 30-37
for i in $(seq 30 37); do
    echo $((i-29)) > /proc/irq/$i/smp_affinity_list
done

# 或使用 irqbalance（自动平衡）
systemctl stop irqbalance
# 然后手动配置
```

**理想的 CPU 分配**：

```
CPU 0: 管理线程 (FM, FR, CS, CW)
CPU 1: eth0 IRQ 队列 0 + Suricata W#01-eth0
CPU 2: eth0 IRQ 队列 1 + Suricata W#02-eth0
CPU 3: eth0 IRQ 队列 2 + Suricata W#03-eth0
...
```

## 内存管理

### 关键内存池（Memcap）

Suricata 使用多个内存池来控制资源使用，每个都有可配置的上限：

```yaml
# 流表内存
flow:
  memcap: 128mb          # 流表总内存上限
  hash-size: 65536       # 流哈希表大小
  prealloc: 10000        # 预分配流对象数量

# TCP 流重组
stream:
  memcap: 64mb           # TCP 会话跟踪内存
  reassembly:
    memcap: 256mb        # TCP 重组缓冲区内存
    depth: 1mb           # 单流重组深度上限

# 应用层内存
app-layer:
  protocols:
    http:
      memcap: 64mb       # HTTP 解析器内存
```

### Memcap 监控

```bash
# 查看 memcap 告警
grep "memcap" /var/log/suricata/stats.log

# 关键指标
# flow.memcap            - 流表 memcap 命中次数
# tcp.memcap             - TCP memcap 命中次数
# tcp.reassembly_memcap  - 重组 memcap 命中次数
```

当 memcap 计数器持续增长，说明内存不足，需要增大对应的 memcap 值。

### 异常策略（Exception Policy）

当 memcap 耗尽时，Suricata 需要决定如何处理新的数据包。异常策略提供了灵活的配置：

```yaml
# 全局异常策略
exception-policy: auto

# 或针对不同场景分别配置
stream:
  memcap-exception-policy: pass-flow   # memcap 满时放行
  reassembly:
    memcap-exception-policy: pass-flow

flow:
  memcap-exception-policy: pass-flow
```

可用的策略：

| 策略 | 说明 | IDS | IPS |
|------|------|-----|-----|
| `pass-packet` | 放行当前包 | Y | Y |
| `pass-flow` | 放行整个流 | Y | Y |
| `bypass-flow` | 旁路整个流 | Y | Y |
| `drop-packet` | 丢弃当前包 | N | Y |
| `drop-flow` | 丢弃整个流 | N | Y |
| `reject` | 拒绝并发送 RST | Y | Y |

### 流表调优

```yaml
flow:
  memcap: 128mb
  hash-size: 65536         # 应为 2 的幂
  prealloc: 10000          # 预分配减少运行时 malloc
  emergency-recovery: 30   # 紧急模式下的流回收百分比

  timeouts:
    default:
      new: 30              # 新建流超时
      established: 300     # 已建立流超时
      closed: 0            # 已关闭流超时
      bypassed: 100        # 被旁路流超时
      emergency-new: 10    # 紧急模式下的超时
      emergency-established: 100
      emergency-closed: 0
      emergency-bypassed: 50
```

**hash-size 选择原则**：
- 应接近预期的并发流数量
- 过小会导致哈希冲突增加，降低查找效率
- 过大会浪费内存
- 经验值：10Gbps 网络可设为 `1048576`（1M）

### max-pending-packets

```yaml
max-pending-packets: 1024   # 默认值
```

这个参数控制 Suricata 内部数据包池的大小。每个数据包对象约占几 KB 内存。

- 设置过低：高流量时包池耗尽，导致丢包
- 设置过高：浪费内存
- 高流量环境建议：`10000` - `65534`

## Hyperscan 加速

Intel Hyperscan 是一个高性能正则表达式匹配引擎，可以显著提升 Suricata 的规则匹配性能。

### 编译启用

```bash
# 安装 Hyperscan 开发库
# Ubuntu/Debian
sudo apt-get install libhyperscan-dev

# CentOS/RHEL
sudo yum install hyperscan-devel

# 编译 Suricata 时指定
./configure --with-libhs-includes=/usr/include/hs \
            --with-libhs-libraries=/usr/lib/x86_64-linux-gnu
```

### Hyperscan 在 Suricata 中的使用

Suricata 使用 Hyperscan 作为 MPM（Multi-Pattern Matcher）引擎。MPM 是规则匹配的预过滤阶段，从数据包负载中搜索所有规则的 fast pattern 内容。

```yaml
# 在 suricata.yaml 中设置 MPM 算法
mpm-algo: hs           # 使用 Hyperscan
# 其他选项: ac (Aho-Corasick), ac-bs, ac-ks

# 同样可以配置 SPM（Single Pattern Matcher）
spm-algo: hs
```

### Hyperscan vs Aho-Corasick

| 维度 | Hyperscan | Aho-Corasick (AC) |
|------|-----------|-------------------|
| 编译时间 | 较长（JIT 编译） | 较短 |
| 运行时性能 | 优秀（利用 SIMD 指令） | 良好 |
| 内存使用 | 较高（编译后的数据库） | 中等 |
| PCRE 支持 | 部分（需兼容子集） | 不支持 |
| 平台 | x86 with SSE4.2+ | 全平台 |

### Prefilter

Suricata 的 prefilter 机制允许非 content 关键字也参与预过滤阶段，减少全匹配的次数：

```yaml
# 启用默认的 prefilter 引擎
detect:
  prefilter:
    default: mpm          # 使用 MPM 做预过滤
```

## Profiling 工具

### 编译选项

```bash
# 启用规则级 profiling
./configure --enable-profiling-rules

# 启用锁 profiling（排查锁竞争）
./configure --enable-profiling-locks

# 启用通用 profiling
./configure --enable-profiling
```

### 规则 Profiling

```yaml
profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
    sort: avgticks          # 按平均 CPU 周期排序
    limit: 100              # 输出前 100 条
    json: yes               # 同时输出 JSON 格式
```

输出示例（`rule_perf.log`）：

```
  Num      Rule         Gid      Rev      Ticks        %      Checks   Matches  Max Ticks
  -------- ------------ -------- -------- ------------ ------ -------- -------- ----------
  1        2100498      1        7        1500000      15.00  50000    200      30000
  2        2100366      1        8        800000       8.00   30000    50       25000
  3        2100367      1        3        600000       6.00   25000    100      22000
```

**关注指标**：
- `Ticks`：总 CPU 周期消耗
- `Checks`：规则被检查的次数（预过滤后的全匹配次数）
- `Matches`：实际匹配次数
- Checks 很高但 Matches 很低的规则可能需要优化 fast pattern

### 关键字 Profiling

```yaml
profiling:
  keywords:
    enabled: yes
    filename: keyword_perf.log
    append: yes
```

### 数据包 Profiling

```yaml
profiling:
  packets:
    enabled: yes
    filename: packet_stats.log
    append: yes
    csv:
      enabled: no
      filename: packet_stats.csv
```

### 锁 Profiling

```yaml
profiling:
  locks:
    enabled: yes
    filename: lock_stats.log
    append: yes
```

锁 profiling 帮助识别锁竞争热点，在高并发场景下非常有用。

## 系统级调优

### 网卡优化

```bash
# 增大网卡接收缓冲区
ethtool -G eth0 rx 4096

# 启用网卡多队列
ethtool -L eth0 combined 8

# 关闭网卡 offload（让 Suricata 看到原始数据包）
ethtool -K eth0 rx off tx off gro off lro off

# 但保留校验和 offload
ethtool -K eth0 rx-checksum on

# 查看网卡统计
ethtool -S eth0 | grep -i drop
```

### 内核参数

```bash
# /etc/sysctl.conf

# 增大接收缓冲区
net.core.rmem_max = 67108864
net.core.rmem_default = 33554432
net.core.netdev_max_backlog = 250000

# 增大 conntrack 表（如果使用 NFQueue）
net.netfilter.nf_conntrack_max = 1048576

# 启用 NAPI
# （通常默认启用）

# 大页内存（用于 DPDK）
vm.nr_hugepages = 1024
```

### CPU 频率管理

```bash
# 固定 CPU 频率为最高（避免频率缩放带来的性能波动）
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance > $cpu
done

# 或使用 cpupower
cpupower frequency-set -g performance
```

### NUMA 优化

```bash
# 查看 NUMA 拓扑
numactl --hardware

# 将 Suricata 绑定到网卡所在的 NUMA 节点
numactl --cpunodebind=0 --membind=0 suricata -c suricata.yaml -i eth0
```

## 流量旁路（Flow Bypass）

对于已经确认安全的大流量连接（如视频流），可以使用 flow bypass 跳过检测：

```yaml
# 启用 bypass
stream:
  bypass: true

# eBPF bypass（内核层面跳过）
af-packet:
  - interface: eth0
    ebpf-filter-file: /etc/suricata/ebpf/bypass_filter.bpf
```

bypass 的效果是将已匹配的流直接在内核层面转发，不再经过用户态处理。

## 实战调优检查清单

```
□ 确认 workers 模式（高速场景）
□ 线程数 = 可用核心数 - 2
□ CPU 亲和性已配置，工作线程独占核心
□ 网卡 IRQ 亲和性与工作线程对齐
□ 网卡 offload 已正确配置
□ max-pending-packets 已根据流量调整
□ flow hash-size 已根据并发连接数调整
□ memcap 值已根据可用内存调整
□ 异常策略已配置（memcap 满时的行为）
□ Hyperscan 已启用（如有 Intel CPU）
□ 规则 profiling 已运行，低效规则已优化
□ 系统 sysctl 已调优
□ CPU 频率固定为 performance
□ NUMA 亲和性已配置
□ 丢包率在可接受范围内
```

## 小结

本文覆盖了：

- 线程数量与 detect-thread-ratio 配置
- CPU 亲和性与 NUMA 感知配置
- 内存池（memcap）管理与异常策略
- Hyperscan 加速与 MPM 选择
- Profiling 工具（规则、关键字、包、锁）
- 系统级调优（网卡、内核、CPU 频率）
- 流量旁路优化

## 下一篇预告

**07 - EVE JSON 日志与 ELK 集成**

深入 EVE 日志格式，了解每种事件类型的字段含义，配置 Logstash 管道解析 Suricata 日志，构建 Kibana 可视化仪表盘。
