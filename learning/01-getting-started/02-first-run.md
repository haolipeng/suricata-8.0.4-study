# 02 - 快速上手：第一次运行 Suricata

> 上一篇我们完成了源码编译。本文将实际运行 Suricata，处理第一个 pcap 文件，理解命令行参数体系、运行模式和输出格式。所有操作可在 Docker 实验环境中复现。

## 命令行参数总览

Suricata 的命令行参数分为六大类。理解这些参数是使用 Suricata 的基础，也是后续源码分析的入口——每个参数都对应 `src/suricata.c` 中 `SCParseCommandLine` 函数的一段处理逻辑。

### 通用参数

| 参数 | 说明 |
|------|------|
| `-c <path>` | 指定配置文件路径 |
| `-l <dir>` | 指定日志输出目录（覆盖配置文件中的 `default-log-dir`） |
| `-v` | 增加日志详细级别（可叠加：`-vvv`） |
| `-T` | 测试配置文件是否有效（不启动引擎） |
| `-D` | 以守护进程方式运行（Linux） |
| `-V` | 显示版本号 |
| `--include <path>` | 加载额外的配置文件 |
| `--set name=value` | 在命令行覆盖配置项 |
| `--pidfile <file>` | 写入 PID 文件 |
| `--init-errors-fatal` | 规则加载出错时直接退出 |
| `--user <user>` | 初始化后切换到指定用户（需 libcap-ng） |
| `--group <group>` | 初始化后切换到指定用户组 |
| `--build-info` | 显示构建信息（编译选项、启用功能、依赖版本） |
| `--dump-config` | 打印运行时完整配置 |
| `--dump-features` | 打印引擎支持的特性 |

### 抓包与 IPS 模式

| 参数 | 说明 |
|------|------|
| `-i <dev>` | 在指定网络接口上实时抓包（使用 AF_PACKET 或 pcap） |
| `--pcap[=<dev>]` | pcap 实时抓包模式 |
| `--af-packet[=<dev>]` | AF_PACKET 模式（Linux 高性能抓包） |
| `--af-xdp[=<dev>]` | AF_XDP 模式（基于 XDP 的高性能抓包） |
| `--netmap[=<dev>]` | Netmap 模式 |
| `--pfring[=<dev>]` | PF_RING 模式 |
| `--dpdk` | DPDK 模式 |
| `-q <qid[:qid]>` | NFQueue IPS 模式（指定队列 ID 或范围） |
| `-F <file>` | 从文件加载 BPF 过滤器 |
| `-k [all\|none]` | 强制启用/禁用校验和检查 |
| `--reject-dev <dev>` | 指定发送 reject 包的接口 |
| `--simulate-ips` | 模拟 IPS 模式（用于测试） |

### 离线文件处理

| 参数 | 说明 |
|------|------|
| `-r <path>` | 读取 pcap 文件（离线分析模式） |
| `--pcap-file-continuous` | 持续监控目录中的新 pcap 文件 |
| `--pcap-file-delete` | 处理完后删除 pcap 文件 |
| `--pcap-file-recursive` | 递归处理子目录中的 pcap 文件 |
| `--pcap-file-buffer-size` | 设置读取缓冲区大小 |
| `--erf-in <path>` | 处理 ERF 格式文件 |

### 检测相关

| 参数 | 说明 |
|------|------|
| `-s <path>` | 额外加载指定规则文件（追加到配置文件中的规则） |
| `-S <path>` | 仅加载指定规则文件（忽略配置文件中的规则） |
| `--disable-detection` | 禁用检测引擎（仅做协议解析和日志记录） |
| `--engine-analysis` | 分析引擎配置并生成报告 |
| `--strict-rule-keywords[=all]` | 严格检查规则关键字 |

### 信息查询

| 参数 | 说明 |
|------|------|
| `--list-keywords[=all\|csv\|<kw>]` | 列出支持的检测关键字 |
| `--list-runmodes` | 列出支持的运行模式 |
| `--list-app-layer-protos` | 列出支持的应用层协议 |
| `--list-app-layer-hooks` | 列出规则可用的应用层钩子 |
| `--list-app-layer-frames` | 列出支持的应用层帧类型 |

### 测试参数

| 参数 | 说明 |
|------|------|
| `-u` | 运行内置单元测试 |
| `-U=REGEX` | 用正则表达式过滤要运行的单元测试 |
| `--list-unittests` | 列出所有单元测试 |
| `--fatal-unittests` | 测试失败时立即终止 |

### Unix Socket 控制

| 参数 | 说明 |
|------|------|
| `--unix-socket[=<file>]` | 启用 Unix Socket 控制模式 |

> **源码对应**：所有参数定义在 `src/suricata.c:1397` 的 `long_opts[]` 数组中，处理逻辑在 `SCParseCommandLine` 函数（`src/suricata.c:1483`）。

## 运行模式概览

Suricata 支持多种运行模式，每种模式对应不同的使用场景。从源码角度看，运行模式在 `src/runmodes.c` 中注册，由枚举类型定义：

```
实时抓包 IDS 模式                       离线分析模式
┌──────────────────┐                   ┌──────────────────┐
│  -i ens33         │                   │  -r file.pcap    │
│  --af-packet     │                   │  --erf-in        │
│  --pcap          │                   │  --unix-socket   │
│  --pfring        │                   │    (pcap-file)   │
│  --dpdk          │                   └──────────────────┘
│  --netmap        │
│  --af-xdp        │                   IPS 内联模式
└──────────────────┘                   ┌──────────────────┐
                                       │  -q (NFQueue)    │
                                       │  -d (IPFW)       │
                                       │  --windivert     │
                                       │  --simulate-ips  │
                                       └──────────────────┘
```

### IDS 模式（被动监听）

最常见的模式。Suricata 从网络接口或镜像端口抓包，分析后生成告警日志，不影响网络流量。

```bash
# AF_PACKET 模式（Linux 推荐）
suricata -c /etc/suricata/suricata.yaml -i ens33

# 等价写法
suricata -c /etc/suricata/suricata.yaml --af-packet=ens33
```

### IPS 模式（内联阻断）

流量经过 Suricata 引擎，匹配到 `drop` 动作的规则时可以直接丢弃数据包。

```bash
# NFQueue 模式（需要 iptables 配合）
suricata -c /etc/suricata/suricata.yaml -q 0

# iptables 将流量导入 NFQueue
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```

### 离线分析模式（pcap 文件）

对 pcap 文件进行离线分析，是学习和开发时最常用的模式。

```bash
suricata -c /etc/suricata/suricata.yaml -r capture.pcap
```

### Unix Socket 模式

通过 Unix Socket 接收控制命令，可以动态提交 pcap 文件、重载规则等。常用于自动化分析场景。

```bash
# 启动 Unix Socket 模式
suricata -c /etc/suricata/suricata.yaml --unix-socket

# 用 suricatasc 客户端交互
suricatasc -c "pcap-file /path/to/file.pcap /var/log/suricata"
```

## 第一次运行：处理 pcap 文件

下面我们在 Docker 环境中实际操作。

### 步骤 1：进入实验环境

```bash
cd docs/docker
docker compose run --rm suricata-lab
```

### 步骤 2：准备测试 pcap

如果没有现成的 pcap 文件，可以用 tcpdump 快速抓一个：

```bash
# 在容器内抓几秒钟的流量（如果有网络连接）
tcpdump -i any -c 100 -w /tmp/test.pcap

# 或者用 Suricata 自带的测试方式——直接处理一个简单的 pcap
# 如果没有 pcap 文件，我们可以先验证 Suricata 是否正常启动
suricata --build-info
```

### 步骤 3：运行 Suricata

```bash
# 用离线模式处理 pcap 文件
suricata -c /etc/suricata/suricata.yaml -r /tmp/test.pcap -l /tmp/suricata-output/

# 参数解释：
# -c  指定配置文件
# -r  指定 pcap 文件（离线模式）
# -l  指定日志输出目录
```

### 步骤 4：查看输出

Suricata 处理完成后，会在日志目录生成多个文件：

```bash
ls -la /tmp/suricata-output/
```

典型输出文件：

| 文件 | 说明 |
|------|------|
| `eve.json` | **核心输出**：EVE JSON 格式，包含所有事件（告警、流、协议日志等） |
| `fast.log` | 快速告警日志（一行一条告警，便于快速查看） |
| `stats.log` | 引擎运行统计信息 |
| `suricata.log` | 引擎运行日志（启动、错误、关闭信息） |

### 步骤 5：解读 EVE JSON

EVE (Extensible Event Format) JSON 是 Suricata 的主要输出格式。每行一个 JSON 对象，通过 `event_type` 字段区分事件类型。

```bash
# 查看所有事件类型
cat /tmp/suricata-output/eve.json | jq -r '.event_type' | sort | uniq -c | sort -rn
```

常见的 `event_type`：

| 类型 | 说明 |
|------|------|
| `alert` | 规则匹配告警 |
| `flow` | 流记录（每个网络连接一条） |
| `http` | HTTP 事务日志 |
| `dns` | DNS 查询和应答 |
| `tls` | TLS 握手信息（SNI、证书等） |
| `fileinfo` | 文件元信息（从流量中提取的文件） |
| `smtp` | SMTP 邮件会话 |
| `ssh` | SSH 会话信息 |
| `stats` | 引擎性能统计 |
| `anomaly` | 协议异常 |
| `drop` | IPS 模式下丢弃的数据包 |

#### alert 事件示例

```json
{
  "timestamp": "2026-03-12T10:30:00.000000+0800",
  "flow_id": 1234567890,
  "in_iface": "ens33",
  "event_type": "alert",
  "src_ip": "10.0.0.1",
  "src_port": 12345,
  "dest_ip": "192.168.1.100",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2100498,
    "rev": 7,
    "signature": "GPL ATTACK_RESPONSE id check returned root",
    "category": "Potentially Bad Traffic",
    "severity": 2
  },
  "flow": {
    "pkts_toserver": 5,
    "pkts_toclient": 3,
    "bytes_toserver": 500,
    "bytes_toclient": 300,
    "start": "2026-03-12T10:29:59.000000+0800"
  }
}
```

关键字段含义：

- `timestamp`：事件发生时间
- `flow_id`：流 ID，同一连接的所有事件共享此 ID（用于关联分析）
- `src_ip` / `dest_ip`：源和目的 IP
- `alert.signature_id`（SID）：规则编号
- `alert.action`：动作（`allowed` 表示 IDS 模式下仅告警，`blocked` 表示 IPS 模式下已阻断）
- `alert.severity`：严重级别（1=高 2=中 3=低）

#### flow 事件示例

```json
{
  "timestamp": "2026-03-12T10:35:00.000000+0800",
  "event_type": "flow",
  "src_ip": "10.0.0.1",
  "dest_ip": "192.168.1.100",
  "proto": "TCP",
  "app_proto": "http",
  "flow": {
    "pkts_toserver": 10,
    "pkts_toclient": 8,
    "bytes_toserver": 1500,
    "bytes_toclient": 45000,
    "start": "2026-03-12T10:29:59.000000+0800",
    "end": "2026-03-12T10:34:59.000000+0800",
    "state": "closed",
    "reason": "timeout"
  },
  "tcp": {
    "tcp_flags": "1f",
    "tcp_flags_ts": "1b",
    "tcp_flags_tc": "1b",
    "syn": true,
    "fin": true,
    "psh": true,
    "ack": true
  }
}
```

#### http 事件示例

```json
{
  "event_type": "http",
  "http": {
    "hostname": "example.com",
    "url": "/index.html",
    "http_user_agent": "Mozilla/5.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 1234,
    "http_content_type": "text/html"
  }
}
```

### 用 jq 快速分析 EVE JSON

```bash
# 查看所有告警
cat eve.json | jq 'select(.event_type=="alert")'

# 只看告警的签名名称和 SID
cat eve.json | jq 'select(.event_type=="alert") | {sid: .alert.signature_id, msg: .alert.signature}'

# 查看所有 HTTP 请求
cat eve.json | jq 'select(.event_type=="http") | {host: .http.hostname, url: .http.url, method: .http.http_method}'

# 查看所有 DNS 查询
cat eve.json | jq 'select(.event_type=="dns") | {query: .dns.rrname, type: .dns.rrtype}'

# 按告警数量排名
cat eve.json | jq -r 'select(.event_type=="alert") | .alert.signature' | sort | uniq -c | sort -rn | head

# 查看某个 flow_id 的所有关联事件
cat eve.json | jq 'select(.flow_id==1234567890)'

# 统计各协议的流量
cat eve.json | jq -r 'select(.event_type=="flow") | .app_proto' | sort | uniq -c | sort -rn
```

## fast.log 格式

`fast.log` 是传统的一行一告警格式，适合快速浏览：

```
03/12/2026-10:30:00.000000  [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 10.0.0.1:12345 -> 192.168.1.100:80
```

格式拆解：

```
时间戳  [**] [gid:sid:rev] 签名描述 [**] [Classification: 分类] [Priority: 优先级] {协议} 源IP:源端口 -> 目的IP:目的端口
```

## 常用实操场景

### 场景 1：快速测试配置是否有效

```bash
suricata -T -c /etc/suricata/suricata.yaml
# 输出 "Configuration provided was successfully loaded" 表示配置有效
```

### 场景 2：只用特定规则文件

```bash
# -S 表示"仅使用这个规则文件"（忽略 suricata.yaml 中配置的规则）
suricata -c /etc/suricata/suricata.yaml -S my-rules.rules -r test.pcap

# -s 表示"额外加载这个规则文件"（追加到配置文件中的规则）
suricata -c /etc/suricata/suricata.yaml -s extra-rules.rules -r test.pcap
```

### 场景 3：命令行覆盖配置项

`--set` 参数可以在不修改配置文件的情况下覆盖任意配置项：

```bash
# 改变日志目录
suricata -c suricata.yaml -r test.pcap --set default-log-dir=/tmp/output

# 修改 HOME_NET
suricata -c suricata.yaml -r test.pcap --set vars.address-groups.HOME_NET="[10.0.0.0/8]"

# 禁用某个应用层协议
suricata -c suricata.yaml -r test.pcap --set app-layer.protocols.http.enabled=no
```

### 场景 4：禁用检测，只做协议日志

```bash
# 不加载任何规则，只做网络流量的协议解析和日志记录
suricata -c suricata.yaml --disable-detection -r test.pcap
```

这在以下场景中非常有用：
- 网络流量元数据采集（NSM - Network Security Monitoring）
- 大量 pcap 文件的协议统计
- 测试应用层解析器而不需要检测引擎

### 场景 5：校验和处理

离线分析 pcap 文件时，经常遇到校验和不正确的问题（抓包工具在发送前抓取了数据包，此时校验和还未由网卡计算）。

```bash
# 禁用校验和检查（离线分析推荐）
suricata -c suricata.yaml -r test.pcap -k none
```

也可以在配置文件中设置：

```yaml
stream:
  checksum-validation: no
```

### 场景 6：查看支持的协议和关键字

```bash
# 列出所有支持的应用层协议
suricata --list-app-layer-protos

# 列出所有支持的检测关键字
suricata --list-keywords=all

# 查看特定关键字的详细信息
suricata --list-keywords=content

# 以 CSV 格式导出关键字列表
suricata --list-keywords=csv > keywords.csv

# 列出支持的运行模式
suricata --list-runmodes
```

### 场景 7：批量处理 pcap 文件

```bash
# 处理目录中的所有 pcap 文件
suricata -c suricata.yaml -r /path/to/pcap-directory/

# 递归处理子目录
suricata -c suricata.yaml -r /path/to/pcap-directory/ --pcap-file-recursive

# 持续监控目录（新文件自动处理）
suricata -c suricata.yaml -r /path/to/pcap-directory/ --pcap-file-continuous

# 处理完后自动删除 pcap 文件（节省磁盘）
suricata -c suricata.yaml -r /path/to/pcap-directory/ --pcap-file-delete
```

## suricata.log：引擎运行日志

`suricata.log` 记录了引擎的启动、运行和关闭过程。学习阶段建议仔细阅读这个日志：

```
[ERRCODE: SC_ERR_OPENING_FILE(40)] - 错误：无法打开文件
[ERRCODE: SC_WARN_...(xxx)] - 警告
i: 信息级别日志（正常运行信息）
```

典型的启动日志包含：

```
<Notice> - This is Suricata version 8.0.3 RELEASE running in SYSTEM mode
<Notice> - CPUs/cores online: 4
<Notice> - all 4 packet processing threads, 4 management threads initialized, engine started
<Notice> - Signal Received. Stopping engine.
<Notice> - Pcap-file module read 1000 packets, 500000 bytes
```

## stats.log：性能统计

`stats.log` 定期输出引擎内部的性能计数器：

```
------------------------------------------------------------------------------------
Date: 03/12/2026 -- 10:30:00 (uptime: 0d, 00h 00m 10s)
------------------------------------------------------------------------------------
Counter                                      | TM Name                   | Value
------------------------------------------------------------------------------------
capture.kernel_packets                       | Total                     | 1000
decoder.pkts                                 | Total                     | 1000
decoder.bytes                                | Total                     | 500000
decoder.ipv4                                 | Total                     | 950
decoder.tcp                                  | Total                     | 800
decoder.udp                                  | Total                     | 140
flow.tcp                                     | Total                     | 50
flow.udp                                     | Total                     | 30
detect.alert                                 | Total                     | 5
app_layer.flow.http                          | Total                     | 20
app_layer.flow.dns                           | Total                     | 10
app_layer.flow.tls                           | Total                     | 15
```

这些计数器直接对应源码中的 `StatsRegisterCounter` 调用，在后续源码分析中我们会看到每个模块如何注册和更新自己的计数器。

## 理解 --build-info 输出

`--build-info` 是了解当前 Suricata 构建配置的最佳方式：

```bash
suricata --build-info
```

输出中的关键信息：

```
Suricata Configuration:
  AF_PACKET support:                       yes    ← 抓包方式
  NFQueue support:                         yes    ← IPS 模式支持
  PCAP_SET_BUFF:                           yes
  PF_RING support:                         no     ← 未启用 PF_RING
  AF_XDP support:                          no
  DPDK support:                            no

  Libpcre2 support:                        yes    ← 正则引擎
  Hyperscan support:                       no     ← 未启用高性能正则

  libcap_ng support:                       yes    ← 权限管理
  libnet support:                          yes    ← reject 包发送

  Lua support:                             yes    ← Lua 脚本
  GeoIP support:                           yes    ← 地理位置

  Rust support:                            yes    ← Rust 组件
  Rust compiler:                           rustc 1.75.0
  Rust cargo:                              cargo 1.75.0
```

## 数据包处理流程预览

当你运行 `suricata -r test.pcap` 时，数据包经历以下处理流程。这是板块三源码分析的核心主题：

```
pcap 文件                                              输出
   │                                                    ▲
   ▼                                                    │
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌────────┐│
│ 数据包   │──▶│  解码层  │──▶│  流处理  │──▶│ 应用层 ││
│ 读取     │   │  Decode  │   │  Stream  │   │ Parser ││
└──────────┘   └──────────┘   └──────────┘   └────────┘│
                                    │                   │
                                    ▼                   │
                              ┌──────────┐   ┌────────┐│
                              │ 检测引擎 │──▶│ 输出层 │┘
                              │ Detect   │   │ Output │
                              └──────────┘   └────────┘
```

1. **数据包读取**：从 pcap 文件逐包读取（`src/source-pcap-file.c`）
2. **解码层**：以太网帧 → IP → TCP/UDP 逐层解包（`src/decode-*.c`）
3. **流处理**：TCP 流跟踪和重组（`src/stream-tcp.c`）
4. **应用层解析**：HTTP、DNS、TLS 等协议解析（`src/app-layer-*.c` + `rust/src/*/`）
5. **检测引擎**：规则匹配（`src/detect.c`）
6. **输出层**：生成 EVE JSON、fast.log 等（`src/output-*.c`）

## 小结

本文我们完成了：

- 掌握 Suricata 命令行参数的六大分类
- 理解 IDS、IPS、离线分析、Unix Socket 四种运行模式
- 在 Docker 环境中处理了第一个 pcap 文件
- 学会解读 EVE JSON、fast.log、stats.log 三种输出格式
- 掌握 jq 分析 EVE JSON 的常用技巧
- 了解数据包处理的整体流程

## 下一篇预告

**03 - 配置文件全解析**

深入 `suricata.yaml` 的完整结构，理解网络变量、输出配置、应用层协议开关、检测引擎参数等核心配置项。配合 `src/conf.c` 源码，理解配置加载机制。
