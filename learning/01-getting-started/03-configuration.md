# 03 - 配置文件全解析

> `suricata.yaml` 是 Suricata 的核心配置文件，长达 2300+ 行，控制着引擎的方方面面。本文将系统梳理其结构，理解每个配置段的作用，并结合 `src/conf.c` 源码理解配置加载机制。

## 配置文件的四步结构

Suricata 官方将 `suricata.yaml` 分为四大步骤（Step），再加上一个高级设置区：

```
suricata.yaml 整体结构
├── Step 1: 网络定义 ─────────── vars（地址组、端口组）
├── Step 2: 输出配置 ─────────── outputs（EVE JSON、fast.log 等）
├── Step 3: 抓包配置 ─────────── af-packet / pcap / dpdk 等
├── Step 4: 应用层协议 ────────── app-layer.protocols.*
└── 高级设置 ─────────────────── 检测引擎、流处理、线程、性能分析等
```

## Step 1：网络定义（vars）

网络变量是规则引擎的基础。规则中的 `$HOME_NET`、`$HTTP_PORTS` 等变量在此定义。

### 地址组（address-groups）

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"
```

**关键理解**：

- `HOME_NET` 是最重要的变量，定义"内网"范围。规则中 `alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS` 的含义就取决于此。
- `EXTERNAL_NET: "!$HOME_NET"` 表示非内网的所有地址。
- 服务器变量默认都指向 `$HOME_NET`，在生产环境中应根据实际网络拓扑精细化配置。
- **性能影响**：精确的 `HOME_NET` 定义可以减少不必要的规则匹配，提升性能。

### 端口组（port-groups）

```yaml
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
    SIP_PORTS: "[5060, 5061]"
```

端口组同样被规则引用。注意 `HTTP_PORTS` 默认只有 80，如果环境中使用了非标准端口（如 8080、8443），需要在此添加。

### 配置建议

```yaml
# 生产环境示例：根据实际网络精确配置
vars:
  address-groups:
    HOME_NET: "[10.1.0.0/16,10.2.0.0/16]"       # 只包含实际内网段
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "[10.1.1.0/24]"                 # Web 服务器子网
    DNS_SERVERS: "[10.1.0.10,10.1.0.11]"          # 具体 DNS 服务器
    SQL_SERVERS: "[10.1.2.0/24]"                  # 数据库子网

  port-groups:
    HTTP_PORTS: "[80,443,8080,8443,8000]"         # 包含所有 HTTP 端口
    SSH_PORTS: "[22,2222]"                        # 包含非标准 SSH 端口
```

## Step 2：输出配置（outputs）

### 日志目录

```yaml
default-log-dir: /var/log/suricata/
```

所有日志文件的默认输出目录。可被命令行 `-l` 参数覆盖。

### 统计信息（stats）

```yaml
stats:
  enabled: yes
  interval: 8          # 每 8 秒更新一次统计
```

### 输出类型

Suricata 支持多种输出格式，最重要的是 EVE JSON：

#### fast.log

```yaml
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
```

传统的一行一告警格式，便于快速查看和 grep 搜索。

#### EVE JSON（核心输出）

```yaml
  - eve-log:
      enabled: yes
      filetype: regular    # regular|syslog|unix_dgram|unix_stream|redis
      filename: eve.json

      # 多线程输出（高流量场景启用）
      #threaded: false

      # Community Flow ID（跨工具关联）
      community-id: false
      community-id-seed: 0

      # X-Forwarded-For 支持（反向代理场景）
      xff:
        enabled: no
        mode: extra-data
        deployment: reverse
        header: X-Forwarded-For
```

**filetype 选项详解**：

| 值 | 说明 | 适用场景 |
|-----|------|---------|
| `regular` | 普通文件 | 默认，配合 logrotate |
| `syslog` | 系统日志 | 集中日志管理 |
| `unix_dgram` | Unix 数据报套接字 | 高性能本地传输 |
| `unix_stream` | Unix 流套接字 | 可靠本地传输 |
| `redis` | Redis 推送 | 分布式日志收集 |

**Community Flow ID**：生成跨工具统一的流标识符，便于与 Zeek（原 Bro）等工具进行关联分析。

#### EVE 事件类型配置

```yaml
      types:
        - alert:
            # payload: yes           # Base64 编码的载荷
            # payload-printable: yes # 可打印格式的载荷
            # packet: yes            # 完整数据包
            # metadata:
            #   app-layer: true      # 包含应用层元数据
            #   flow: true           # 包含流状态
            #   rule:
            #     metadata: true     # 规则元数据
            #     raw: false         # 原始规则文本

        - anomaly:
            enabled: yes

        - http:
            extended: yes            # 包含扩展字段

        - dns:
            # query: yes
            # answer: yes

        - tls:
            extended: yes

        - files:
            force-magic: no          # 强制文件类型检测
            # force-hash: [md5,sha256]  # 强制计算哈希

        - smtp:

        - ssh:

        - flow:

        - stats:
            totals: yes
            threads: no
            deltas: no

        # 还支持: nfs, smb, ftp, rdp, mqtt, http2, pgsql 等
```

**配置建议**：

- 开发/学习环境：全部启用，便于观察所有事件
- 生产环境：根据需要选择性启用，减少磁盘 I/O

#### Redis 输出配置

```yaml
      # 适用于分布式部署
      redis:
        server: 127.0.0.1
        port: 6379
        async: true
        mode: list     # list|rpush|channel|publish|xadd|stream
        key: suricata
        pipelining:
          enabled: yes
          batch-size: 10
```

### 日志框架（logging）

Suricata 自身的运行日志（不是检测日志）：

```yaml
logging:
  default-log-level: notice    # emergency|alert|critical|error|warning|notice|info|debug
  default-output-filter:

  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        level: info
        filename: suricata.log
    - syslog:
        enabled: no
        facility: local5
        format: "[%i] <%d> -- "
```

调试时可以设置 `default-log-level: debug`，但注意 debug 级别会产生大量日志。

## Step 3：抓包配置

### AF_PACKET（Linux 推荐）

```yaml
af-packet:
  - interface: eth0
    cluster-id: 99              # 多线程集群 ID
    cluster-type: cluster_flow  # cluster_flow|cluster_cpu|cluster_qm|cluster_ebpf
    defrag: yes                 # 内核态分片重组
    use-mmap: yes               # 使用内存映射
    mmap-locked: yes            # 锁定 mmap 内存
    tpacket-v3: yes             # 使用 TPACKET_V3
    ring-size: 2048             # 环形缓冲区大小
    block-size: 32768           # TPACKET_V3 块大小
    block-timeout: 10           # 块超时（毫秒）
    buffer-size: 32768          # 套接字缓冲区大小
    checksum-checks: kernel     # kernel|yes|no|auto
    bpf-filter: ""              # BPF 过滤器
    copy-mode: ips              # ips|tap（IPS 模式）
    copy-iface: eth1            # IPS 模式下的出口接口
```

**cluster-type 详解**：

| 类型 | 说明 |
|------|------|
| `cluster_flow` | 按流分配到线程（同一流的包总是由同一线程处理，推荐） |
| `cluster_cpu` | 按 CPU 分配 |
| `cluster_qm` | 按 RSS 队列分配 |
| `cluster_ebpf` | 使用 eBPF 程序分配 |

### pcap 模式

```yaml
pcap:
  - interface: eth0
    buffer-size: 16777216       # 16MB 缓冲区
    bpf-filter: "tcp or udp"
    checksum-checks: auto
    threads: auto
    promisc: yes
    snaplen: 1518
```

### pcap 文件模式

```yaml
pcap-file:
  checksum-checks: auto
```

离线分析 pcap 文件时使用。`checksum-checks: auto` 在离线模式下自动禁用校验和检查。

## Step 4：应用层协议配置

`app-layer.protocols` 控制 Suricata 解析哪些应用层协议。这是 Suricata 协议分析能力的核心配置。

### 配置结构

```yaml
app-layer:
  protocols:
    <protocol-name>:
      enabled: yes|no|detection-only
      detection-ports:
        dp: <port-list>        # 目的端口
        sp: <port-list>        # 源端口
      # 协议特定配置...
```

**enabled 的三种值**：

| 值 | 说明 |
|-----|------|
| `yes` | 完全启用：协议检测 + 解析 + 日志 |
| `no` | 完全禁用 |
| `detection-only` | 仅做协议检测，不做完整解析（节省资源） |

### 各协议配置概览

#### HTTP（基于 libhtp）

HTTP 是最复杂的协议配置，使用 libhtp 库解析：

```yaml
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS                        # 解析器行为特性
          request-body-limit: 100 KiB             # 请求体检查限制
          response-body-limit: 100 KiB            # 响应体检查限制
          request-body-minimal-inspect-size: 32 KiB
          request-body-inspect-window: 4 KiB
          response-body-minimal-inspect-size: 40 KiB
          response-body-inspect-window: 16 KiB
          response-body-decompress-layer-limit: 2 # 解压层数限制
          http-body-inline: auto
          double-decode-path: no
          double-decode-query: no
          swf-decompression:
            enabled: no
            type: both                            # deflate|lzma|both

        # 可以按服务器地址配置不同的解析行为
        server-config:
          #- apache:
          #    address: [192.168.1.0/24]
          #    personality: Apache_2
          #- iis7:
          #    address: [192.168.0.0/24]
          #    personality: IIS_7_0
```

**personality 选项**：Minimal、Generic、IDS（默认）、IIS_4_0、IIS_5_0、IIS_5_1、IIS_6_0、IIS_7_0、IIS_7_5、Apache_2。不同 personality 影响 URL 规范化、编码处理等行为，这对安全检测至关重要。

#### TLS

```yaml
    tls:
      enabled: yes
      detection-ports:
        dp: 443
      #ja3-fingerprints: auto    # JA3 指纹
      #ja4-fingerprints: auto    # JA4 指纹
      #encryption-handling: track-only   # track-only|bypass|full
```

`encryption-handling` 控制加密通信开始后的处理方式：
- `track-only`（默认）：继续跟踪 TLS 会话但不检查加密内容
- `bypass`：跳过后续处理（最佳性能）
- `full`：完整检查（最大安全性但影响性能）

#### DNS

```yaml
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
```

DNS 同时支持 TCP 和 UDP 两种传输方式。

#### SSH

```yaml
    ssh:
      enabled: yes
      #hassh: no              # HASSH 指纹
      #encryption-handling: track-only
```

#### SMTP

```yaml
    smtp:
      enabled: yes
      raw-extraction: no
      mime:
        decode-mime: yes
        decode-base64: yes
        decode-quoted-printable: yes
        header-value-depth: 2000
        extract-urls: yes
        body-md5: no
```

#### 工控协议

```yaml
    modbus:
      enabled: yes
      detection-ports:
        dp: 502
    dnp3:
      enabled: yes
      detection-ports:
        dp: 20000
    enip:
      enabled: yes
      detection-ports:
        dp: 44818
        sp: 44818
```

Suricata 对工控协议（ICS/SCADA）的支持使其适用于工业网络安全监控。

#### 其他协议

```yaml
    # 完整的协议列表
    telnet:     { enabled: yes }
    rfb:        { enabled: yes }    # 远程帧缓冲（VNC）
    mqtt:       { enabled: yes }    # MQTT 物联网协议
    krb5:       { enabled: yes }    # Kerberos
    snmp:       { enabled: yes }
    ike:        { enabled: yes }    # IKE/IPSec
    nfs:        { enabled: yes }
    tftp:       { enabled: yes }
    ftp:        { enabled: yes }
    smb:        { enabled: yes }
    dcerpc:     { enabled: yes }
    ssh:        { enabled: yes }
    http2:      { enabled: yes }
    doh2:       { enabled: yes }    # DNS over HTTPS
    pgsql:      { enabled: no }     # PostgreSQL（默认关闭）
    websocket:  { enabled: yes }
    rdp:        { enabled: yes }
    pop3:       { enabled: yes }
    imap:       { enabled: detection-only }
    bittorrent-dht: { enabled: yes }
    sip:        { enabled: yes }
    ldap:       { enabled: yes }
```

## 高级设置

### 安全设置（security）

```yaml
security:
  limit-noproc: true         # 限制进程创建
  landlock:                  # Linux Landlock 沙箱
    enabled: no
    directories:
      read:                  # 只读目录
        - /usr/
        - /etc/
      write:                 # 可写目录
        - /var/log/suricata/
      read-write:
        - /var/run/suricata/
  lua:
    allow-rules: no          # 是否允许 Lua 规则
    sandbox:
      enabled: yes           # Lua 沙箱
```

### 流处理配置（stream）

```yaml
stream:
  memcap: 64 MiB             # TCP 重组内存上限
  checksum-validation: yes    # 校验和检查
  inline: auto                # IPS 模式下自动启用内联处理
  reassembly:
    memcap: 256 MiB           # 重组缓冲区内存上限
    depth: 1 MiB              # 重组深度
    toserver-chunk-size: 2560 # 客户端方向块大小
    toclient-chunk-size: 2560 # 服务端方向块大小
    randomize-chunk-size: yes # 随机化块大小（防逃逸）
```

### 流配置（flow）

```yaml
flow:
  memcap: 128 MiB            # 流表内存上限
  hash-size: 65536           # 流哈希表大小
  prealloc: 10000            # 预分配流对象数量
  emergency-recovery: 30     # 紧急模式恢复阈值
```

### 流超时

```yaml
flow-timeouts:
  default:
    new: 30
    established: 300
    closed: 0
    bypassed: 100
    emergency-new: 10
    emergency-established: 100
    emergency-closed: 0
    emergency-bypassed: 50
  tcp:
    new: 60
    established: 600
    closed: 60
    bypassed: 100
  udp:
    new: 30
    established: 300
    bypassed: 100
  icmp:
    new: 30
    established: 300
    bypassed: 100
```

### IP 分片重组（defrag）

```yaml
defrag:
  memcap: 32 MiB
  hash-size: 65536
  trackers: 65535            # 跟踪的分片流数
  max-frags: 65535           # 最大分片数
  prealloc: yes
  timeout: 60
```

### 操作系统策略（host-os-policy）

针对不同操作系统的 TCP/IP 栈差异配置不同的重组策略，防止逃逸攻击：

```yaml
host-os-policy:
  windows: [0.0.0.0/0]      # 默认使用 Windows 策略
  bsd: []
  linux: []
  old-linux: []
  solaris: []
  macos: []
```

### 检测引擎（detect）

```yaml
detect:
  profile: medium            # low|medium|high|custom
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto      # 多模式匹配上下文
  sgh-mpm-caching: yes       # 签名组缓存
  inspection:
    recursion-limit: 3000     # 检查递归限制
  prefilter:
    default: mpm              # 默认预过滤方法
  grouping:                   # 规则分组
  profiling:
    grouping:
      dump-to-disk: false
      include-rules: false
```

### 多模式匹配算法

```yaml
mpm-algo: auto               # auto|hs（Hyperscan）|ac（Aho-Corasick）|ac-bs|ac-ks
spm-algo: auto               # auto|bm（Boyer-Moore）|hs
```

### 线程配置（threading）

```yaml
threading:
  set-cpu-affinity: no        # CPU 亲和性
  autopin: no                 # 自动 CPU 绑定
  cpu-affinity:
    - management-cpu-set:
        cpu: [0]
    - receive-cpu-set:
        cpu: [0]
    - worker-cpu-set:
        cpu: ["all"]
        mode: "exclusive"     # exclusive|balanced
        prio:
          default: "medium"   # low|medium|high
  detect-thread-ratio: 1.0   # 检测线程与 CPU 核心的比例
```

### 性能分析（profiling）

```yaml
profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
    sort: avgticks            # avgticks|checks|matches|maxticks

  keywords:
    enabled: yes
    filename: keyword_perf.log

  prefilter:
    enabled: yes
    filename: prefilter_perf.log

  rulegroups:
    enabled: yes
    filename: rule_group_perf.log

  packets:
    enabled: yes
    filename: packet_stats.log

  locks:
    enabled: no
    filename: lock_stats.log
```

### 规则文件配置

```yaml
default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules

classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
```

### Unix Socket 控制

```yaml
unix-command:
  enabled: auto              # auto|yes|no
  #filename: /var/run/suricata/suricata-command.socket
```

### 异常策略（exception-policy）

```yaml
exception-policy: auto
# 可选值：
# - auto: 自动选择（IDS 模式下忽略，IPS 模式下丢弃）
# - drop-packet: 丢弃当前数据包
# - drop-flow: 丢弃整个流
# - reject: 发送 TCP RST 或 ICMP 不可达
# - bypass: 跳过处理
# - ignore: 忽略错误
# - pass-packet: 放行数据包
# - pass-flow: 放行整个流
```

## 配置加载机制（源码视角）

配置的加载和查询逻辑在 `src/conf.c` 中实现。

### 核心数据结构

配置以树形结构存储，每个节点是一个 `SCConfNode`：

```c
// src/conf.h
typedef struct SCConfNode_ {
    char *name;           // 节点名称
    char *val;            // 节点值（叶节点）
    int is_seq;           // 是否是序列（YAML 列表）
    int final;            // 是否为最终值（不可覆盖）
    TAILQ_HEAD(, SCConfNode_) head;  // 子节点链表
    TAILQ_ENTRY(SCConfNode_) next;   // 同级链表
} SCConfNode;
```

### 配置查询

```c
// 获取配置值
int SCConfGet(const char *name, const char **vptr);

// 示例：获取 HOME_NET
const char *home_net;
SCConfGet("vars.address-groups.HOME_NET", &home_net);
// home_net = "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"

// 获取布尔值
int SCConfGetBool(const char *name, int *val);

// 获取整数
int SCConfGetInt(const char *name, intmax_t *val);
```

### 配置覆盖

命令行 `--set` 参数通过 `SCConfSetFromString` 实现，设置 `final=1` 确保命令行参数优先于配置文件：

```c
// src/suricata.c:1800
if (!SCConfSetFromString(optarg, 1)) {
    FatalError("failed to set configuration value %s", optarg);
}
```

### 配置加载流程

```
1. SuricataPreInit()
   └── SCConfInit()                    // 初始化空配置树

2. SCParseCommandLine()
   ├── --set key=value                 // 命令行覆盖（final=1）
   └── -c suricata.yaml               // 记录配置文件路径

3. SCLoadYamlConfig()
   ├── SCConfYamlLoadFile()            // 解析 YAML 文件
   │   └── yaml_parser → SCConfNode   // libyaml → 配置树
   └── --include 的额外配置文件

4. SuricataInit()
   └── 各模块从配置树中读取自己的配置
       ├── OutputSetup() → outputs.*
       ├── StreamTcpInit() → stream.*
       ├── FlowInit() → flow.*
       ├── DetectEngineInit() → detect.*
       └── AppLayerSetup() → app-layer.*
```

## --set 参数的实用技巧

`--set` 参数是调试和实验的利器，可以在不修改配置文件的情况下临时调整配置：

```bash
# 修改网络变量
suricata --set vars.address-groups.HOME_NET="[10.0.0.0/8]"

# 修改日志目录
suricata --set default-log-dir=/tmp/output

# 启用/禁用协议解析
suricata --set app-layer.protocols.http.enabled=no
suricata --set app-layer.protocols.pgsql.enabled=yes

# 调整流处理参数
suricata --set stream.memcap=128mb
suricata --set stream.reassembly.depth=2mb

# 调整检测引擎
suricata --set detect.profile=high

# 修改规则文件路径
suricata --set default-rule-path=/opt/rules
```

## 配置验证

修改配置后，务必先验证：

```bash
# 测试配置文件语法
suricata -T -c /etc/suricata/suricata.yaml

# 显示运行时完整配置（含默认值和覆盖值）
suricata --dump-config -c /etc/suricata/suricata.yaml
```

`--dump-config` 非常有用，它展示了配置解析后的完整树结构，可以确认你的设置是否生效。

## 常见配置场景

### 场景 1：纯 NSM 模式（只记录不告警）

```yaml
# 禁用检测引擎，仅做协议日志
# 或通过命令行：suricata --disable-detection

outputs:
  - fast:
      enabled: no               # 关闭告警日志

  - eve-log:
      enabled: yes
      types:
        - http:                  # 只启用需要的协议日志
            extended: yes
        - dns:
        - tls:
            extended: yes
        - flow:
        - ssh:
```

### 场景 2：高性能 IDS

```yaml
# 关闭非必要协议解析
app-layer:
  protocols:
    rfb: { enabled: no }
    mqtt: { enabled: no }
    bittorrent-dht: { enabled: no }
    # 保留关键协议：http, tls, dns, ssh, smtp

# TLS 加密后跳过处理
    tls:
      enabled: yes
      encryption-handling: bypass

# 增大内存限制
stream:
  memcap: 256 MiB
  reassembly:
    memcap: 512 MiB

flow:
  memcap: 256 MiB
  prealloc: 50000

# CPU 亲和性
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - worker-cpu-set:
        cpu: ["1-7"]
        mode: "exclusive"
```

### 场景 3：pcap 文件批量分析

```bash
suricata -c suricata.yaml \
    -r /data/pcaps/ \
    --pcap-file-recursive \
    -k none \
    -l /data/output/ \
    --set outputs.0.eve-log.pcap-file=true
```

## 小结

本文我们完成了：

- 理解 `suricata.yaml` 的四步结构
- 掌握网络变量、输出、抓包、协议四大配置段
- 深入了解高级设置（流处理、检测引擎、线程、安全）
- 从源码角度理解配置加载机制（`src/conf.c` 中的树形结构）
- 学会使用 `--set`、`-T`、`--dump-config` 进行灵活的配置管理

## 下一篇预告

**04 - 运行模式深入**

详细对比 IDS vs IPS vs 离线分析 vs Unix Socket 模式的实现差异，深入 AF_PACKET、NFQueue、pcap 的工作原理，结合 `src/runmodes.c` 和各 `src/source-*.c` 源码分析。
