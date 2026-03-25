# 第 07 篇：EVE JSON 日志与 ELK 集成

> **系列**：Suricata 8.0.3 源码与实战全解析
> **板块**：二、使用与运维篇
> **适用版本**：Suricata 8.0.3
> **前置阅读**：第 03 篇（配置体系）、第 04 篇（运行模式）

---

## 1. 什么是 EVE JSON

EVE（Extensible Event Format）是 Suricata 的统一 JSON 日志格式。所有事件——告警、协议日志、流记录、统计数据——都以每行一个 JSON 对象（JSON Lines）的形式写入 `eve.json`。

与传统 IDS 的多文件输出相比（fast.log、http.log、dns.log……），EVE 有三大优势：

| 特性 | 传统输出 | EVE JSON |
|------|---------|----------|
| 格式 | 各不相同 | 统一 JSON |
| 关联 | 依赖手动匹配 | flow_id 自动关联 |
| 集成 | 需要自定义解析器 | 原生支持 ELK/Splunk/SIEM |
| 扩展 | 修改源码 | 配置即可增减字段 |

## 2. EVE 输出架构（源码视角）

### 2.1 核心结构体

EVE 的输出系统围绕三个层次的结构体构建：

```
OutputJsonCtx (全局上下文)
  ├── file_ctx: LogFileCtx*      // 文件/socket/redis 句柄
  ├── json_out: LogFileType      // 输出类型枚举
  ├── cfg: OutputJsonCommonSettings  // 通用选项
  ├── xff_cfg: HttpXFFCfg*       // XFF 配置
  └── filetype: SCEveFileType*   // 插件 filetype

OutputJsonCommonSettings (通用选项)
  ├── include_metadata: bool     // 包含 flowvars/pktvars
  ├── include_community_id: bool // Community Flow ID
  ├── include_ethernet: bool     // MAC 地址
  ├── include_suricata_version: bool
  └── community_id_seed: uint16_t

OutputJsonThreadCtx (线程上下文)
  ├── ctx: OutputJsonCtx*
  ├── file_ctx: LogFileCtx*      // 线程自己的文件句柄
  ├── buffer: MemBuffer*         // 序列化缓冲区
  └── too_large_warning: bool    // 超大记录告警标记
```

这些定义在 `src/output-json.h:64-88`。

### 2.2 模块注册

EVE 输出模块通过 `OutputJsonRegister()` 注册为 `eve-log`（`src/output-json.c:83`）：

```c
void OutputJsonRegister(void)
{
    OutputRegisterModule(MODULE_NAME, "eve-log", OutputJsonInitCtx);
    // 注册内置 filetype 插件
    SyslogInitialize();
    NullLogInitialize();
}
```

各事件类型作为子模块注册。例如 flow 日志（`src/output-json-flow.c:440`）：

```c
void JsonFlowLogRegister(void)
{
    OutputRegisterFlowSubModule(LOGGER_JSON_FLOW, "eve-log",
        "JsonFlowLog", "eve-log.flow",
        OutputJsonLogInitSub, JsonFlowLogger,
        JsonLogThreadInit, JsonLogThreadDeinit);
}
```

整个系统形成树状结构：

```
RootLogger (output.c)
  └── eve-log (OutputJsonCtx)
        ├── eve-log.alert  → output-json-alert.c
        ├── eve-log.flow   → output-json-flow.c
        ├── eve-log.http   → output-json-http.c
        ├── eve-log.dns    → output-json-dns.c
        ├── eve-log.tls    → output-json-tls.c
        ├── eve-log.smtp   → output-json-smtp.c
        ├── eve-log.stats  → output-json-stats.c
        └── ... (共 27 个子模块)
```

全部子模块文件列表：

```
src/output-json-alert.c      src/output-json-mqtt.c
src/output-json-anomaly.c    src/output-json-netflow.c
src/output-json-arp.c        src/output-json-nfs.c
src/output-json-dcerpc.c     src/output-json-pgsql.c
src/output-json-dhcp.c       src/output-json-smb.c
src/output-json-dnp3.c       src/output-json-smtp.c
src/output-json-dns.c        src/output-json-stats.c
src/output-json-drop.c       src/output-json-tls.c
src/output-json-file.c       src/output-json-frame.c
src/output-json-flow.c       src/output-json-ftp.c
src/output-json-http.c       src/output-json-ike.c
src/output-json-mdns.c       src/output-json-metadata.c
```

### 2.3 EVE 记录生成流程

以 flow 事件为例，追踪一条 EVE 记录从产生到写入磁盘的完整路径：

```
JsonFlowLogger()                    // src/output-json-flow.c:419
  ├── CreateEveHeaderFromFlow(f)    // 构建 JSON 头部
  │     ├── timestamp               // ISO 8601 时间戳
  │     ├── flow_id                 // 流标识
  │     ├── in_iface                // 输入接口
  │     ├── event_type: "flow"      // 事件类型
  │     ├── vlan                    // VLAN 信息
  │     └── 五元组                   // src_ip, src_port, dest_ip, dest_port, proto
  │
  ├── EveFlowLogJSON(thread, jb, f) // 填充 flow 特有字段
  │     ├── app_proto               // 应用层协议
  │     ├── flow.pkts_toserver/toclient
  │     ├── flow.bytes_toserver/toclient
  │     ├── flow.start / flow.end / flow.age
  │     ├── flow.state              // new/established/closed/bypassed
  │     ├── flow.reason             // timeout/tcp_reuse/forced/shutdown
  │     ├── tcp.tcp_flags / tcp.state
  │     └── exception_policy
  │
  └── OutputJsonBuilderBuffer()     // src/output-json.c:997
        ├── host (sensor_name)      // 添加主机名
        ├── pcap_filename           // 离线模式添加文件名
        ├── SCEveRunCallbacks()     // 执行插件回调
        ├── SCJbClose(js)           // 关闭 JSON 对象
        └── LogFileWrite()          // 写入文件/socket/redis
```

### 2.4 CreateEveHeader：公共头部构建

`CreateEveHeader()`（`src/output-json.c:832`）为所有事件类型构建统一的 JSON 头部：

```c
SCJsonBuilder *CreateEveHeader(const Packet *p,
    enum SCOutputJsonLogDirection dir,
    const char *event_type, JsonAddrInfo *addr,
    OutputJsonCtx *eve_ctx)
{
    SCJbSetString(js, "timestamp", timebuf);    // ISO 8601
    CreateEveFlowId(js, f);                      // flow_id + parent_id
    SCJbSetUint(js, "sensor_id", sensor_id);     // 可选
    SCJbSetString(js, "in_iface", p->livedev->dev);
    SCJbSetUint(js, "pcap_cnt", p->pcap_cnt);   // 包计数器
    SCJbSetString(js, "event_type", event_type); // 事件类型
    // vlan 数组
    // 五元组
    // ip 版本
    // icmp type/code
    SCJbSetString(js, "pkt_src", PktSrcToString(p->pkt_src));
    EveAddCommonOptions(&eve_ctx->cfg, p, f, js, dir);
}
```

`EveAddCommonOptions()`（`src/output-json.c:396`）根据配置决定是否附加额外字段：

```c
void EveAddCommonOptions(const OutputJsonCommonSettings *cfg,
    const Packet *p, const Flow *f,
    SCJsonBuilder *js, enum SCOutputJsonLogDirection dir)
{
    if (cfg->include_suricata_version)
        SCJbSetString(js, "suricata_version", PROG_VER);
    if (cfg->include_metadata)
        EveAddMetadata(p, f, js);       // flowvars, pktvars, flowbits, flowints
    if (cfg->include_ethernet)
        CreateJSONEther(js, p, f, dir); // MAC 地址
    if (cfg->include_community_id && f != NULL)
        CreateEveCommunityFlowId(js, f, cfg->community_id_seed);
    if (f != NULL && f->tenant_id > 0)
        SCJbSetUint(js, "tenant_id", f->tenant_id);
}
```

## 3. EVE 事件类型详解

### 3.1 所有事件类型一览

Suricata 8.0 支持超过 30 种事件类型：

| 类别 | 事件类型 | 说明 |
|------|---------|------|
| **检测** | alert | 规则告警 |
| | frame | 应用层帧日志（实验性） |
| | anomaly | 协议异常（decode/stream/applayer） |
| **网络层** | flow | 双向流记录（流结束时生成） |
| | netflow | 单向流记录 |
| | arp | ARP 事件（默认关闭） |
| **传输层** | stream | TCP 状态跟踪（实验性） |
| **应用层** | http | HTTP 事务 |
| | dns | DNS 查询/应答 |
| | mdns | mDNS 事件 |
| | tls | TLS 握手信息 |
| | smtp | SMTP 事务 |
| | ftp / ftp_data | FTP 命令/数据传输 |
| | ssh | SSH 握手 |
| | smb | SMB 事务 |
| | nfs | NFS 事务 |
| | dcerpc | DCERPC 事务 |
| | dhcp | DHCP 事务 |
| | mqtt | MQTT 消息 |
| | http2 | HTTP/2 事务 |
| | doh2 | DNS over HTTP/2 |
| | quic | QUIC 事务 |
| | ike | IKE/IPsec 事务 |
| | krb5 | Kerberos 5 |
| | snmp | SNMP 事务 |
| | sip | SIP 事务 |
| | rfb | VNC/RFB 事务 |
| | rdp | RDP 事务 |
| | dnp3 | DNP3 工控协议 |
| | websocket | WebSocket 消息 |
| | pgsql | PostgreSQL（默认关闭） |
| | pop3 | POP3 |
| | ldap | LDAP |
| | tftp | TFTP |
| | bittorrent-dht | BitTorrent DHT |
| **元数据** | files | 文件信息（hash、magic、大小） |
| | metadata | 变量元数据 |
| | drop | 丢弃的数据包 |
| | stats | 引擎统计数据 |

### 3.2 alert 事件结构

alert 是最核心的事件类型，其 JSON 结构如下：

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
  "pkt_src": "wire/pcap",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2024001,
    "rev": 1,
    "signature": "ET MALWARE Example Trojan Callback",
    "category": "A Network Trojan was Detected",
    "severity": 1,
    "metadata": {
      "attack_target": ["Client_Endpoint"],
      "deployment": ["Perimeter"],
      "signature_severity": ["Major"]
    }
  },
  "app_proto": "http",
  "flow": {
    "pkts_toserver": 5,
    "pkts_toclient": 3,
    "bytes_toserver": 512,
    "bytes_toclient": 1024,
    "start": "2024-01-15T10:29:59.000000+0800"
  },
  "http": {
    "hostname": "evil.example.com",
    "url": "/callback",
    "http_method": "GET",
    "http_user_agent": "Mozilla/5.0",
    "status": 200,
    "length": 512
  }
}
```

alert 事件的源码入口在 `src/output-json-alert.c:202`，`AlertJsonHeader()` 函数构建 alert 子对象：

```c
// action 判断逻辑
if (pa->action & ACTION_REJECT_ANY) {
    action = "blocked";
} else if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
    action = "blocked";
}
// alert 对象字段
SCJbSetString(js, "action", action);
SCJbSetUint(js, "gid", pa->s->gid);
SCJbSetUint(js, "signature_id", pa->s->id);
SCJbSetUint(js, "rev", pa->s->rev);
SCJbSetString(js, "signature", pa->s->msg);
SCJbSetString(js, "category", pa->s->class_msg);
SCJbSetUint(js, "severity", pa->s->prio);
```

注意 action 字段的值取决于运行模式：
- IDS 模式下 DROP 规则的 action 仍为 `"allowed"`（因为实际未丢弃）
- IPS 模式下 DROP 规则的 action 为 `"blocked"`

alert 子模块的配置标志位（`src/output-json-alert.c:73`）：

```c
#define LOG_JSON_PAYLOAD           BIT_U16(0)   // 原始载荷（Base64）
#define LOG_JSON_PACKET            BIT_U16(1)   // 原始数据包
#define LOG_JSON_PAYLOAD_BASE64    BIT_U16(2)   // 载荷 Base64 编码
#define LOG_JSON_TAGGED_PACKETS    BIT_U16(3)   // tag 关键字触发的后续包
#define LOG_JSON_APP_LAYER         BIT_U16(4)   // 应用层元数据
#define LOG_JSON_FLOW              BIT_U16(5)   // 流状态信息
#define LOG_JSON_HTTP_BODY         BIT_U16(6)   // HTTP body
#define LOG_JSON_HTTP_BODY_BASE64  BIT_U16(7)   // HTTP body (Base64)
#define LOG_JSON_RULE_METADATA     BIT_U16(8)   // 规则 metadata 字段
#define LOG_JSON_RULE              BIT_U16(9)   // 规则原文
#define LOG_JSON_VERDICT           BIT_U16(10)  // 最终裁决
#define LOG_JSON_WEBSOCKET_PAYLOAD BIT_U16(11)  // WebSocket 载荷
#define LOG_JSON_PAYLOAD_LENGTH    BIT_U16(13)  // 载荷长度
#define LOG_JSON_REFERENCE         BIT_U16(14)  // 规则引用
```

### 3.3 flow 事件结构

flow 事件在流结束时生成，提供完整的会话统计：

```json
{
  "timestamp": "2024-01-15T10:35:00.000000+0800",
  "flow_id": 1234567890123456,
  "event_type": "flow",
  "src_ip": "192.168.1.100",
  "dest_ip": "10.0.0.1",
  "src_port": 54321,
  "dest_port": 443,
  "proto": "TCP",
  "app_proto": "tls",
  "flow": {
    "pkts_toserver": 120,
    "pkts_toclient": 95,
    "bytes_toserver": 8192,
    "bytes_toclient": 65536,
    "start": "2024-01-15T10:30:00.000000+0800",
    "end": "2024-01-15T10:35:00.000000+0800",
    "age": 300,
    "state": "closed",
    "reason": "timeout",
    "alerted": false
  },
  "tcp": {
    "tcp_flags": "1b",
    "tcp_flags_ts": "1b",
    "tcp_flags_tc": "1b",
    "syn": true,
    "fin": true,
    "ack": true,
    "psh": true,
    "state": "closed"
  }
}
```

flow 状态机在 `src/output-json-flow.c:302` 中映射：

```c
switch (flow_state) {
    case FLOW_STATE_NEW:              → "new"
    case FLOW_STATE_ESTABLISHED:      → "established"
    case FLOW_STATE_CLOSED:           → "closed"
    case FLOW_STATE_LOCAL_BYPASSED:   → "bypassed" + bypass: "local"
    case FLOW_STATE_CAPTURE_BYPASSED: → "bypassed" + bypass: "capture"
}
```

flow 结束原因（`src/output-json-flow.c:327`）：

| 标志 | reason 值 | 说明 |
|------|----------|------|
| FLOW_END_FLAG_TCPREUSE | `"tcp_reuse"` | TCP 端口被重新连接使用 |
| FLOW_END_FLAG_FORCED | `"forced"` | 因内存压力强制回收 |
| FLOW_END_FLAG_SHUTDOWN | `"shutdown"` | Suricata 关闭 |
| FLOW_END_FLAG_TIMEOUT | `"timeout"` | 超时回收 |

### 3.4 dns 事件

Suricata 8.0 使用新的 DNS 日志格式（version 3），与旧版有显著变化。可通过 `version: 2` 保持兼容。

### 3.5 stats 事件

stats 不是由网络流量触发，而是由定时器周期性生成。包含所有引擎统计计数器：

```yaml
- stats:
    totals: yes       # 合并所有线程的统计
    threads: no       # 每线程独立统计
    deltas: no        # 包含增量值
```

## 4. Community Flow ID

Community ID 是一种跨工具的流标识标准，使得 Suricata、Zeek、网络设备等不同工具对同一条流生成相同的 ID。

### 4.1 算法原理

Community ID 的计算在 `src/output-json.c:585`（IPv4）和 `src/output-json.c:635`（IPv6）：

```c
// IPv4 计算结构（src/output-json.c:588）
struct {
    uint16_t seed;        // 用户配置的种子值
    uint32_t src;         // 较小的 IP 放前面
    uint32_t dst;
    uint8_t  proto;       // 协议号
    uint8_t  pad0;        // 填充
    uint16_t sp;          // 对应的端口
    uint16_t dp;
} __attribute__((__packed__)) ipv4;
```

算法步骤：
1. 比较 src IP 和 dst IP 的大小（网络序比较）
2. 较小的 IP 放在前面，对应的端口跟随
3. 如果 IP 相同，则比较端口大小
4. 将整个结构体做 SHA-1 哈希
5. 对哈希结果做 Base64 编码
6. 加上 `"1:"` 前缀（版本号）

最终输出形如：`1:LQU9qZlK+B5F3KDmev6m5PMibrg=`

### 4.2 配置

```yaml
outputs:
  - eve-log:
      community-id: true
      community-id-seed: 0    # 0-65535，所有传感器需相同
```

## 5. EVE 输出目标

### 5.1 输出类型一览

`LogFileType` 枚举定义了所有输出类型（`src/util-logopenfile.h:38`）：

```c
enum LogFileType {
    LOGFILE_TYPE_FILE,        // 常规文件
    LOGFILE_TYPE_UNIX_DGRAM,  // Unix 数据报 socket
    LOGFILE_TYPE_UNIX_STREAM, // Unix 流 socket
    LOGFILE_TYPE_REDIS,       // Redis
    LOGFILE_TYPE_FILETYPE,    // 插件 filetype
    LOGFILE_TYPE_NOTSET
};
```

`FileTypeFromConf()`（`src/output-json.c:1044`）根据配置字符串映射：

```c
if (strcmp(typestr, "file") == 0 || strcmp(typestr, "regular") == 0)
    → LOGFILE_TYPE_FILE
else if (strcmp(typestr, "unix_dgram") == 0)
    → LOGFILE_TYPE_UNIX_DGRAM
else if (strcmp(typestr, "unix_stream") == 0)
    → LOGFILE_TYPE_UNIX_STREAM
else if (strcmp(typestr, "redis") == 0)
    → LOGFILE_TYPE_REDIS       // 需要 --enable-hiredis 编译
```

### 5.2 常规文件输出

最常用的输出方式：

```yaml
- eve-log:
    enabled: yes
    filetype: regular
    filename: eve.json
    threaded: false     # 多线程输出（文件名变为 eve.N.json）
    buffer-size: 0      # 0 表示不缓冲
    prefix: ""          # 每条日志前缀（如 "@cee: "）
```

**threaded 模式**：当 `threaded: true` 时，每个输出线程写独立文件（如 `eve.0.json`、`eve.1.json`）。适合高吞吐场景，消除了文件锁竞争。在 `OutputJsonInitCtx()`（`src/output-json.c:1197`）中初始化：

```c
const SCConfNode *threaded = SCConfNodeLookupChild(conf, "threaded");
if (threaded && threaded->val && SCConfValIsTrue(threaded->val)) {
    json_ctx->file_ctx->threaded = true;
}
```

### 5.3 Unix Socket 输出

适合将 EVE 数据管道化到其他进程：

```yaml
- eve-log:
    filetype: unix_dgram   # 或 unix_stream
    filename: /var/run/suricata/eve.sock
```

典型用法：配合 `logstash-input-unix` 或自定义消费程序。

### 5.4 Syslog 输出

通过内置的 syslog filetype 插件实现（`src/output-eve-syslog.c`）：

```yaml
- eve-log:
    filetype: syslog
    identity: "suricata"
    facility: local5
    level: Info
```

syslog 插件的实现很简单——`SyslogWrite()` 直接调用系统 `syslog()` 函数（`src/output-eve-syslog.c:82`）：

```c
static int SyslogWrite(const char *buffer, const int buffer_len,
    const void *init_data, void *thread_data)
{
    const Context *context = init_data;
    syslog(context->alert_syslog_level, "%s", buffer);
    return 0;
}
```

### 5.5 Redis 输出

需要编译时启用 `--enable-hiredis`：

```yaml
- eve-log:
    filetype: redis
    redis:
      server: 127.0.0.1
      port: 6379
      async: true
      mode: list        # list|lpush|rpush|channel|publish|xadd|stream
      key: suricata
      # Stream 模式特有选项
      stream-maxlen: 100000
      stream-trim-exact: false
      # Pipeline 批量写入
      pipelining:
        enabled: yes
        batch-size: 10
```

Redis 模式选项：
- `list` / `lpush`：Redis List，左端插入
- `rpush`：Redis List，右端插入
- `channel` / `publish`：Redis Pub/Sub
- `xadd` / `stream`：Redis Stream（支持持久化和消费者组）

### 5.6 插件 Filetype

Suricata 8 引入了 `SCEveFileType` 插件接口（`src/output-eve.h:73`），允许通过动态库扩展输出目标：

```c
typedef struct SCEveFileType_ {
    const char *name;           // 配置中使用的名字
    int (*Init)(const SCConfNode *conf, const bool threaded, void **init_data);
    int (*ThreadInit)(const void *init_data, const ThreadId thread_id, void **thread_data);
    int (*Write)(const char *buffer, const int buffer_len,
                 const void *init_data, void *thread_data);
    void (*ThreadDeinit)(const void *init_data, void *thread_data);
    void (*Deinit)(void *init_data);
} SCEveFileType;
```

生命周期为：`Init → ThreadInit → Write (多次) → ThreadDeinit → Deinit`

注册通过 `SCRegisterEveFileType()`（`src/output-eve.c:100`）完成。注册后即可在配置中使用：

```yaml
- eve-log:
    filetype: my-custom-output
```

## 6. EVE 配置全解

### 6.1 全局选项

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json

      # 包含顶层 metadata（flowvars, pktvars, flowbits）
      metadata: yes

      # 包含 Suricata 版本号
      suricata-version: no

      # 离线模式下包含 pcap 文件名
      pcap-file: false

      # Community Flow ID
      community-id: false
      community-id-seed: 0

      # 以太网 MAC 地址
      ethernet: no

      # X-Forwarded-For 处理
      xff:
        enabled: no
        mode: extra-data    # extra-data | overwrite
        deployment: reverse # reverse | forward
        header: X-Forwarded-For
```

### 6.2 事件类型配置

每种事件类型可以独立启用/禁用，部分类型有额外选项：

```yaml
      types:
        # --- 告警 ---
        - alert:
            payload: yes              # 载荷 Base64
            payload-printable: yes    # 可打印载荷
            payload-length: yes       # 载荷长度
            packet: yes               # 完整数据包 Base64
            tagged-packets: yes       # tag 关键字的后续包
            verdict: yes              # IPS 模式最终裁决
            metadata:
              app-layer: true         # 包含应用层上下文
              flow: true              # 包含流信息
              rule:
                metadata: true        # 规则 metadata 字段
                raw: false            # 规则原文
                reference: false      # 引用信息

        # --- 协议日志 ---
        - http:
            extended: yes             # 扩展字段
            custom: [Accept-Encoding, Accept-Language]
            dump-all-headers: both    # both|request|response|none

        - dns:
            version: 3               # 2 为旧格式
            requests: yes
            responses: yes
            formats: [detailed, grouped]
            types: [a, aaaa, cname, mx, ns, ptr, txt]

        - tls:
            extended: yes
            session-resumption: no
            custom: [subject, issuer, serial, fingerprint,
                     sni, version, not_before, not_after,
                     ja3, ja3s, ja4]

        - files:
            force-magic: no
            force-hash: [md5, sha256]

        # --- 异常 ---
        - anomaly:
            enabled: yes
            types:
              decode: yes
              stream: yes
              applayer: yes
            packethdr: no

        # --- 统计 ---
        - stats:
            totals: yes
            threads: no
            deltas: no

        # --- 流记录 ---
        - flow
        - smtp
        - ssh
        - smb
        - nfs
        - dhcp:
            extended: no
        - mqtt
        - http2
        - quic
```

### 6.3 多 EVE 实例

Suricata 支持配置多个 EVE 输出实例，分别写入不同目标：

```yaml
outputs:
  # 实例 1：告警写入文件
  - eve-log:
      enabled: yes
      filename: alerts.json
      types:
        - alert

  # 实例 2：网络元数据写入 Redis
  - eve-log:
      enabled: yes
      filetype: redis
      redis:
        server: 10.0.0.1
        key: suricata-meta
      types:
        - flow
        - dns
        - http
        - tls

  # 实例 3：统计写入 syslog
  - eve-log:
      enabled: yes
      filetype: syslog
      types:
        - stats:
            totals: yes
```

## 7. EVE 日志实战分析

### 7.1 用 jq 查询 EVE 日志

```bash
# 查看所有事件类型分布
cat eve.json | jq -r '.event_type' | sort | uniq -c | sort -rn

# 筛选高危告警（severity 1-2）
cat eve.json | jq 'select(.event_type=="alert" and .alert.severity <= 2)'

# 统计告警签名 Top 10
cat eve.json | jq -r 'select(.event_type=="alert") | .alert.signature' \
  | sort | uniq -c | sort -rn | head -10

# 按 flow_id 关联：从一条告警找到完整上下文
FLOW_ID=1234567890123456
cat eve.json | jq "select(.flow_id==$FLOW_ID)"

# 查看 DNS 查询统计
cat eve.json | jq -r 'select(.event_type=="dns") | .dns.rrname' \
  | sort | uniq -c | sort -rn | head -20

# TLS SNI 统计
cat eve.json | jq -r 'select(.event_type=="tls") | .tls.sni' \
  | sort | uniq -c | sort -rn | head -20

# 流量大户（bytes_toserver + bytes_toclient > 10MB）
cat eve.json | jq 'select(.event_type=="flow" and
  (.flow.bytes_toserver + .flow.bytes_toclient) > 10485760) |
  {src: .src_ip, dst: .dest_ip, proto: .app_proto,
   bytes: (.flow.bytes_toserver + .flow.bytes_toclient)}'

# 查找使用了过期 TLS 版本的连接
cat eve.json | jq 'select(.event_type=="tls" and
  (.tls.version == "TLS 1.0" or .tls.version == "TLS 1.1"))'
```

### 7.2 用 Python 分析 EVE 日志

```python
import json
from collections import Counter

alerts = Counter()
protocols = Counter()

with open('eve.json') as f:
    for line in f:
        event = json.loads(line)
        if event['event_type'] == 'alert':
            alerts[event['alert']['signature']] += 1
        if event['event_type'] == 'flow' and 'app_proto' in event:
            protocols[event['app_proto']] += 1

print("=== Top 10 Alerts ===")
for sig, count in alerts.most_common(10):
    print(f"  {count:6d}  {sig}")

print("\n=== Protocol Distribution ===")
for proto, count in protocols.most_common():
    print(f"  {count:6d}  {proto}")
```

## 8. ELK 集成

### 8.1 架构概览

```
Suricata → eve.json → Logstash → Elasticsearch → Kibana
                      (采集+解析)    (存储+索引)    (可视化)
```

### 8.2 使用实验环境

本系列文档提供了预配置的 Docker 环境。启动 ELK 集成：

```bash
cd docs/docker

# 启动 Suricata + ELK
docker compose --profile elk up -d

# 确认所有服务正常
docker compose --profile elk ps
```

服务组件：
- **Elasticsearch** (端口 9200)：单节点模式，禁用安全认证
- **Kibana** (端口 5601)：可视化面板
- **Logstash**：从 eve.json 读取并写入 ES

### 8.3 Logstash Pipeline 配置

`docs/docker/logstash/pipeline/suricata.conf` 是我们的 Logstash 管道：

```ruby
input {
  file {
    path => "/var/log/suricata/eve.json"
    start_position => "beginning"
    sincedb_path => "/dev/null"
    codec => json
  }
}

filter {
  # 使用 EVE 的 timestamp 作为事件时间
  date {
    match => [ "timestamp", "ISO8601" ]
  }

  # 按事件类型打标签，方便 Kibana 筛选
  if [event_type] == "alert" {
    mutate { add_tag => [ "suricata-alert" ] }
  }
  if [event_type] == "dns" {
    mutate { add_tag => [ "suricata-dns" ] }
  }
  if [event_type] == "http" {
    mutate { add_tag => [ "suricata-http" ] }
  }
  if [event_type] == "tls" {
    mutate { add_tag => [ "suricata-tls" ] }
  }
  if [event_type] == "flow" {
    mutate { add_tag => [ "suricata-flow" ] }
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "suricata-%{+YYYY.MM.dd}"
  }
}
```

### 8.4 生产环境 Logstash 建议

生产环境中建议增强 Logstash 管道：

```ruby
filter {
  # 时间解析
  date {
    match => [ "timestamp", "ISO8601" ]
    target => "@timestamp"
  }

  # GeoIP 地理定位
  if [src_ip] {
    geoip {
      source => "src_ip"
      target => "geoip_src"
      database => "/usr/share/GeoIP/GeoLite2-City.mmdb"
    }
  }
  if [dest_ip] {
    geoip {
      source => "dest_ip"
      target => "geoip_dest"
      database => "/usr/share/GeoIP/GeoLite2-City.mmdb"
    }
  }

  # alert severity 映射
  if [event_type] == "alert" {
    if [alert][severity] == 1 {
      mutate { add_field => { "severity_label" => "Critical" } }
    } else if [alert][severity] == 2 {
      mutate { add_field => { "severity_label" => "High" } }
    } else if [alert][severity] == 3 {
      mutate { add_field => { "severity_label" => "Medium" } }
    }
  }

  # 删除不需要的字段以减少存储
  mutate {
    remove_field => [ "host", "[log]" ]
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "suricata-%{[event_type]}-%{+YYYY.MM.dd}"
    # 按事件类型分索引，便于生命周期管理
  }
}
```

### 8.5 Elasticsearch 索引优化

建议为 Suricata 创建索引模板：

```bash
curl -X PUT "http://localhost:9200/_index_template/suricata" \
  -H 'Content-Type: application/json' -d '{
  "index_patterns": ["suricata-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.mapping.total_fields.limit": 5000
    },
    "mappings": {
      "properties": {
        "timestamp": { "type": "date" },
        "src_ip": { "type": "ip" },
        "dest_ip": { "type": "ip" },
        "src_port": { "type": "integer" },
        "dest_port": { "type": "integer" },
        "proto": { "type": "keyword" },
        "event_type": { "type": "keyword" },
        "app_proto": { "type": "keyword" },
        "flow_id": { "type": "long" },
        "community_id": { "type": "keyword" },
        "alert": {
          "properties": {
            "signature_id": { "type": "long" },
            "signature": { "type": "text", "fields": { "keyword": { "type": "keyword" }}},
            "category": { "type": "keyword" },
            "severity": { "type": "integer" },
            "action": { "type": "keyword" }
          }
        },
        "flow": {
          "properties": {
            "bytes_toserver": { "type": "long" },
            "bytes_toclient": { "type": "long" },
            "pkts_toserver": { "type": "long" },
            "pkts_toclient": { "type": "long" },
            "state": { "type": "keyword" },
            "reason": { "type": "keyword" }
          }
        }
      }
    }
  }
}'
```

### 8.6 Kibana 可视化

在 Kibana 中创建 Data View，索引模式设为 `suricata-*`，时间字段选 `@timestamp`。

推荐仪表盘组件：

1. **告警概览**
   - 按 severity 分组的柱状图
   - 告警签名词云
   - 告警时间趋势线

2. **网络流量**
   - Top 源/目的 IP 表格
   - 协议分布饼图
   - 流量带宽趋势

3. **威胁情报**
   - GeoIP 地图显示攻击源
   - 被 DROP 的流 Top N
   - TLS 版本分布

4. **DNS 分析**
   - DNS 查询 Top N
   - 异常长域名检测
   - NXDOMAIN 统计

### 8.7 替代方案：Filebeat

在生产环境中，Filebeat 比 Logstash 更轻量。Filebeat 7.x+ 内置 Suricata 模块：

```yaml
# filebeat.yml
filebeat.modules:
  - module: suricata
    eve:
      enabled: true
      var.paths: ["/var/log/suricata/eve.json"]

output.elasticsearch:
  hosts: ["http://elasticsearch:9200"]
  index: "suricata-%{+yyyy.MM.dd}"
```

Filebeat Suricata 模块自动处理字段映射和索引模板，是最省力的集成方式。

## 9. EVE 回调扩展接口

Suricata 提供了 `SCEveRegisterCallback()` API（`src/output-eve.h:210`），允许插件向 EVE 记录注入自定义字段：

```c
// 回调函数签名
typedef void (*SCEveUserCallbackFn)(
    ThreadVars *tv, const Packet *p, Flow *f,
    SCJsonBuilder *jb, void *user);

// 注册
bool SCEveRegisterCallback(SCEveUserCallbackFn fn, void *user);
```

回调在 `OutputJsonBuilderBuffer()`（`src/output-json.c:1010`）中、JSON 对象关闭之前被调用：

```c
SCEveRunCallbacks(tv, p, f, js);  // 执行所有注册的回调
SCJbClose(js);                     // 然后关闭根对象
```

`SCEveRunCallbacks()` 的实现在 `src/output-eve.c:53`，遍历回调链表依次执行。

这个机制让插件能够为每条 EVE 记录添加额外信息（如威胁情报标签、资产信息等），而无需修改 Suricata 核心代码。

## 10. 性能注意事项

### 10.1 减少日志量

高流量环境下 EVE 日志量可能很大。优化策略：

```yaml
# 1. 只启用需要的事件类型
types:
  - alert
  - flow
  - stats
  # 不启用 http、dns 等高频事件

# 2. 关闭 metadata
metadata: no

# 3. alert 不记录 payload 和 packet
- alert:
    payload: no
    packet: no

# 4. 使用 threaded 模式减少锁竞争
threaded: true
```

### 10.2 磁盘 I/O 优化

```yaml
# 启用缓冲（减少系统调用）
buffer-size: 65535

# threaded 模式消除锁竞争
threaded: true
```

### 10.3 超大记录处理

当 JSON 记录超过 `MemBuffer` 容量时，Suricata 会尝试扩展缓冲区。如果扩展失败，记录会被丢弃并输出一次告警日志（`src/output-json.c:1026`）：

```c
if (MemBufferExpand(buffer, (uint32_t)expand_by) < 0) {
    if (!ctx->too_large_warning) {
        SCLogWarning("Formatted JSON EVE record too large, will be dropped: %s",
            partial);
        ctx->too_large_warning = true;
    }
    return;
}
```

## 11. 小结

本篇覆盖了 EVE JSON 输出系统的完整知识：

| 主题 | 要点 |
|------|------|
| 架构 | 树形 logger 层次结构，27 个子模块 |
| 公共头部 | timestamp, flow_id, event_type, 五元组 |
| 通用选项 | metadata, community_id, ethernet |
| 输出目标 | file, unix_socket, syslog, redis, 插件 |
| Community ID | SHA-1 哈希 + Base64，跨工具流关联 |
| ELK 集成 | Logstash/Filebeat → ES → Kibana |
| 扩展接口 | SCEveRegisterCallback 注入自定义字段 |

**核心源码文件索引**：

| 文件 | 关键内容 |
|------|---------|
| `src/output-json.h` | OutputJsonCtx, OutputJsonCommonSettings 结构体 |
| `src/output-json.c` | CreateEveHeader, Community ID 算法, 初始化 |
| `src/output-json-alert.c` | alert 事件日志 |
| `src/output-json-flow.c` | flow 事件日志 |
| `src/output-eve.h` | SCEveFileType 插件接口 |
| `src/output-eve.c` | filetype 注册, 回调系统 |
| `src/output.c` | RootLogger 层次结构 |
| `src/util-logopenfile.h` | LogFileType 枚举 |

---

> **下一篇预告**：第 08 篇《suricata-update 与规则管理》将深入 suricata-update 工具的使用，涵盖规则源管理、规则启用/禁用/修改、自定义规则集成等运维必备技能。
