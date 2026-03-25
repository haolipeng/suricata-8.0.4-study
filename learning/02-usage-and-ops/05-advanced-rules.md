---
title: "规则编写进阶"
series: "Suricata 深度解析"
number: 05
author: ""
date: 2026-03-12
version: "Suricata 8.0.3"
keywords: [suricata, 规则, flowbits, datasets, lua, sticky buffer, 多缓冲区]
---

# 05 - 规则编写进阶

> 本文假设读者已掌握 Suricata 规则基本语法（action、header、rule options）。我们将深入探讨进阶检测技术：sticky buffer 与多缓冲区匹配、flowbits 状态跟踪、datasets 数据集、transform 变换、阈值控制和 Lua 脚本检测。

## 规则引擎架构速览

在深入规则语法之前，先理解检测引擎如何处理规则。

### 规则加载流程

```
规则文件 (.rules)
     │
     ▼
  解析 (src/detect-parse.c)
     │ 每条规则解析为一个 Signature 结构
     ▼
  分组 (src/detect-engine-siggroup.c)
     │ 按协议、端口、地址分组
     ▼
  预过滤构建 (src/detect-engine-mpm.c)
     │ 提取 fast_pattern 构建多模式匹配器
     ▼
  就绪
```

### 核心数据结构

```c
// src/detect.h:668
typedef struct Signature_ {
    uint32_t flags;
    enum SignatureType type;     // IPONLY, PKT, APP_TX 等
    AppProto alproto;            // 关联的应用层协议
    uint8_t action;              // alert, drop, pass, reject
    DetectProto proto;           // 协议匹配
    // ...
} Signature;

// src/detect.h:356
typedef struct SigMatch_ {
    uint16_t type;               // 关键字类型（content, pcre, flowbits 等）
    SigMatchCtx *ctx;            // 关键字特定数据
    struct SigMatch_ *next;      // 链表：多个关键字按顺序匹配
} SigMatch;
```

每个关键字在 `sigmatch_table[]` 中注册自己的 `Match`、`Setup`、`Free` 函数。例如 flowbits（`src/detect-flowbits.c:71`）：

```c
void DetectFlowbitsRegister(void)
{
    sigmatch_table[DETECT_FLOWBITS].name = "flowbits";
    sigmatch_table[DETECT_FLOWBITS].Match = DetectFlowbitMatch;
    sigmatch_table[DETECT_FLOWBITS].Setup = DetectFlowbitSetup;
    sigmatch_table[DETECT_FLOWBITS].Free  = DetectFlowbitFree;
}
```

## Sticky Buffer 与多缓冲区匹配

### Sticky Buffer 基础

Sticky buffer（粘性缓冲区）是 Suricata 的核心检测概念。它指定后续 `content`、`pcre` 等匹配关键字作用于哪个数据缓冲区。

```
# 传统方式（Snort 兼容）
content:"pattern"; http_uri;        # content 先出现，修饰符在后

# Sticky buffer 方式（Suricata 推荐）
http.uri; content:"pattern";        # 缓冲区声明在前，content 在后
```

Suricata 支持的主要 sticky buffer：

**HTTP 缓冲区**：

| 关键字 | 说明 | 方向 |
|--------|------|------|
| `http.uri` | 请求 URI（规范化后） | → |
| `http.uri.raw` | 请求 URI（原始） | → |
| `http.method` | HTTP 方法 | → |
| `http.request_line` | 完整请求行 | → |
| `http.request_body` | 请求体 | → |
| `http.request_header` | 请求头（单个） | → |
| `http.host` | Host 头（规范化） | → |
| `http.host.raw` | Host 头（原始） | → |
| `http.cookie` | Cookie 头 | → |
| `http.user_agent` | User-Agent 头 | → |
| `http.content_type` | Content-Type 头 | ↔ |
| `http.response_line` | 响应行 | ← |
| `http.response_body` | 响应体 | ← |
| `http.response_header` | 响应头（单个） | ← |
| `http.stat_code` | 状态码 | ← |
| `http.stat_msg` | 状态消息 | ← |
| `http.header_names` | 所有头名称 | ↔ |

**DNS 缓冲区**：

| 关键字 | 说明 |
|--------|------|
| `dns.query` | DNS 查询名称 |
| `dns.answer.name` | DNS 应答名称 |
| `dns.opcode` | DNS 操作码 |

**TLS 缓冲区**：

| 关键字 | 说明 |
|--------|------|
| `tls.sni` | TLS Server Name Indication |
| `tls.cert_subject` | 证书主题 |
| `tls.cert_issuer` | 证书颁发者 |
| `tls.cert_serial` | 证书序列号 |
| `tls.cert_fingerprint` | 证书指纹 |
| `ja3.hash` | JA3 哈希 |
| `ja3.string` | JA3 原始字符串 |
| `ja3s.hash` | JA3S 哈希 |
| `ja4.hash` | JA4 哈希 |

### 多缓冲区匹配（Suricata 7+）

Suricata 7 引入了多缓冲区匹配能力，允许在同一事务的多个实例中分别匹配。

**场景**：一个 DNS 事务包含两个查询：
- 查询 1: `example.net`
- 查询 2: `something.com`

```
# 匹配两个不同的 dns.query 缓冲区
alert dns $HOME_NET any -> $EXTERNAL_NET any (
    msg:"DNS Multiple Query Match";
    dns.query; content:"example";       # 第一个 dns.query 缓冲区
    dns.query; content:".com";          # 第二个 dns.query 缓冲区
    sid:1; rev:1;
)
```

这条规则会告警，因为两个内容匹配分别在不同的缓冲区实例中满足。

**与传统行为的区别**：

```
# 单缓冲区内匹配（传统行为）
dns.query; content:"example"; content:".net";
# → 两个 content 在同一个缓冲区中匹配
# → 查询 "example.net" 会匹配

# 多缓冲区匹配（Suricata 7+）
dns.query; content:"example"; dns.query; content:".com";
# → 每个 dns.query 声明开启新的缓冲区实例
# → 在所有可用实例中分别匹配
```

支持多缓冲区匹配的关键字列表包括：`dns.query`、`http.request_header`、`http.response_header`、`file.name`、`file.data`、`http2.header_name`、`mqtt.subscribe.topic` 等。

### 实战规则示例

```
# 检测 HTTP 请求中同时包含特定请求头
alert http any any -> any any (
    msg:"HTTP2 Suspicious Headers Combo";
    flow:established,to_server;
    http.request_header; content:"authorization|3a 20|Bearer";
    http.request_header; content:"x-custom-debug|3a 20|true";
    sid:100001; rev:1;
)

# 检测 DNS 隧道（查询名很长）
alert dns any any -> any any (
    msg:"Possible DNS Tunnel - Long Query";
    dns.query; content:"."; offset:50;
    threshold:type both, track by_src, count 10, seconds 60;
    sid:100002; rev:1;
)
```

## Flowbits：跨规则状态跟踪

Flowbits 是 Suricata 最强大的检测特性之一，允许在同一流的不同数据包之间共享状态。

### 基本操作

| 操作 | 说明 |
|------|------|
| `flowbits:set,<name>` | 设置标志位 |
| `flowbits:isset,<name>` | 检查标志位是否已设置 |
| `flowbits:unset,<name>` | 清除标志位 |
| `flowbits:isnotset,<name>` | 检查标志位是否未设置 |
| `flowbits:toggle,<name>` | 切换标志位 |
| `flowbits:noalert` | 本规则不产生告警（仅设置状态） |

### 经典场景：登录检测

```
# 规则 1：检测登录请求，设置标志（不告警）
alert http any any -> any any (
    msg:"HTTP Login Attempt";
    flow:to_server,established;
    http.uri; content:"/api/login";
    http.method; content:"POST";
    flowbits:set,login_attempt;
    flowbits:noalert;
    sid:200001; rev:1;
)

# 规则 2：检测登录失败响应
alert http any any -> any any (
    msg:"HTTP Login Failed";
    flow:to_client,established;
    flowbits:isset,login_attempt;
    http.stat_code; content:"401";
    flowbits:unset,login_attempt;
    sid:200002; rev:1;
)

# 规则 3：检测登录成功后的敏感操作
alert http any any -> any any (
    msg:"Sensitive API After Login";
    flow:to_server,established;
    flowbits:isset,login_attempt;
    http.uri; content:"/api/admin";
    sid:200003; rev:1;
)
```

### 分组 flowbits

Flowbits 支持分组操作，同时检查多个位的逻辑组合：

```
# 设置多个位
flowbits:set,seen_request & seen_login;

# 检查所有位都已设置（AND 逻辑）
flowbits:isset,seen_request & seen_login;

# 检查任一位已设置（OR 逻辑）
flowbits:isset,seen_request | seen_login;
```

### flowbits 的源码实现

Flowbits 的状态存储在 Flow 结构体的位数组中（`src/flow-bit.h`）。每个 flowbit 名称在引擎初始化时被映射为一个整数 ID（`src/util-var-name.c`），运行时通过位操作快速检查。

## Datasets：大规模数据集匹配

Datasets 允许 Suricata 在运行时维护和查询大型数据集，非常适合黑白名单、IoC（Indicator of Compromise）匹配等场景。

### 基本用法

```
# 检查 DNS 查询是否在黑名单中
alert dns any any -> any any (
    msg:"DNS Blacklisted Domain";
    dns.query; dataset:isset,dns-blacklist,
        type string,
        load /etc/suricata/dns-blacklist.lst;
    sid:300001; rev:1;
)
```

黑名单文件格式（CSV，每行一条）：

```
malware.example.com
phishing.evil.org
c2.badsite.net
```

### Dataset 操作

| 操作 | 说明 |
|------|------|
| `dataset:isset,<name>` | 检查数据是否在集合中 |
| `dataset:isnotset,<name>` | 检查数据是否不在集合中 |
| `dataset:set,<name>` | 将数据添加到集合中 |
| `dataset:unset,<name>` | 从集合中删除数据 |

### 支持的数据类型

| 类型 | 说明 |
|------|------|
| `string` | 字符串（原始内容） |
| `md5` | MD5 哈希 |
| `sha256` | SHA-256 哈希 |
| `ipv4` | IPv4 地址 |
| `ip` | IPv4 或 IPv6 地址 |

### 结合 transform 使用

Datasets 与 transform（变换）结合使用非常强大：

```
# DNS 查询取 SHA-256 后与数据集匹配
alert dns any any -> any any (
    msg:"DNS SHA256 Blacklist Hit";
    dns.query; to_sha256;
    dataset:isset,dns-sha256-bl,
        type sha256,
        load /etc/suricata/dns-sha256.lst;
    sid:300002; rev:1;
)

# TLS SNI 取 MD5 后匹配
alert tls any any -> any any (
    msg:"TLS SNI MD5 Blacklist";
    tls.sni; to_md5;
    dataset:isset,sni-md5-bl,
        type md5,
        load /etc/suricata/sni-md5.lst;
    sid:300003; rev:1;
)
```

### 动态数据集（运行时更新）

使用 `state` 参数可以在 Suricata 运行期间持久化数据集状态：

```
# 记录所有见过的 User-Agent（动态更新）
alert http any any -> any any (
    msg:"New User-Agent Seen";
    http.user_agent;
    dataset:set,ua-seen,
        type string,
        state /var/lib/suricata/ua-seen.lst;
    sid:300004; rev:1;
)
```

`state` 选项同时兼具 `load`（启动时加载）和 `save`（退出时保存）的功能。

### 在 suricata.yaml 中预定��

```yaml
datasets:
  defaults:
    memcap: 100mb
    hashsize: 2048
  dns-blacklist:
    type: string
    load: /etc/suricata/dns-blacklist.lst
  ip-blocklist:
    type: ip
    state: /var/lib/suricata/ip-blocklist.lst
```

### datarep：带评分的数据集

`datarep` 类似 dataset，但每条数据关联一个数值评分：

```
# IP 信誉数据文件格式：IP,category,score
# 10.0.0.1,malware,100
# 10.0.0.2,scanner,50

alert ip any any -> any any (
    msg:"Connection to Low Reputation IP";
    datarep:isset,ip-reputation,
        type ip,
        load /etc/suricata/ip-reputation.lst,
        gt 80;  # 分数大于 80 才匹配
    sid:300005; rev:1;
)
```

## Transform：数据变换

Transform 关键字对 sticky buffer 的内容进行变换后再匹配，扩展了检测的灵活性。

### 可用的 transform

| 关键字 | 说明 |
|--------|------|
| `to_md5` | 计算 MD5 哈希 |
| `to_sha256` | 计算 SHA-256 哈希 |
| `dotprefix` | 在前面添加 `.`（DNS 域名前缀匹配） |
| `strip_whitespace` | 删除空白字符 |
| `compress_whitespace` | 压缩连续空白为单个空格 |
| `base64encode` | Base64 编码 |
| `base64decode` | Base64 解码 |
| `url_decode` | URL 解码 |
| `header_lowercase` | 头名称转小写 |
| `pcrexform` | 使用 PCRE 提取/替换 |
| `xbits` | 位操作变换 |

### 使用示例

```
# DNS 域名前缀匹配（防止子域名绕过）
alert dns any any -> any any (
    msg:"DNS Malicious Domain";
    dns.query; dotprefix;
    content:".malware.com";
    sid:400001; rev:1;
)
# dotprefix 在查询名前加 "."
# "malware.com" → ".malware.com"
# "sub.malware.com" → ".sub.malware.com"
# 两者都能匹配 content:".malware.com"

# URL 解码后匹配（防止编码绕过）
alert http any any -> any any (
    msg:"HTTP SQLi After URL Decode";
    http.uri; url_decode;
    content:"' OR 1=1";
    sid:400002; rev:1;
)
```

## 阈值与抑制

### threshold：频率控制

```
# 每个源 IP 每 60 秒最多告警 5 次
alert http any any -> any any (
    msg:"HTTP Brute Force";
    http.uri; content:"/login";
    http.method; content:"POST";
    threshold:type both, track by_src, count 5, seconds 60;
    sid:500001; rev:1;
)
```

| 类型 | 说明 |
|------|------|
| `threshold` | 达到计数时告警 |
| `limit` | 时间窗口内最多告警 N 次 |
| `both` | 达到计数时告警，之后在时间窗口内不再告警 |

### detection_filter：检测过滤

```
# 先匹配 10 次才开始告警
alert tcp any any -> any 22 (
    msg:"SSH Brute Force";
    flow:to_server,established;
    content:"SSH-";
    detection_filter:track by_src, count 10, seconds 60;
    sid:500002; rev:1;
)
```

### suppress：全局抑制

在 `threshold.config` 中配置：

```
# 完全抑制某个 SID
suppress gen_id 1, sig_id 2100498

# 仅针对特定源 IP 抑制
suppress gen_id 1, sig_id 2100498, track by_src, ip 10.0.0.1

# 针对子网抑制
suppress gen_id 1, sig_id 2100498, track by_src, ip 10.0.0.0/24
```

## Lua 脚本检测

当内置关键字无法满足复杂检测逻辑时，可以使用 Lua 脚本。

### 前提条件

1. 编译时启用 `--enable-lua`
2. 配置文件中允许 Lua 规则：

```yaml
security:
  lua:
    allow-rules: yes
    sandbox:
      enabled: yes
```

### 基本结构

```lua
-- /etc/suricata/lua/detect-long-ua.lua

function init(args)
    local needs = {}
    needs["http.user_agent"] = tostring(true)
    return needs
end

function match(args)
    local ua = tostring(args["http.user_agent"])
    if ua and #ua > 256 then
        return 1  -- 匹配
    end
    return 0      -- 不匹配
end
```

### 规则引用

```
alert http any any -> any any (
    msg:"HTTP Excessively Long User-Agent";
    flow:to_server,established;
    lua:detect-long-ua.lua;
    sid:600001; rev:1;
)
```

### Lua 可访问的缓冲区

Lua 脚本可以请求访问以下数据：

```lua
-- HTTP 相关
needs["http.uri"] = tostring(true)
needs["http.user_agent"] = tostring(true)
needs["http.host"] = tostring(true)
needs["http.request_body"] = tostring(true)
needs["http.response_body"] = tostring(true)
needs["http.request_headers"] = tostring(true)
needs["http.response_headers"] = tostring(true)

-- 包数据
needs["packet"] = tostring(true)
needs["payload"] = tostring(true)

-- 流数据
needs["flowvar"] = tostring(true)
needs["flowint"] = tostring(true)
```

### 复杂检测示例

```lua
-- 检测 HTTP 请求中的异常：
-- 1. User-Agent 包含可疑关键字
-- 2. 请求体中包含 Base64 编码数据
-- 3. 两个条件同时满足

function init(args)
    local needs = {}
    needs["http.user_agent"] = tostring(true)
    needs["http.request_body"] = tostring(true)
    return needs
end

function match(args)
    local ua = tostring(args["http.user_agent"])
    local body = tostring(args["http.request_body"])

    if not ua or not body then
        return 0
    end

    -- 检查 User-Agent 是否可疑
    local suspicious_ua = false
    local ua_patterns = {"curl/", "wget/", "python-requests"}
    for _, pattern in ipairs(ua_patterns) do
        if string.find(ua:lower(), pattern) then
            suspicious_ua = true
            break
        end
    end

    -- 检查请求体是否包含大量 Base64
    local b64_ratio = 0
    if #body > 100 then
        local b64_chars = body:gsub("[^A-Za-z0-9+/=]", "")
        b64_ratio = #b64_chars / #body
    end

    if suspicious_ua and b64_ratio > 0.8 then
        return 1
    end

    return 0
end
```

### Lua 性能注意事项

- Lua 规则比原生关键字慢很多（数量级差异）
- 沙箱模式限制了 IO 和网络访问
- 每个匹配的数据包都会调用 Lua 函数
- 建议使用原生关键字做预过滤，Lua 做最终判定

```
# 好的做法：先用 content 预过滤，减少 Lua 调用
alert http any any -> any any (
    msg:"Complex Detection";
    flow:to_server,established;
    http.user_agent; content:"curl";   # 预过滤
    lua:complex-check.lua;              # 详细检查
    sid:600002; rev:1;
)
```

## 规则编写最佳实践

### 1. Fast Pattern 选择

Suricata 使用多模式匹配器（MPM）进行预过滤。每条规则中最合适的 content 模式被选为 fast pattern。可以手动指定：

```
alert http any any -> any any (
    msg:"Example";
    http.uri; content:"/api/v2/";    # 较短但更具区分度
    content:"action=delete"; fast_pattern;  # 手动指定为 fast pattern
    sid:700001; rev:1;
)
```

选择原则：
- 选择最具唯一性的模式
- 避免太短的模式（<4 字节容易误匹配）
- 避免太常见的模式（增加全匹配次数）

### 2. 使用 flow 关键字

```
# 总是指定流方向
flow:to_server,established;   # 客户端到服务端，连接已建立
flow:to_client,established;   # 服务端到客户端
```

### 3. 利用 app-layer 事件

```
# 检测应用层协议异常
alert http any any -> any any (
    msg:"HTTP Protocol Anomaly";
    app-layer-event:http.invalid_request_chunk_len;
    sid:700002; rev:1;
)

alert tls any any -> any any (
    msg:"TLS Invalid Certificate";
    app-layer-event:tls.invalid_certificate;
    sid:700003; rev:1;
)
```

### 4. 合理使用 noalert

```
# 设置状态但不告警
flowbits:noalert;

# 或使用 noalert 关键字
alert http any any -> any any (
    msg:"Set State Only";
    noalert;
    flowbits:set,seen_login;
    sid:700004; rev:1;
)
```

### 5. 规则性能分析

```bash
# 编译时启用 profiling
./configure --enable-profiling-rules

# 运行后查看规则性能日志
cat /var/log/suricata/rule_perf.log
```

输出示例：

```
  Num      Rule         Gid      Rev      Ticks        %      Checks   Matches  Max Ticks
  -------- ------------ -------- -------- ------------ ------ -------- -------- ----------
  1        200001       1        1        50000        25.00  1000     50       500
  2        200002       1        1        30000        15.00  500      10       600
```

## 实战：检测 Web Shell 上传

综合运用多种进阶技术：

```
# 规则 1：检测文件上传行为（设置状态）
alert http any any -> any any (
    msg:"HTTP File Upload Detected";
    flow:to_server,established;
    http.method; content:"POST";
    http.content_type; content:"multipart/form-data";
    flowbits:set,file_upload;
    flowbits:noalert;
    sid:800001; rev:1;
)

# 规则 2：上传内容包含 PHP 代码特征
alert http any any -> any any (
    msg:"Possible WebShell Upload - PHP";
    flow:to_server,established;
    flowbits:isset,file_upload;
    http.request_body; content:"<?php";
    http.request_body; content:"eval(";
    sid:800002; rev:2;
)

# 规则 3：上传后立即访问可疑路径
alert http any any -> any any (
    msg:"WebShell Access After Upload";
    flow:to_server,established;
    flowbits:isset,file_upload;
    http.uri; content:"/uploads/"; content:".php";
    sid:800003; rev:1;
)

# 规则 4：使用 dataset 维护已知 WebShell 文件名
alert http any any -> any any (
    msg:"Known WebShell Filename";
    flow:to_server,established;
    http.uri;
    dataset:isset,webshell-names,
        type string,
        load /etc/suricata/webshell-names.lst;
    sid:800004; rev:1;
)
```

## 小结

本文覆盖了：

- Sticky buffer 和多缓冲区匹配的机制与用法
- Flowbits 跨规则状态跟踪
- Datasets 大规模数据集匹配（黑白名单、IoC）
- Transform 数据变换
- 阈值和抑制控制
- Lua 脚本检测
- 规则性能优化最佳实践

## 下一篇预告

**06 - 性能调优实战**

深入 Suricata 的多线程配置、CPU 亲和性、内存池管理、Hyperscan 加速，以及 profiling 工具的使用。
