# 第 08 篇：suricata-update 与规则管理

> **系列**：Suricata 8.0.3 源码与实战全解析
> **板块**：二、使用与运维篇
> **适用版本**：Suricata 8.0.3
> **前置阅读**：第 05 篇（规则编写进阶）

---

## 1. 规则管理概述

Suricata 的检测能力完全依赖规则。一个生产环境通常加载数万条规则，涉及多个规则源、频繁的规则更新、特定规则的启用/禁用/修改等操作。手动管理这些规则既容易出错又不可持续。

`suricata-update` 是 OISF 官方的规则管理工具，从 Suricata 4.1 开始随 Suricata 一起捆绑安装。它解决了以下问题：

| 问题 | suricata-update 的解决方案 |
|------|-------------------------|
| 规则下载 | 自动从多个规则源下载 |
| 规则合并 | 将所有规则源合并为单一 suricata.rules 文件 |
| 规则启用/禁用 | 通过 enable.conf / disable.conf 控制 |
| 规则修改 | 通过 modify.conf 修改规则动作或内容 |
| 规则降级 | 通过 drop.conf 将 alert 改为 drop |
| 版本管理 | 按 Suricata 版本过滤不兼容的规则 |

### 1.1 捆绑机制

在 Suricata 源码仓库中，`suricata-update` 通过 `scripts/bundle.sh` 从独立的 GitHub 仓库拉取并捆绑。`requirements.txt` 指定了版本：

```
# requirements.txt
suricata-update https://github.com/OISF/suricata-update 1.3.7
```

`suricata-update` 是一个独立的 Python 项目（仓库地址 https://github.com/OISF/suricata-update），有自己的版本号和文档。当前 Suricata 8.0.3 捆绑的是 1.3.7 版本。

## 2. 快速上手

### 2.1 基本用法

最简单的用法只需一条命令：

```bash
# 下载 ET Open 规则集并安装到默认路径
sudo suricata-update

# 输出示例：
# 15/1/2024 -- 10:00:00 - <Info> -- Using data-directory /var/lib/suricata
# 15/1/2024 -- 10:00:00 - <Info> -- Using Suricata configuration /etc/suricata/suricata.yaml
# 15/1/2024 -- 10:00:01 - <Info> -- Loading /etc/suricata/enable.conf
# 15/1/2024 -- 10:00:01 - <Info> -- Loading /etc/suricata/disable.conf
# 15/1/2024 -- 10:00:01 - <Info> -- Loading /etc/suricata/drop.conf
# 15/1/2024 -- 10:00:01 - <Info> -- Loading /etc/suricata/modify.conf
# 15/1/2024 -- 10:00:03 - <Info> -- Loaded 35000 rules.
# 15/1/2024 -- 10:00:03 - <Info> -- Disabled 14 rules.
# 15/1/2024 -- 10:00:03 - <Info> -- Enabled 0 rules.
# 15/1/2024 -- 10:00:03 - <Info> -- Modified 0 rules.
# 15/1/2024 -- 10:00:03 - <Info> -- Dropped 0 rules.
# 15/1/2024 -- 10:00:03 - <Info> -- Wrote 34986 rules to /var/lib/suricata/rules/suricata.rules
```

默认行为：
- 下载 ET Open 规则集（Emerging Threats 开放规则）
- 读取 `/etc/suricata/` 下的控制文件
- 合并所有规则为 `/var/lib/suricata/rules/suricata.rules`

### 2.2 Suricata 配置对接

确保 `suricata.yaml` 中的规则路径与 `suricata-update` 的输出路径一致（`suricata.yaml.in:2308`）：

```yaml
##
## Configure Suricata to load Suricata-Update managed rules.
##

default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules
```

### 2.3 更新后重载规则

更新规则后需要让 Suricata 重新加载：

```bash
# 方法 1：发送 SIGUSR2 信号（推荐，不中断检测）
sudo kill -USR2 $(pidof suricata)

# 方法 2：通过 Unix Socket（如果启用了 unix-command）
sudo suricatasc -c reload-rules

# 方法 3：重启 Suricata（会中断检测）
sudo systemctl restart suricata
```

推荐使用 SIGUSR2 或 Unix Socket 方式，实现规则热更新而不中断流量检测。

## 3. 规则源管理

### 3.1 查看可用规则源

```bash
# 首先更新规则源索引
sudo suricata-update update-sources

# 列出所有可用规则源
sudo suricata-update list-sources
```

输出类似于：

```
Name: et/open
  Vendor: Proofpoint
  Summary: Emerging Threats Open Ruleset
  License: MIT

Name: et/pro
  Vendor: Proofpoint
  Summary: Emerging Threats Pro Ruleset
  License: Commercial
  Subscription required

Name: oisf/trafficid
  Vendor: OISF
  Summary: OISF Traffic ID Ruleset
  License: MIT

Name: ptresearch/attackdetection
  Vendor: Positive Technologies
  Summary: PT Research Attack Detection Ruleset
  License: Custom

Name: sslbl/ssl-fp-blacklist
  Vendor: Abuse.ch
  Summary: Abuse.ch SSL Fingerprint Blacklist
  License: Non-Commercial

Name: sslbl/ja3-fingerprints
  Vendor: Abuse.ch
  Summary: Abuse.ch JA3 Fingerprint Ruleset
  License: Non-Commercial

Name: etnetera/aggressive
  Vendor: Etnetera
  Summary: Etnetera Aggressive IP Blacklist
  License: MIT

Name: tgreen/hunting
  Vendor: tgreen
  Summary: Threat Hunting Rules
  License: GPLv3
```

### 3.2 启用/禁用规则源

```bash
# 启用一个规则源
sudo suricata-update enable-source oisf/trafficid

# 启用需要订阅码的商业规则源
sudo suricata-update enable-source et/pro secret-code=YOUR_CODE

# 启用后需要重新运行 update 下载规则
sudo suricata-update

# 禁用一个规则源
sudo suricata-update disable-source oisf/trafficid

# 删除一个规则源（同时删除下载的规则缓存）
sudo suricata-update remove-source oisf/trafficid

# 查看当前已启用的规则源
sudo suricata-update list-enabled-sources
```

### 3.3 自定义规则源

除了官方索引中的规则源，还可以添加自定义 URL：

```bash
# 添加自定义规则源（URL 指向 .rules 文件或 .tar.gz 压缩包）
sudo suricata-update add-source custom-rules \
  https://my-server.example.com/rules/custom.rules

# 添加需要 HTTP 认证的规则源
sudo suricata-update add-source my-commercial-rules \
  https://rules.example.com/suricata.rules.tar.gz \
  secret-code=MY_LICENSE_KEY
```

### 3.4 本地规则文件

将自定义规则放在本地文件中，通过 `--local` 参数或配置文件加入合并：

```bash
# 方法 1：命令行指定本地规则文件
sudo suricata-update --local /etc/suricata/rules/local.rules

# 方法 2：在配置文件中指定
# /etc/suricata/update.yaml
local:
  - /etc/suricata/rules/local.rules
  - /etc/suricata/rules/custom-ioc.rules
```

本地规则不会被 disable.conf 等控制文件影响（除非明确指定 SID）。

## 4. 规则控制文件

suricata-update 提供四个控制文件来精细管理规则的最终状态。这些文件默认位于 `/etc/suricata/` 目录。

### 4.1 enable.conf — 启用规则

启用默认被禁用的规则。支持三种匹配方式：

```bash
# /etc/suricata/enable.conf

# 1. 按 SID 启用
2019401

# 2. 按组名启用（即规则文件名）
group:emerging-icmp.rules

# 3. 按正则表达式启用
re:trojan
re:ET\sMalware
```

### 4.2 disable.conf — 禁用规则

禁用不需要的规则，减少误报或降低性能开销：

```bash
# /etc/suricata/disable.conf

# 禁用特定 SID
2019401

# 禁用整个规则文件
group:emerging-info.rules
group:emerging-games.rules

# 禁用所有包含特定关键字的规则
re:heartbleed
re:GPL\sATTACK_RESPONSE

# 禁用低危规则（severity 3 的信息类规则）
re:classtype:misc-activity
```

**实践建议**：生产环境中通常禁用以下类别以降低噪音：
- `emerging-info.rules`：信息类规则，告警量大
- `emerging-games.rules`：游戏流量检测，非安全相关
- `emerging-p2p.rules`：P2P 流量，误报率高
- 含 `GPL` 前缀的老旧规则

### 4.3 modify.conf — 修改规则

修改规则的内容，支持正则替换。语法：

```
<匹配条件> <搜索模式> <替换内容>
```

示例：

```bash
# /etc/suricata/modify.conf

# 将所有 ET MALWARE 规则的 alert 改为 drop
re:ET\sMALWARE "alert" "drop"

# 将特定 SID 的动作改为 drop
2024001 "alert" "drop"

# 修改规则的 classtype
2024001 "classtype:trojan-activity" "classtype:attempted-admin"

# 批量将 "alert http" 改为 "alert tcp"（不推荐，仅示例）
# re:. "alert http" "alert tcp"

# 调整阈值
2019401 "threshold: type limit, track by_src, count 1, seconds 60;" \
  "threshold: type limit, track by_src, count 5, seconds 300;"
```

### 4.4 drop.conf — 丢弃规则

将匹配的 alert 规则升级为 drop（仅在 IPS 模式下有实际效果）：

```bash
# /etc/suricata/drop.conf

# 将特定 SID 设为 drop
2024001

# 将整个规则组设为 drop
group:emerging-exploit.rules

# 将所有恶意软件相关规则设为 drop
re:ET\sMALWARE
re:ET\sEXPLOIT
```

**注意**：drop.conf 本质上等价于 modify.conf 中的 `"alert" "drop"` 替换，但语法更简洁。

### 4.5 控制文件的处理顺序

suricata-update 按以下顺序处理规则：

```
1. 加载所有启用的规则源
2. 合并规则
3. 应用 enable.conf  → 启用默认禁用的规则
4. 应用 disable.conf → 禁用指定的规则
5. 应用 modify.conf  → 修改规则内容
6. 应用 drop.conf    → 将 alert 改为 drop
7. 过滤不兼容的规则（基于 Suricata 版本）
8. 写入 suricata.rules
```

## 5. 全局阈值与抑制

除了通过规则内嵌的 `threshold` 关键字控制告警频率外，Suricata 还支持全局 threshold.config 文件（`suricata.yaml.in:2319`）：

```yaml
# threshold-file: /etc/suricata/threshold.config
```

### 5.1 threshold / event_filter

全局阈值覆盖规则内的阈值设置：

```bash
# /etc/suricata/threshold.config

# 限制 SID 2002087 每个源 IP 60 秒内最多触发 10 次告警
threshold gen_id 1, sig_id 2002087, type threshold, \
  track by_src, count 10, seconds 60

# 每个源 IP 15 秒只告警 1 次
threshold gen_id 1, sig_id 2002087, type limit, \
  track by_src, count 1, seconds 15

# 先静默，达到阈值后才告警
threshold gen_id 1, sig_id 2002087, type both, \
  track by_src, count 3, seconds 5
```

track 选项：
- `by_src`：按源 IP 跟踪
- `by_dst`：按目标 IP 跟踪
- `by_rule`：全局跟踪（不分 IP）
- `by_both`：按 IP 对追踪
- `by_flow`：按流跟踪

### 5.2 suppress

抑制特定规则或特定 IP 的告警，同时保留规则的副作用（如设置 flowbit）：

```bash
# 完全抑制一条规则（相当于 noalert）
suppress gen_id 1, sig_id 2002087

# 抑制特定源 IP 的告警
suppress gen_id 1, sig_id 2002087, track by_src, ip 209.132.180.67

# 抑制子网
suppress gen_id 1, sig_id 2003614, track by_src, ip 217.110.97.128/25

# 抑制多个地址
suppress gen_id 1, sig_id 2003614, track by_src, \
  ip [192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]

# 使用变量
suppress gen_id 1, sig_id 2003614, track by_src, ip $HOME_NET

# 双向抑制（源或目标匹配都抑制）
suppress gen_id 1, sig_id 2003614, track by_either, ip 217.110.97.128/25
```

**suppress vs disable 的区别**：
- `disable.conf` 禁用规则：规则完全不加载，不消耗检测资源，但 flowbit 等副作用也不执行
- `suppress`：规则仍然检测匹配，flowbit 等副作用正常执行，只是不生成告警

### 5.3 rate_filter

根据触发频率动态改变规则动作。典型场景：暴力破解检测。

```bash
# /etc/suricata/threshold.config

# SSH 暴力破解检测：
# 规则 888 检测 SSH SYN 包，每源 IP 60 秒内超过 10 次就改为 drop，
# drop 行为持续 300 秒
rate_filter gen_id 1, sig_id 888, track by_src, \
  count 10, seconds 60, new_action drop, timeout 300
```

对应的检测规则：

```
alert tcp any any -> $MY_SSH_SERVER 22 (msg:"Connection to SSH server"; \
  flow:to_server; flags:S,12; sid:888;)
```

## 6. suricata-update 高级用法

### 6.1 配置文件

suricata-update 支持 YAML 配置文件 `/etc/suricata/update.yaml`：

```yaml
# /etc/suricata/update.yaml

# 指定 Suricata 可执行文件（用于检测版本）
suricata: /usr/bin/suricata

# 指定 Suricata 配置文件
suricata-conf: /etc/suricata/suricata.yaml

# 规则输出目录
output: /var/lib/suricata/rules/suricata.rules

# 本地规则文件
local:
  - /etc/suricata/rules/local.rules
  - /etc/suricata/rules/ioc.rules

# 控制文件路径
enable-conf: /etc/suricata/enable.conf
disable-conf: /etc/suricata/disable.conf
modify-conf: /etc/suricata/modify.conf
drop-conf: /etc/suricata/drop.conf

# 忽略的规则文件（不合并）
ignore:
  - dnp3-events.rules
  - modbus-events.rules
  - decoder-events.rules
  - stream-events.rules
  - smtp-events.rules
  - app-layer-events.rules
```

### 6.2 常用命令行参数

```bash
# 指定 Suricata 配置文件
sudo suricata-update --suricata-conf /etc/suricata/suricata.yaml

# 指定输出文件
sudo suricata-update -o /var/lib/suricata/rules/suricata.rules

# 包含本地规则
sudo suricata-update --local /etc/suricata/rules/local.rules

# 只做测试，不实际写入
sudo suricata-update --no-output

# 强制下载（忽略缓存）
sudo suricata-update --force

# 指定 disable 文件
sudo suricata-update --disable-conf /path/to/disable.conf

# 指定 Suricata 二进制（用于版本检测和规则验证）
sudo suricata-update --suricata /usr/bin/suricata

# 设置数据目录
sudo suricata-update -D /var/lib/suricata

# 输出更多调试信息
sudo suricata-update -v
```

### 6.3 缓存与离线模式

suricata-update 将下载的规则缓存在 `/var/lib/suricata/update/cache/` 目录：

```bash
# 查看缓存内容
ls -la /var/lib/suricata/update/cache/

# 清除缓存
sudo rm -rf /var/lib/suricata/update/cache/*

# 离线使用：先在有网环境下载，然后复制缓存目录到离线主机
# 有网主机
sudo suricata-update --force
tar czf suricata-rules-cache.tar.gz /var/lib/suricata/update/cache/

# 离线主机
tar xzf suricata-rules-cache.tar.gz -C /
sudo suricata-update
```

## 7. 自定义规则实践

### 7.1 本地规则文件结构

建议按功能分组组织本地规则：

```
/etc/suricata/rules/
├── local.rules          # 通用自定义规则
├── ioc-domains.rules    # IoC 域名检测规则
├── ioc-ips.rules        # IoC IP 检测规则
├── policy.rules         # 安全策略规则
└── honeypot.rules       # 蜜罐检测规则
```

### 7.2 IoC 快速转换为规则

将威胁情报的 IoC（Indicators of Compromise）转换为 Suricata 规则：

```bash
#!/bin/bash
# ioc-to-rules.sh - 将 IoC 列表转换为 Suricata 规则

SID_START=9000001
OUTPUT="/etc/suricata/rules/ioc-domains.rules"

echo "# Auto-generated IoC rules - $(date)" > "$OUTPUT"

SID=$SID_START
while read -r domain; do
    # 跳过空行和注释
    [[ -z "$domain" || "$domain" == \#* ]] && continue

    echo "alert dns any any -> any any (msg:\"IOC DNS query for $domain\"; \
dns.query; content:\"$domain\"; nocase; endswith; \
sid:$SID; rev:1; classtype:trojan-activity;)" >> "$OUTPUT"

    ((SID++))
done < /path/to/ioc-domains.txt

echo "Generated $((SID - SID_START)) rules"
```

### 7.3 与 Datasets 结合

对于大量 IoC（上千条），使用 datasets 比逐条生成规则更高效（参考第 05 篇）：

```bash
# 单条规则 + 数据集文件
alert dns any any -> any any (msg:"IOC domain match"; \
  dns.query; dataset:isset,ioc-domains,type string,load /etc/suricata/ioc-domains.lst; \
  sid:9000001; rev:1;)
```

数据集文件 `/etc/suricata/ioc-domains.lst`：

```
evil.example.com
malware.bad-domain.net
c2-server.evil.org
```

### 7.4 规则 SID 分配策略

| SID 范围 | 用途 |
|---------|------|
| 1-999999 | Snort 官方规则（GID 1） |
| 2000000-2999999 | ET/ET Pro 规则 |
| 3000000-3999999 | 保留 |
| 9000000+ | 推荐用于本地自定义规则 |

确保本地规则 SID 不与已有规则冲突。

## 8. 辅助配置文件

### 8.1 classification.config

定义规则分类与默认优先级（`suricata.yaml.in:2317`）：

```yaml
classification-file: /etc/suricata/classification.config
```

文件格式：

```
# config classification: shortname,description,priority

config classification: not-suspicious,Not Suspicious Traffic,3
config classification: unknown,Unknown Traffic,3
config classification: bad-unknown,Potentially Bad Traffic,2
config classification: attempted-recon,Attempted Information Leak,2
config classification: successful-recon-limited,Information Leak,2
config classification: successful-recon-largescale,Large Scale Information Leak,2
config classification: attempted-dos,Attempted Denial of Service,2
config classification: successful-dos,Denial of Service Attack,2
config classification: attempted-user,Attempted User Privilege Gain,1
config classification: unsuccessful-user,Unsuccessful User Privilege Gain,1
config classification: successful-user,Successful User Privilege Gain,1
config classification: attempted-admin,Attempted Administrator Privilege Gain,1
config classification: successful-admin,Successful Administrator Privilege Gain,1
config classification: trojan-activity,A Network Trojan was Detected,1
config classification: web-application-attack,Web Application Attack,1
config classification: misc-activity,Misc activity,3
```

priority 值越小，严重程度越高（1 最高）。

### 8.2 reference.config

定义告警引用 URL 的前缀：

```yaml
reference-config-file: /etc/suricata/reference.config
```

文件格式：

```
config reference: bugtraq   http://www.securityfocus.com/bid/
config reference: cve       http://cve.mitre.org/cgi-bin/cvename.cgi?name=
config reference: nessus    http://cgi.nessus.org/plugins/dump.php3?id=
config reference: url       http://
config reference: et_ref    http://doc.emergingthreats.net/
config reference: etpro     http://doc.emergingthreatspro.com/
```

当规则包含 `reference:cve,2024-1234;` 时，Suricata 会将其展开为完整 URL。

### 8.3 threshold.config

全局阈值和抑制配置（详见第 5 节）：

```yaml
# 在 suricata.yaml 中指定
threshold-file: /etc/suricata/threshold.config
```

## 9. 自动化规则管理

### 9.1 Cron 定时更新

```bash
# /etc/cron.d/suricata-update
# 每天凌晨 3 点更新规则
0 3 * * * root suricata-update && kill -USR2 $(pidof suricata)
```

更安全的写法：

```bash
#!/bin/bash
# /usr/local/bin/suricata-rules-update.sh

LOG="/var/log/suricata-update.log"

echo "=== $(date) ===" >> "$LOG"

# 更新规则
if suricata-update >> "$LOG" 2>&1; then
    echo "Rules updated successfully" >> "$LOG"

    # 验证规则语法
    if suricata -T -c /etc/suricata/suricata.yaml >> "$LOG" 2>&1; then
        echo "Rules validation passed, reloading..." >> "$LOG"
        kill -USR2 $(pidof suricata)
        echo "Reload signal sent" >> "$LOG"
    else
        echo "ERROR: Rules validation failed, NOT reloading" >> "$LOG"
    fi
else
    echo "ERROR: suricata-update failed" >> "$LOG"
fi
```

关键：更新规则后先用 `suricata -T` 验证语法，通过后再发送 SIGUSR2 重载。

### 9.2 Git 版本化管理

将规则管理文件纳入 Git 管理：

```bash
cd /etc/suricata

# 初始化 Git 仓库
git init
git add enable.conf disable.conf modify.conf drop.conf
git add rules/local.rules rules/ioc-*.rules
git commit -m "Initial rule management configuration"

# 后续修改
vim disable.conf  # 添加禁用规则
git add disable.conf
git commit -m "Disable noisy emerging-info rules"
```

### 9.3 多节点规则同步

在多传感器环境中保持规则一致：

```bash
# 方法 1：集中管理节点更新，rsync 分发
# 管理节点
suricata-update -o /var/lib/suricata/rules/suricata.rules
rsync -avz /var/lib/suricata/rules/ sensor1:/var/lib/suricata/rules/
rsync -avz /var/lib/suricata/rules/ sensor2:/var/lib/suricata/rules/
ssh sensor1 'kill -USR2 $(pidof suricata)'
ssh sensor2 'kill -USR2 $(pidof suricata)'

# 方法 2：各节点独立更新，使用相同的控制文件
# 将 enable.conf, disable.conf 等通过配置管理工具（Ansible/Salt/Puppet）分发
```

## 10. 规则调优流程

### 10.1 调优方法论

```
部署初始规则集
      ↓
运行 24-72 小时收集基线
      ↓
分析 EVE 日志，识别误报
      ↓
├── 高频误报 → disable.conf 禁用
├── 部分误报 → suppress 按 IP/网段抑制
├── 阈值过低 → threshold.config 调整阈值
├── 动作不对 → modify.conf / drop.conf 调整
└── 缺少检测 → local.rules 添加自定义规则
      ↓
验证调优效果
      ↓
重复循环
```

### 10.2 快速识别误报

```bash
# 1. 找出告警量 Top 20 的规则
cat /var/log/suricata/eve.json | \
  jq -r 'select(.event_type=="alert") |
    "\(.alert.signature_id) \(.alert.signature)"' | \
  sort | uniq -c | sort -rn | head -20

# 2. 查看特定规则的详细告警样本
cat /var/log/suricata/eve.json | \
  jq 'select(.event_type=="alert" and .alert.signature_id==2024001)' | \
  head -5

# 3. 检查告警来源 IP 分布
cat /var/log/suricata/eve.json | \
  jq -r 'select(.event_type=="alert" and .alert.signature_id==2024001) |
    .src_ip' | sort | uniq -c | sort -rn | head -10

# 4. 如果主要来自可信 IP，用 suppress 抑制
echo 'suppress gen_id 1, sig_id 2024001, track by_src, ip 10.0.0.0/8' \
  >> /etc/suricata/threshold.config
```

### 10.3 规则性能分析

参考第 06 篇的性能分析方法。在 `suricata.yaml` 中启用规则性能统计：

```yaml
profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
    sort: avgticks
    limit: 100
```

然后分析 `rule_perf.log` 找出消耗 CPU 最多的规则，对不必要的高开销规则执行禁用。

## 11. 故障排查

### 11.1 常见问题

| 问题 | 排查方式 |
|------|---------|
| 下载失败 | 检查网络连接和代理设置；尝试 `--force` 参数 |
| 规则数量为 0 | 检查是否启用了规则源（`list-enabled-sources`） |
| 规则未生效 | 确认 suricata.yaml 的 rule-files 路径正确 |
| 热更新失败 | 用 `suricata -T` 验证规则语法 |
| SID 冲突 | 本地规则使用 9000000+ 范围的 SID |

### 11.2 调试模式

```bash
# 详细输出
sudo suricata-update -v

# 只做测试不写入
sudo suricata-update --no-output

# 检查某条规则的最终状态
sudo suricata-update --dump-sample-configs
grep "2024001" /var/lib/suricata/rules/suricata.rules
```

### 11.3 规则语法验证

```bash
# 使用 Suricata 的 -T 参数验证配置和规则
suricata -T -c /etc/suricata/suricata.yaml

# 验证单个规则文件
suricata -T -c /etc/suricata/suricata.yaml \
  -S /etc/suricata/rules/local.rules
```

`-T` 模式只加载配置和规则并验证，不启动检测引擎。

## 12. 小结

本篇覆盖了 Suricata 规则管理的完整流程：

| 主题 | 要点 |
|------|------|
| suricata-update | 官方规则管理工具，捆绑安装 |
| 规则源管理 | update-sources, list-sources, enable-source |
| 控制文件 | enable.conf, disable.conf, modify.conf, drop.conf |
| 全局阈值 | threshold.config: threshold, suppress, rate_filter |
| 自定义规则 | 本地规则文件 + datasets 方案 |
| 自动化 | cron 定时更新 + 语法验证 + 热重载 |
| 调优流程 | 收集基线 → 识别误报 → 调整控制文件 → 验证 |

**核心目录索引**：

| 路径 | 用途 |
|------|------|
| `/var/lib/suricata/rules/suricata.rules` | suricata-update 输出的合并规则文件 |
| `/var/lib/suricata/update/cache/` | 规则下载缓存 |
| `/etc/suricata/enable.conf` | 启用规则 |
| `/etc/suricata/disable.conf` | 禁用规则 |
| `/etc/suricata/modify.conf` | 修改规则 |
| `/etc/suricata/drop.conf` | 升级规则为 drop |
| `/etc/suricata/threshold.config` | 全局阈值和抑制 |
| `/etc/suricata/classification.config` | 规则分类定义 |
| `/etc/suricata/reference.config` | 引用 URL 前缀 |

---

> **下一篇预告**：第 09 篇《整体架构与模块总览》将正式进入源码分析阶段，从 `main()` 入口出发，俯瞰 Suricata 的模块化架构设计，理解数据包从进入到输出的完整生命周期。
