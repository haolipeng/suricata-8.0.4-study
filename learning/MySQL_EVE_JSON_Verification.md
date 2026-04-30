# MySQL 协议解析 EVE JSON 手动验证

本文档验证 Suricata MySQL 协议解析器对 `mysql_complete.pcap` 的解析结果。

## 1. 前置条件

### 1.1 编译安装

```bash
cd /home/work/suricata-8.0.4-study && make -j$(nproc) && make install
```

### 1.2 通用说明

- MySQL 解析器仅解析 Server Greeting（Initial Handshake Packet v10），提取 `protocol_version` 和 `server_version`
- 每个 TCP 连接只解析第一个握手包，后续数据（认证、查询等）不解析
- 运行 Suricata 时需加 `-k none` 禁用 checksum 校验（pcap 中 checksum 不正确）

---

## 2. 验证步骤

### 步骤 1：使用 tshark 提取基准数据

```bash
tshark -r pcap/mysql_complete.pcap -Y "mysql" -T fields -e mysql.version
```

**输出：**
```
5.0.54
```

### 步骤 2：使用 Suricata 解析 pcap

```bash
mkdir -p /tmp/mysql_verify && rm -rf /tmp/mysql_verify/*
suricata -r pcap/mysql_complete.pcap \
    -S /dev/null \
    -c suricata.yaml \
    -l /tmp/mysql_verify \
    -k none
```

**Suricata 输出：**
```
This is Suricata version 8.0.4 RELEASE running in USER mode
read 1 file, 57 packets, 5631 bytes
```

### 步骤 3：提取 MySQL 事件

```bash
cat /tmp/mysql_verify/eve.json | jq 'select(.event_type == "mysql")'
```

**输出：**
```json
{
  "timestamp": "2008-07-17T15:50:25.136455+0800",
  "flow_id": 303369957379899,
  "pcap_cnt": 5,
  "event_type": "mysql",
  "src_ip": "192.168.0.254",
  "src_port": 56162,
  "dest_ip": "192.168.0.254",
  "dest_port": 3306,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "mysql": {
    "protocol_version": 10,
    "server_version": "5.0.54"
  }
}
```

### 步骤 4：确认协议识别

```bash
cat /tmp/mysql_verify/eve.json | jq -c 'select(.event_type == "flow") | {app_proto, dest_port}'
```

**输出：**
```json
{"app_proto":"mysql","dest_port":3306}
```

### 步骤 5：确认事务统计

```bash
cat /tmp/mysql_verify/eve.json | jq 'select(.event_type == "stats") | {
    flow: .stats.app_layer.flow.mysql,
    tx: .stats.app_layer.tx.mysql,
    error: .stats.app_layer.error.mysql
}'
```

**输出：**
```json
{
  "flow": 1,
  "tx": 1,
  "error": {
    "gap": 0,
    "alloc": 0,
    "parser": 0,
    "internal": 0
  }
}
```

---

## 3. 验证结果

### 预期输出（共 1 条 MySQL 事件）

```json
{ "protocol_version": 10, "server_version": "5.0.54" }
```

### 交叉验证

| 字段 | tshark 解析 | Suricata 解析 | 一致 |
|------|------------|---------------|------|
| server_version | 5.0.54 | 5.0.54 | ✅ |
| protocol_version | (tshark 显示为 Greeting 包) | 10 (0x0a) | ✅ |
| 协议识别 | MySQL | app_proto="mysql" | ✅ |
| 目标端口 | 3306 | dest_port=3306 | ✅ |

### 验证要点

- 握手包 `protocol_version = 10`（MySQL v10 协议）正确解析
- `server_version = "5.0.54"` 与 tshark 解析结果完全一致
- 流量被正确识别为 MySQL 协议（`app_proto: "mysql"`）
- 1 个 flow、1 个 transaction、0 个 error
- 无解析错误、无内存分配失败

---

## 4. EVE JSON 字段参考

来源：`rust/src/mysql/logger.rs`

### 顶层结构

```json
{ "mysql": { "protocol_version": 10, "server_version": "..." } }
```

### 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `protocol_version` | uint | MySQL 协议版本号，通常为 10（0x0a），对应 MySQL v10 握手协议 |
| `server_version` | string | 服务器版本字符串，如 `"5.0.54"`、`"8.0.32-0ubuntu0.22.04.1"` |

---

## 5. pcap 文件信息

| 属性 | 值 |
|------|------|
| 文件 | `pcap/mysql_complete.pcap` |
| 包数 | 57 |
| 大小 | 5631 bytes |
| 时间 | 2008-07-17 |
| 源/目标 | 192.168.0.254:56162 ↔ 192.168.0.254:3306 |
| MySQL 版本 | 5.0.54 |
| 内容 | 完整 MySQL 会话（握手 + 认证 + 多条查询 + 关闭） |
