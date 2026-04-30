# Suricata 事务（Transaction）概念详解

## 事务 = 一次完整的"问答"

最直观的理解：**客户端问一句，服务器答一句，这一对问答就是一个 Transaction。**

```
TCP 连接（一个 State）
│
├── Transaction 1:  请求 "GET /index.html"  ←→  响应 "200 OK ..."
├── Transaction 2:  请求 "GET /style.css"   ←→  响应 "200 OK ..."
├── Transaction 3:  请求 "GET /logo.png"    ←→  响应 "404 Not Found"
└── ...
```

一个 TCP 连接可以复用，发很多次请求，所以**一个 State 里会有多个 Transaction**。

## 为什么需要 Transaction？

因为 Suricata 的核心工作是**检测和记录**，这两件事都需要一个"单位"。

### 1. 检测规则针对单个事务做匹配

```
alert http any any -> any any (msg:"404 detected"; http.stat_code; content:"404"; sid:1;)
```

这条规则不是检查"整个连接"，而是检查"某一次请求-响应"。Transaction 就是这个检查单位。

### 2. EVE JSON 日志按事务输出

```json
{"timestamp":"...", "http": {"url":"/index.html", "status":200}}
{"timestamp":"...", "http": {"url":"/style.css",  "status":200}}
{"timestamp":"...", "http": {"url":"/logo.png",   "status":404}}
```

每个 Transaction 输出一条日志，不是整个连接输出一条。

### 3. 框架负责事务的生命周期管理

开发者只管创建（`new_tx`），框架会在合适的时候调用 `free_tx` 回收。这个"合适的时候"是指：检测规则跑完了、日志也写完了。

## State 与 Transaction 的关系

```
一个 TCP 连接
  └── 一个 State（TemplateState）
        ├── state_data: AppLayerStateData   // 框架要求的元数据
        ├── tx_id: u64                      // 事务编号计数器
        ├── transactions: VecDeque<Tx>      // 事务队列（核心）
        ├── request_gap: bool               // 请求方向是否有数据缺口
        └── response_gap: bool              // 响应方向是否有数据缺口
```

- **一个 TCP 连接对应一个 State**，不是两个（两个方向共享同一个 State）
- State 内部维护一个事务队列（`VecDeque`），所有 Transaction 按创建顺序排列
- 引擎调用 `parse_request` 时传请求方向的数据，调用 `parse_response` 时传响应方向的数据，但**操作的是同一个 State 实例**

## Transaction 的生命周期

以 Template 协议为例：

```
t1: 客户端发送请求
    → 引擎调用 parse_request
    → 解析器创建新事务：request = Some("..."), response = None
    → 事务状态：未完成（progress = 0）

t2: 服务器处理中...
    → 事务仍在队列中等待，response 仍为 None

t3: 服务器返回响应
    → 引擎调用 parse_response
    → 解析器找到匹配的事务，填入 response = Some("...")
    → 事务状态：已完成（progress = 1）

t4: 框架处理完成的事务
    → 检测引擎对该事务执行规则匹配
    → Logger 将该事务写入 eve.json
    → 框架调用 free_tx 回收事务
```

`Option<String>` 的设计意义正在于此：**request 和 response 不是同时到达的，`None` 表示"还没收到"。**

## tx_id 编号体系

框架的迭代器（`applayer.rs:681`）有如下逻辑：

```rust
if tx.id() < min_tx_id + 1 {
    continue;  // 跳过这个 tx
}
```

首次遍历时 `min_tx_id = 0`，条件变为 `tx.id() < 1`。如果第一个事务的 `tx_id = 0`，则 `0 < 1` 为 true，**该事务被永远跳过**。因此：

- **内部（Rust）**：tx_id 从 **1** 开始（1-based），给框架迭代器用
- **外部（C 引擎）**：tx_id 从 **0** 开始（0-based），C 端传进来的

转换关系：

```
外部 tx_id + 1 = 内部 tx_id
内部 tx_id - 1 = 外部 tx_id
```

这就是为什么 `get_tx` 和 `free_tx` 中查找时都用 `tx_id + 1`：

```rust
// get_tx：把 C 引擎传来的 0-based 转成内部 1-based
pub fn get_tx(&mut self, tx_id: u64) -> Option<&TemplateTransaction> {
    self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
}

// new_tx：先自增再赋值，保证第一个事务 tx_id = 1
fn new_tx(&mut self) -> TemplateTransaction {
    let mut tx = TemplateTransaction::new();
    self.tx_id += 1;        // 0 → 1
    tx.tx_id = self.tx_id;  // 第一个事务 tx_id = 1
    return tx;
}
```

> **踩坑警告**：如果 tx_id 从 0 开始，不会有任何报错、崩溃或警告，只是 Logger 永远不被调用，eve.json 里永远没有输出。排查难度极高。

## 不同协议的事务模型

没有唯一正确的模型，取决于协议特点。

### 请求-响应配对模型（Template / HTTP）

```rust
pub struct TemplateTransaction {
    pub request:  Option<String>,
    pub response: Option<String>,
}
```

- 客户端发请求 → 创建事务，填 request
- 服务器回响应 → 找到同一个事务，填 response
- 事务完成判定：`response.is_some()`
- 适用于请求和响应有明确一一对应关系的协议

### 单向独立模型（MMS）

```rust
pub struct MmsTransaction {
    pub pdu: Option<MmsPdu>,   // 一个事务只装一个 PDU
    pub is_request: bool,       // 用方向标志区分
}
```

- 每收到一个 PDU（无论请求还是响应），都创建一个**独立的事务**
- 没有配对关系，创建即完成（progress 始终返回 1）
- 适用于连接上可以交叉发多种不同类型 PDU、强制配对反而麻烦的协议

### 如何选择？

| 协议特点 | 推荐模型 |
|----------|----------|
| 严格的一问一答，响应和请求可明确匹配 | 请求-响应配对 |
| 交叉发送、广播、通知类消息多 | 单向独立 |
| 有 invoke_id 等可关联请求和响应的字段 | 两种都可以，按需选择 |
