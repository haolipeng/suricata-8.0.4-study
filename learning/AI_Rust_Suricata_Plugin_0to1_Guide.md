# AI 工具版：Rust 从 0 到 1 开发 Suricata 协议插件

> 目标读者：使用 Cursor/Claude Code 等 AI 编码工具的开发者。  
> 目标：让 AI 按可控步骤完成一个新的 Suricata 协议插件（Rust 实现），并可验证、可回归、可交付。

---

## 1. 使用方式与总原则

这份文档是给 AI 的执行蓝图。你每次只让 AI 做一个阶段，并要求：

1. **先读上下文再改代码**：先定位已有协议模板（建议 `applayertemplate` + 目标协议参考如 `iec61850mms`）。
2. **每轮只做一类改动**：例如“只完成 Rust parser 注册”，不要一口气改完 Rust + C + YAML + 规则。
3. **每轮都要验证证据**：必须给出执行命令、关键输出、退出码。
4. **失败先定位，再修复，再复验**：禁止只给“理论上可行”。

---

## 2. 开发阶段总览（给 AI 的任务拆解）

按下面 9 个阶段推进。每个阶段都应是一次独立对话或一次明确任务。

1. 协议需求与边界定义  
2. Rust 模块骨架初始化  
3. 事务与状态结构实现  
4. 底层 parser 与 probe 实现  
5. parse_ts/parse_tc 与事务生成打通  
6. FFI 导出与 `SCRegisterXxxParser()` 完成  
7. C 侧注册与配置接入  
8. 检测关键字（sticky buffer）与 EVE logger  
9. 回归测试与交付检查

---

## 3. 阶段化执行手册（可直接喂给 AI）

下面每一节包含：目标、AI 输入模板、产出物、验收标准。

### 阶段 1：协议边界定义

**目标**
- 明确传输层（TCP/UDP）、默认端口、事务模型、方向语义。

**给 AI 的输入模板**
```text
请先不要写代码。基于 Suricata 的 Rust app-layer 框架，帮我定义 <协议名> 插件的最小可行边界：
1) 事务如何定义
2) 状态机最少状态
3) 每个方向要解析哪些字段
4) 第一版日志最小字段集合
输出为“可实施清单”。
```

**产出物**
- 一页设计清单（事务、状态、输入输出、错误策略）。

**验收标准**
- 能回答“什么时候创建事务、什么时候完成事务、进度值怎么定义”。

---

### 阶段 2：Rust 模块骨架

**目标**
- 创建 `rust/src/<proto>/` 与 `mod.rs`，并在 `rust/src/lib.rs` 暴露模块。

**给 AI 的输入模板**
```text
请按现有代码风格创建新协议模块骨架，暂不实现业务解析：
- rust/src/<proto>/mod.rs
- rust/src/<proto>/<proto>.rs
- rust/src/<proto>/parser.rs
- 可选 detect.rs 占位
- 可选 logger.rs 占位
同时修改 rust/src/lib.rs 增加 pub mod <proto>;
完成后执行最小编译验证并反馈结果。
```

**各文件职责**

- `mod.rs` — 声明子模块与 `pub`，挂模块树。
- `<proto>.rs` — 应用层主模块（对接 Suricata 框架；具体字节解析放在 `parser.rs`，此处组装调用链）。
  - **模型**：`State`、`Transaction`、`AppLayerEvent`（以及本协议特有字段）。
  - **解析入口**：实现或转发 `parse_ts` / `parse_tc`（按流方向收包、缓冲、循环抽帧；必要时处理 gap / 不完整数据）。
  - **事务生命周期**：何时 `new` / 关联 PDU、何时视为完成、`tx_get_alstate_progress` 语义。
  - **注册与 FFI**：以下回调以 `extern "C"` 导出，并在 `SCRegisterXxxParser()` 中挂到 `RustParser`。

    | 回调函数 | 作用 | 注册位置 |
    |---|---|---|
    | `probing_parser`（函数） | 协议探测（识别是否本协议流量） | `RustParser.probe_ts` / `RustParser.probe_tc` |
    | `state_new` / `state_free` | 创建 / 释放协议状态对象 | `RustParser.state_new` / `state_free` |
    | `state_tx_free` | 按 `tx_id` 释放事务资源 | `RustParser.tx_free` |
    | `parse_ts` / `parse_tc` | 处理双向流数据并驱动事务生成 | `RustParser.parse_ts` / `parse_tc` |
    | `state_get_tx` | 按事务编号返回事务指针 | `RustParser.get_tx` |
    | `state_get_tx_count` | 返回当前状态内事务总数 | `RustParser.get_tx_count` |
    | `tx_get_alstate_progress` | 返回事务解析进度（用于框架状态判断） | `RustParser.tx_get_progress` |
    | `export_tx_data_get!` / `export_state_data_get!` | 导出 tx/state 数据访问接口（供 C 侧取数） | 宏导出符号（非 `RustParser` 字段） |
    | `SCAppLayerParserRegisterLogger` | 挂接协议日志回调 | 注册函数末尾调用 |

    完成后，C 引擎可按“探测 -> 解析 -> 查询事务 -> 释放资源 -> 日志输出”完整回调链路运行。
- `parser.rs` — 字节流协议解析与探测规则实现（如 `probe_*`）；对外注册到 `RustParser.probe_ts/probe_tc` 的回调函数通常定义在 `<proto>.rs`。
- `detect.rs` — 规则关键字、与 detect 引擎对接；骨架可空实现。
- `logger.rs` — EVE / 日志输出；骨架可空实现。
- `lib.rs` 增加 `pub mod <proto>;` — 否则该目录不参与 crate 编译。

**产出物**

- 新模块目录与可编译占位代码。

**验收标准**
- `cargo check` 通过（Rust 子工程）。

---

### 阶段 3：State/Transaction/Event

**目标**
- 建立最小可用数据模型，满足 Suricata 框架接口。

**给 AI 的输入模板**
```text
请实现最小 State/Transaction/Event：
1) Transaction 含 tx_id、核心字段、AppLayerTxData
2) State 含 tx 队列、计数器、AppLayerStateData、gap 标记
3) 实现 Transaction trait 与 State<T> trait
4) 加字段注释（中文，简洁）
不要实现复杂解析逻辑，先保证结构完整并可编译。
```

**产出物**
- `Transaction` / `State` / `AppLayerEvent` 可用定义。

**验收标准**
- trait 实现完整；结构体字段含义清晰。

---

### 阶段 4：parser 与 probe

**目标**
- 用 `nom7::streaming` 建立可增量解析的底层 parser。

**给 AI 的输入模板**
```text
请在 parser.rs 实现：
1) 最小头部解析
2) 完整帧解析（头+payload）
3) probe 函数（快速特征检查）
要求：Incomplete 路径明确返回，避免 panic。
请附带 2~3 个单元测试（合法/不完整/非法）。
```

**产出物**
- parser 函数与单元测试。

**验收标准**
- `cargo test -p suricata`（或对应范围）中新增测试通过。

---

### 阶段 5：解析主链路（parse_ts/parse_tc）

**目标**
- 收到流数据后能切帧、解析、创建事务、处理不完整数据。

**给 AI 的输入模板**
```text
请实现 parse_request/parse_response（或 parse_ts/parse_tc 入口内调用）：
1) 空输入直接 ok
2) gap 时置标记并走重同步逻辑
3) 循环解析多帧
4) 成功时创建 tx 并写入关键字段
5) Incomplete 返回 consumed/needed
6) 异常时设置 app-layer-event
完成后跑编译和相关单测。
```

**产出物**
- 解析主流程可跑通，能生成事务。

**验收标准**
- 事务计数可增长；错误路径可观测。

---

### 阶段 6：FFI 与协议注册（Rust 侧）

**目标**
- 完成 `extern "C"` 回调和 `SCRegisterXxxParser()`。

**给 AI 的输入模板**
```text
请实现并注册以下函数：
- probing_parser（协议探测，注册到 `probe_ts/probe_tc`）
- state_new/state_free/state_tx_free
- parse_ts/parse_tc
- state_get_tx/state_get_tx_count
- tx_get_alstate_progress
- export_tx_data_get!/export_state_data_get!
- SCRegisterXxxParser() 填充 RustParser
并确保调用 SCAppLayerParserRegisterLogger。
```

**产出物**
- Rust parser 注册闭环。

**验收标准**
- 框架必需回调均已挂接；无空指针注册项。

---

### 阶段 7：C 侧接入

**目标**
- 让核心引擎认识这个协议并调到 Rust 解析器。

**给 AI 的输入模板**
```text
请只做 C 侧最小接入，不改业务逻辑：
1) src/app-layer-protos.h 增加 ALPROTO_XXX
2) src/app-layer.c 注册协议字符串
3) src/app-layer-parser.c 调用 SCRegisterXxxParser()
4) 如已实现 logger，则在 src/output.c 注册 logger 与 tx 子模块
完成后说明每处改动的目的。
```

**产出物**
- C 侧四件套完成。

**验收标准**
- 运行时能识别并分发到该协议。

---

### 阶段 8：规则与日志能力

**目标**
- 让规则可匹配、EVE 可输出。

**给 AI 的输入模板**
```text
请实现最小 detect.rs + logger.rs：
1) 至少 1 个 sticky buffer（字段名可用于 content 匹配）
2) 最小 EVE JSON 输出（方向 + 类型 + 核心ID）
3) 给出 2 条示例规则（命中与不命中）
4) 给出示例日志片段
```

**产出物**
- 可检测字段与可观测日志。

**验收标准**
- 规则命中符合预期；EVE 字段稳定。

---

### 阶段 9：回归与交付

**目标**
- 从“能跑”升级到“可交付”。

**给 AI 的输入模板**
```text
请给出并执行一组回归验证：
1) 正常流量
2) 分片/粘包
3) gap/丢包
4) malformed 输入
5) 事务上限
输出每项命令、关键输出、退出码，并给出剩余风险列表。
```

**产出物**
- 可审阅的验证报告。

**验收标准**
- 有证据链（命令+输出+结论），不是口头判断。

---

## 4. AI 协作提示词模板（推荐直接复用）

### 模板 A：让 AI 先做“只读分析”
```text
你现在是 Suricata Rust 插件开发助手。
先只读，不改代码。
请在仓库中定位：
1) 最接近我目标协议的参考实现
2) 需要改动的最小文件清单（Rust/C/YAML）
3) 每个文件的改动目的（一句话）
最后给出按风险排序的实施顺序。
```

### 模板 B：让 AI 做“单阶段实现”
```text
只实现 <阶段名>，不要做其他阶段。
要求：
1) 修改前先说明将改哪些文件
2) 修改后列出变更点
3) 运行验证命令并贴关键结果
4) 若失败，先修复再复验
禁止跳过验证。
```

### 模板 C：让 AI 做“代码审查”
```text
请以 code review 方式审查我本次改动，优先找：
1) 事务生命周期错误
2) tx_id/get_tx 语义错误
3) progress/completion 不一致
4) logger 未触发路径
5) gap/incomplete 异常路径
按严重程度输出问题、影响、修复建议。
```

---

## 5. 插件最小文件清单（可复制）

以 `<proto>` 为例，建议最小集如下：

- Rust
  - `rust/src/<proto>/mod.rs`
  - `rust/src/<proto>/<proto>.rs`
  - `rust/src/<proto>/parser.rs`
  - `rust/src/<proto>/detect.rs`（可选）
  - `rust/src/<proto>/logger.rs`（可选）
  - `rust/src/lib.rs`

- C
  - `src/app-layer-protos.h`
  - `src/app-layer.c`
  - `src/app-layer-parser.c`
  - `src/output.c`（有日志时）

- 配置/生成
  - `suricata.yaml.in`
  - `rust/gen/rust-bindings.h`（通过 cbindgen 生成）

---

## 6. 验收清单（Definition of Done）

满足以下条件可认为“从 0 到 1”完成：

- [ ] 协议可识别（flow 中 `app_proto` 正确）
- [ ] 事务可创建、可迭代、可释放（无泄漏/崩溃）
- [ ] `tx_get_progress` 与 `tx_comp_st_ts/tc` 语义一致
- [ ] 至少 1 个 sticky buffer 规则可命中
- [ ] EVE JSON 可输出并含关键字段
- [ ] gap / malformed / incomplete 不会导致崩溃
- [ ] 新增 FFI 已生成绑定并通过编译
- [ ] 有可复现验证命令和结果记录

---

## 7. 常见失败模式（给 AI 的约束）

要求 AI 在提交改动时主动检查这几项：

1. **tx_id 从 1 开始**，并与 `get_tx(tx_id)` 语义一致。  
2. **C 侧四件套必须齐全**，缺任何一项都可能“沉默失败”。  
3. **必须调用 `SCAppLayerParserRegisterLogger`**，否则 eve logger 不会触发。  
4. 修改 `app-layer-protos.h` 后尽量全量重编译。  
5. 新增 FFI 后必须重新生成 `rust-bindings.h`。  

---

## 8. 建议执行节奏（7 天示例）

- Day 1: 阶段 1~2（设计 + 骨架）
- Day 2: 阶段 3（State/Transaction/Event）
- Day 3: 阶段 4（parser/probe + 测试）
- Day 4: 阶段 5~6（解析主链路 + FFI 注册）
- Day 5: 阶段 7（C 侧接入 + 配置）
- Day 6: 阶段 8（detect + logger）
- Day 7: 阶段 9（回归、文档、收口）

每天只追求“一个可验证里程碑”，不要跨阶段并行硬拼。

---

## 9. 与现有指南的关系

本文件是 AI 执行版，强调“怎么让 AI 稳定产出”。  
协议细节、代码示例与背景解释请结合：

- `learning/Suricata_Rust_Protocol_Plugin_Guide.md`

推荐做法：先让 AI 按本文件执行，再回到主指南补充协议细节与最佳实践。

