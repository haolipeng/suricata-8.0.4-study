# IEC 61850 MMS 协议解析器开发工作计划

## 一、项目概述

| 项目 | 内容 |
|------|------|
| 项目名称 | Suricata IEC 61850 MMS 协议深度解析插件开发 |
| 基础平台 | Suricata 8.0.4 开源 IDS/IPS 引擎 |
| 开发语言 | Rust（核心解析）+ C（框架集成） |
| 总代码量 | Rust 2,181 行 + C 集成约 15 行 + 配置 5 行 |
| 协议标准 | IEC 61850 / ISO 9506 (MMS) / RFC 1006 (TPKT) / ISO 8073 (COTP) |
| 默认监听端口 | TCP 102 |

---

## 二、工作任务分解

### 阶段一：协议调研与技术方案设计

| 编号 | 任务项 | 交付物 |
|------|--------|--------|
| 1.1 | IEC 61850 MMS 协议标准调研 | 协议栈结构分析：TCP → TPKT → COTP → Session → Presentation → MMS |
| 1.2 | ASN.1 BER 编码规范调研 | BER TLV 编码/解码方案（含多字节标签、长/短格式长度） |
| 1.3 | MMS PDU 类型与服务类型梳理 | 14 种 PDU 类型 + 42 种确认服务 + 3 种非确认服务完整清单 |
| 1.4 | Suricata 应用层插件开发框架调研 | Rust 端 `RustParser` 结构体接口规范、C 端注册机制 |

### 阶段二：核心协议解析引擎开发（Rust）

| 编号 | 任务项 | 涉及文件 | 代码量 | 技术要点 |
|------|--------|----------|--------|----------|
| 2.1 | TPKT 帧解析器实现 | `rust/src/iec61850mms/parser.rs` | 276 行 | RFC 1006 协议头解析（version/length）；基于 nom 流式解析；TPKT 探测函数 `probe_tpkt()` |
| 2.2 | COTP 帧解析器实现 | `rust/src/iec61850mms/parser.rs` | （含在 2.1） | ISO 8073 PDU 类型识别（CR/CC/DR/DT）；COTP DT 帧的 EOT 标志处理 |
| 2.3 | ASN.1 BER 编解码基础库实现 | `rust/src/iec61850mms/mms_pdu.rs` | 约 100 行 | `parse_ber_tlv()` TLV 头解析（支持多字节标签 base-128 编码）；`parse_ber_length()` 长度解码（短格式/长格式）；`parse_ber_integer()` 整数解码；`parse_ber_string()` 字符串解码 |
| 2.4 | MMS PDU 顶层解析实现 | `rust/src/iec61850mms/mms_pdu.rs` | 约 120 行 | 14 种 MMS PDU 类型识别（Context-specific tag 0~13）；`parse_mms_pdu()` 主入口函数 |
| 2.5 | MMS 确认服务类型枚举定义 | `rust/src/iec61850mms/mms_pdu.rs` | 约 200 行 | `MmsConfirmedService` 枚举 42 种服务变体；请求标签映射 `from_request_tag()`；响应标签映射 `from_response_tag()`；字符串转换 `as_str()` |
| 2.6 | MMS 非确认服务类型枚举定义 | `rust/src/iec61850mms/mms_pdu.rs` | 约 35 行 | `MmsUnconfirmedService` 枚举（InformationReport / UnsolicitedStatus / EventNotification） |
| 2.7 | Confirmed-Request 深度解析 | `rust/src/iec61850mms/mms_pdu.rs` | 约 200 行 | Invoke-ID 提取；Read 请求变量访问规格解析（域名/项名）；Write 请求同上；GetNameList 请求对象类别与域范围提取 |
| 2.8 | Confirmed-Response 解析 | `rust/src/iec61850mms/mms_pdu.rs` | 约 20 行 | Invoke-ID + 服务标签解析；支持最小化响应容错（无 service 标签时标记为 unknown） |
| 2.9 | OSI Session 层剥离 | `rust/src/iec61850mms/mms_pdu.rs` | 约 40 行 | `extract_mms_from_session()`：SPDU 类型识别（CONNECT 0x0D / ACCEPT 0x0E / Give Tokens + DT 0x01） |
| 2.10 | OSI Presentation 层剥离 | `rust/src/iec61850mms/mms_pdu.rs` | 约 50 行 | `extract_mms_from_presentation()`：fully-encoded-data (tag 0x61) 解析；PDV-list 遍历定位 MMS 上下文（context-id=1/3）；single-ASN1-type (tag 0xA0) 提取 |
| 2.11 | MMS PDU 直连判定逻辑 | `rust/src/iec61850mms/mms_pdu.rs` | 约 10 行 | `is_direct_mms_pdu()`：首字节 0xA0~0xAD 范围判定，区分直连 MMS 与 Session/Presentation 封装 |

### 阶段三：应用层状态机开发（Rust）

| 编号 | 任务项 | 涉及文件 | 代码量 | 技术要点 |
|------|--------|----------|--------|----------|
| 3.1 | 事务模型定义 | `rust/src/iec61850mms/mms.rs` | 约 80 行 | `MmsTransaction` 结构体：tx_id、request/response PDU、invoke_id、AppLayerTxData |
| 3.2 | 状态机核心逻辑 | `rust/src/iec61850mms/mms.rs` | 约 200 行 | `MmsState`：事务队列（VecDeque）管理；`handle_mms_pdu()` 请求/响应关联（基于 invoke_id 匹配）；`parse_frames()` TPKT/COTP 帧循环解析 + MMS 层分发（直连 MMS 与 Session/Presentation 双路径） |
| 3.3 | 流间隙处理 | `rust/src/iec61850mms/mms.rs` | 约 20 行 | `on_request_gap()` / `on_response_gap()`：置 gap 标志；后续数据到达时探测 TPKT 头恢复同步 |
| 3.4 | 协议探测与注册 | `rust/src/iec61850mms/mms.rs` | 约 100 行 | `iec61850_mms_probing_parser()`：基于 TPKT 特征探测；`SCRegisterIec61850MmsParser()` RustParser 结构体填充（端口 102、TCP 协议、回调函数注册） |
| 3.5 | FFI 导出函数 | `rust/src/iec61850mms/mms.rs` | 约 120 行 | 状态创建/释放、事务获取/释放/计数、解析请求/响应、进度查询等 8 个 `extern "C"` 函数 |

### 阶段四：检测规则引擎集成（Rust）

| 编号 | 任务项 | 涉及文件 | 代码量 | 技术要点 |
|------|--------|----------|--------|----------|
| 4.1 | `iec61850_mms.service` 粘性缓冲区 | `rust/src/iec61850mms/detect.rs` | 约 70 行 | 注册检测关键字；实现 setup 回调和 get 回调；支持双向匹配（TOSERVER/TOCLIENT） |
| 4.2 | `iec61850_mms.pdu_type` 粘性缓冲区 | `rust/src/iec61850mms/detect.rs` | 约 70 行 | 同上，匹配 PDU 类型字符串 |

### 阶段五：EVE JSON 日志模块（Rust + C）

| 编号 | 任务项 | 涉及文件 | 代码量 | 技术要点 |
|------|--------|----------|--------|----------|
| 5.1 | MMS 事务 JSON 序列化 | `rust/src/iec61850mms/logger.rs` | 109 行 | `log_mms_pdu()` 输出字段：PDU 类型、invoke_id、服务名、变量列表（域名/项名）、对象类别 |
| 5.2 | Logger FFI 导出 | `rust/src/iec61850mms/logger.rs` | （含在 5.1） | `SCIec61850MmsLoggerLog()` extern C 函数 |
| 5.3 | EVE 日志子模块注册 | `src/output.c` | 6 行 | `RegisterSimpleJsonApplayerLogger()` 调用 + `OutputRegisterTxSubModule()` 调用 |

### 阶段六：C 框架层集成

| 编号 | 任务项 | 涉及文件 | 代码量 | 技术要点 |
|------|--------|----------|--------|----------|
| 6.1 | 协议枚举常量定义 | `src/app-layer-protos.h` | 1 行 | 新增 `ALPROTO_IEC61850_MMS` 枚举值 |
| 6.2 | 协议名称字符串注册 | `src/app-layer.c` | 1 行 | `AppProtoRegisterProtoString(ALPROTO_IEC61850_MMS, "iec61850-mms")` |
| 6.3 | Suricata 配置文件修改 | `suricata.yaml` | 5 行 | `iec61850-mms` 协议段：启用开关 + 检测端口 102 |

### 阶段七：单元测试（Rust）

| 编号 | 任务项 | 涉及文件 | 测试数 | 覆盖范围 |
|------|--------|----------|--------|----------|
| 7.1 | BER 编解码测试 | `rust/src/iec61850mms/mms_pdu.rs` | 3 个 | BER 长度短/长格式、整数解码 |
| 7.2 | MMS PDU 解析测试 | `rust/src/iec61850mms/mms_pdu.rs` | 7 个 | InitiateRequest/Response、ConcludeRequest/Response、ConfirmedRequest(Read)、ConfirmedResponse(Read)、UnconfirmedPDU、RejectPDU |
| 7.3 | TPKT/COTP 帧测试 | `rust/src/iec61850mms/parser.rs` | 7 个 | TPKT 探测（合法/非法）、TPKT 头解析、COTP DT/CR 解析、完整帧解析、不完整帧处理 |
| 7.4 | 状态机集成测试 | `rust/src/iec61850mms/mms.rs` | 5 个 | 请求/响应解析、请求-响应匹配（invoke_id 关联）、COTP 连接建立、多帧连续解析 |
| - | **合计** | - | **22 个** | - |

### 阶段八：集成验证测试

| 编号 | 任务项 | 交付物 | 技术要点 |
|------|--------|--------|----------|
| 8.1 | 测试 pcap 文件制作/收集 | 21 个 pcap 文件 | 5 个 IEC 61850 完整协议栈 pcap + 16 个 MMS 直连 pcap，覆盖 15+ 种服务类型 |
| 8.2 | Suricata 检测规则编写 | 22 条告警规则 | 7 条 PDU 类型检测 + 15 条服务类型检测 |
| 8.3 | 批量回放测试执行 | 运行日志 + EVE JSON | 21 个 pcap 逐一回放，收集告警数、malformed 数、事务详情 |
| 8.4 | 测试结果基准表编制 | 预期结果基准表 | 汇总指标表 + MMS 事务详情基准 + 告警 SID 基准 |
| 8.5 | 自动化验证脚本编写 | `run_mms_tests.sh` | 一键执行全部测试并自动判定 PASS/FAIL（共 22 个验证项） |
| 8.6 | 测试指南文档编写 | `IEC61850_MMS_Parser_Test_Guide.md` | 634 行，含缺陷背景、修复概述、环境准备、测试步骤、预期基准、判定标准 |

### 阶段九：缺陷修复

| 编号 | 缺陷描述 | 涉及文件 | 修改量 | 修复方案 |
|------|----------|----------|--------|----------|
| 9.1 | BER 多字节标签解析缺失：tag >= 31 的 16 种 MMS 服务全部解析失败 | `rust/src/iec61850mms/mms_pdu.rs` | +30 行 | `parse_ber_tlv()` 返回类型从 u8 改为 u32，增加 base-128 多字节标签解码逻辑 |
| 9.2 | 服务枚举映射不完整：12+ 种服务类型缺失，被标记为 unknown | `rust/src/iec61850mms/mms_pdu.rs` | +100 行 | `MmsConfirmedService` 新增 25 种服务变体（Status、Rename、TakeControl、RelinquishControl、Start/Stop/Resume/Reset/Kill 等） |
| 9.3 | 不支持 OSI Session/Presentation 层：所有 IEC 61850 完整栈流量解析失败 | `rust/src/iec61850mms/mms_pdu.rs` + `rust/src/iec61850mms/mms.rs` | +120 行 | 新增 `is_direct_mms_pdu()` / `extract_mms_from_session()` / `extract_mms_from_presentation()` 三个函数；`parse_frames()` 增加双路径分发逻辑 |
| 9.4 | ConfirmedResponse 解析失败：最小化响应（仅含 invoke_id 无 service 标签）触发解析错误 | `rust/src/iec61850mms/mms_pdu.rs` | +7 行 | `parse_confirmed_response()` 容忍缺少 service 标签，标记为 `Unknown(0)` |
| 9.5 | EVE 日志模块注册缺失：MMS 事务信息不输出到 EVE JSON 日志 | `src/output.c` | +4 行 | 添加 `OutputRegisterTxSubModule()` 调用 |

---

## 三、代码模块结构

```
Suricata 源码根目录
│
├── rust/src/iec61850mms/              # Rust 核心模块（2,181 行）
│   ├── mod.rs                          # 模块声明与公共接口（26 行）
│   ├── mms_pdu.rs                      # MMS PDU 解析器核心（1,013 行）
│   │   ├── MmsConfirmedService 枚举     # 42 种确认服务类型
│   │   ├── MmsUnconfirmedService 枚举   # 3 种非确认服务类型
│   │   ├── MmsPdu 枚举                  # 14 种 PDU 类型
│   │   ├── parse_ber_tlv()              # ASN.1 BER TLV 解析（支持多字节标签）
│   │   ├── parse_mms_pdu()              # MMS PDU 主解析入口
│   │   ├── extract_mms_from_session()   # OSI Session 层剥离
│   │   ├── extract_mms_from_presentation() # OSI Presentation 层剥离
│   │   └── tests (10 个)               # 单元测试
│   │
│   ├── mms.rs                          # 应用层状态机（620 行）
│   │   ├── MmsState                     # 协议状态管理
│   │   ├── MmsTransaction               # 事务模型
│   │   ├── parse_frames()               # 帧循环解析与 MMS 层分发
│   │   ├── handle_mms_pdu()             # 请求/响应关联
│   │   ├── SCRegisterIec61850MmsParser() # 协议注册入口
│   │   └── tests (5 个)                # 单元测试
│   │
│   ├── parser.rs                       # TPKT/COTP 帧解析（276 行）
│   │   ├── parse_tpkt_cotp_frame()      # TPKT + COTP 完整帧解析
│   │   ├── probe_tpkt()                 # 协议探测函数
│   │   └── tests (7 个)                # 单元测试
│   │
│   ├── detect.rs                       # 检测关键字注册（137 行）
│   │   ├── iec61850_mms.service         # 服务名粘性缓冲区
│   │   └── iec61850_mms.pdu_type        # PDU 类型粘性缓冲区
│   │
│   └── logger.rs                       # EVE JSON 日志（109 行）
│       ├── log_mms_pdu()                # PDU 序列化
│       └── SCIec61850MmsLoggerLog()     # FFI 导出函数
│
├── src/app-layer-protos.h              # C 层：协议枚举常量
├── src/app-layer.c                     # C 层：协议名称注册
├── src/output.c                        # C 层：EVE 日志模块注册
├── suricata.yaml                       # 协议配置（端口 102）
└── IEC61850_MMS_Parser_Test_Guide.md   # 测试指南文档（634 行）
```

---

## 四、MMS 协议服务覆盖范围

### 4.1 确认服务（42 种）

| Tag | 服务名称 | Tag | 服务名称 |
|-----|----------|-----|----------|
| 0 | Status | 26 | InitiateDownloadSequence |
| 1 | GetNameList | 27 | DownloadSegment |
| 2 | Identify | 28 | TerminateDownloadSequence |
| 3 | Rename | 29 | InitiateUploadSequence |
| 4 | Read | 30 | UploadSegment |
| 5 | Write | 31 | TerminateUploadSequence |
| 6 | GetVariableAccessAttributes | 32 | RequestDomainDownload |
| 10 | GetCapabilityList | 33 | RequestDomainUpload |
| 11 | DefineNamedVariableList | 34 | LoadDomainContent |
| 12 | GetNamedVariableListAttributes | 35 | StoreDomainContent |
| 13 | DeleteNamedVariableList | 36 | DeleteDomain |
| 19 | TakeControl | 37 | GetDomainAttributes |
| 20 | RelinquishControl | 38 | CreateProgramInvocation |
| 39 | DeleteProgramInvocation | 40 | Start |
| 41 | Stop | 42 | Resume |
| 43 | Reset | 44 | Kill |
| 45 | GetProgramInvocationAttributes | 63 | GetAlarmSummary |
| 72 | ObtainFile | 73 | FileOpen |
| 74 | FileRead | 75 | FileClose |
| 76 | FileRename | 77 | FileDelete |
| 78 | FileDirectory | - | - |

### 4.2 非确认服务（3 种）

| Tag | 服务名称 |
|-----|----------|
| 0 | InformationReport |
| 1 | UnsolicitedStatus |
| 2 | EventNotification |

### 4.3 PDU 类型（14 种）

| Tag | PDU 类型 | Tag | PDU 类型 |
|-----|----------|-----|----------|
| 0 | confirmed-RequestPDU | 7 | cancel-ErrorPDU |
| 1 | confirmed-ResponsePDU | 8 | initiate-RequestPDU |
| 2 | confirmed-ErrorPDU | 9 | initiate-ResponsePDU |
| 3 | unconfirmed-PDU | 10 | initiate-ErrorPDU |
| 4 | rejectPDU | 11 | conclude-RequestPDU |
| 5 | cancel-RequestPDU | 12 | conclude-ResponsePDU |
| 6 | cancel-ResponsePDU | 13 | conclude-ErrorPDU |

---

## 五、开发时间线

| 时间节点 | 里程碑 | 交付内容 |
|----------|--------|----------|
| 2026-03-25 | 初始版本开发完成 | MMS 协议解析器基础功能（6 个 Rust 模块 1,960 行 + C 集成 9 行） |
| 2026-03-25 ~ 04-11 | 集成测试与缺陷发现 | 21 个 pcap 回放测试，发现 4 个缺陷 |
| 2026-04-11 | 缺陷修复完成 | BER 多字节标签 + 服务枚举扩展 + Session/Presentation 层支持 + EVE 日志注册（新增 257 行） |
| 2026-04-11 | 测试文档编写完成 | 测试指南文档 634 行，含完整基准数据和自动化验证脚本 |

---

## 六、技术能力覆盖

| 维度 | 具体内容 |
|------|----------|
| 协议标准 | IEC 61850、ISO 9506 (MMS)、ASN.1 BER、RFC 1006 (TPKT)、ISO 8073 (COTP)、OSI Session、OSI Presentation |
| 服务覆盖 | 42 种 MMS 确认服务 + 3 种非确认服务 + 14 种 PDU 类型 |
| 开发语言 | Rust（unsafe FFI、nom 解析器组合子、BER 手工解析）+ C（Suricata 框架集成） |
| 工程能力 | 协议探测、流式解析、事务关联（invoke_id 匹配）、流间隙恢复、检测关键字注册、EVE JSON 日志输出 |
| 测试覆盖 | 22 个 Rust 单元测试 + 21 个 pcap 集成测试 + 22 个自动化验证项 |
| 日志输出 | EVE JSON 格式，包含 PDU 类型、服务名、invoke_id、变量访问列表（域名/项名）等字段 |

---

## 七、文件清单与代码统计

| 文件路径 | 类型 | 行数 | 说明 |
|----------|------|------|------|
| `rust/src/iec61850mms/mms_pdu.rs` | Rust | 1,013 | MMS PDU 解析器核心 |
| `rust/src/iec61850mms/mms.rs` | Rust | 620 | 应用层状态机 |
| `rust/src/iec61850mms/parser.rs` | Rust | 276 | TPKT/COTP 帧解析 |
| `rust/src/iec61850mms/detect.rs` | Rust | 137 | 检测关键字注册 |
| `rust/src/iec61850mms/logger.rs` | Rust | 109 | EVE JSON 日志 |
| `rust/src/iec61850mms/mod.rs` | Rust | 26 | 模块声明 |
| `src/app-layer-protos.h` | C | 1 (新增) | 协议枚举常量 |
| `src/app-layer.c` | C | 1 (新增) | 协议名称注册 |
| `src/output.c` | C | 6 (新增) | EVE 日志模块注册 |
| `suricata.yaml` | YAML | 5 (新增) | 协议配置 |
| `IEC61850_MMS_Parser_Test_Guide.md` | Markdown | 634 | 测试指南文档 |
| **合计** | - | **2,828** | - |
