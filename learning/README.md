# Suricata 深度解析系列

> 基于 Suricata 8.0.3 源码，从使用到源码，从 C 到 Rust，系统掌握这款开源网络安全引擎。

## 系列简介

本系列面向有一定网络安全基础的工程师，以 Suricata 8.0.3 源码为蓝本，系统覆盖使用运维、源码分析、Rust 专题和二次开发四大方向。每篇文章 5000-10000 字，配合 Docker 实验环境，确保所有操作可复现。

**前置要求**：

- 熟悉 C 语言（Rust 部分从零教学）
- 了解 TCP/IP 协议栈基础
- 有 Linux 基本操作经验
- 使用过 Suricata 基本功能（跑过 IDS、写过简单规则）

## 实验环境

所有实操内容均可在 Docker 环境中复现，详见 [Docker 实验环境搭建](docker/README.md)。

---

## 目录

### 板块一：环境与入门

| 编号 | 标题 | 状态 |
|------|------|------|
| 01 | [从源码编译 Suricata](01-getting-started/01-build-from-source.md) | 已完成 |
| 02 | [快速上手：第一次运行 Suricata](01-getting-started/02-first-run.md) | 已完成 |
| 03 | [配置文件全解析](01-getting-started/03-configuration.md) | 已完成 |

### 板块二：使用与运维

| 编号 | 标题 | 状态 |
|------|------|------|
| 04 | [运行模式深入](02-usage-and-ops/04-run-modes.md) | 已完成 |
| 05 | [规则编写进阶](02-usage-and-ops/05-advanced-rules.md) | 已完成 |
| 06 | [性能调优实战](02-usage-and-ops/06-performance-tuning.md) | 已完成 |
| 07 | [EVE JSON 日志与 ELK 集成](02-usage-and-ops/07-eve-json-and-elk.md) | 已完成 |
| 08 | [suricata-update 与规则管理](02-usage-and-ops/08-suricata-update-and-rule-management.md) | 已完成 |

### 板块三：架构与源码分析

| 编号 | 标题 | 状态 |
|------|------|------|
| 09 | [架构总览：数据包的一生](03-architecture-and-source/09-packet-lifecycle.md) | 已完成 |
| 10 | [解码层：协议栈逐层解包](03-architecture-and-source/10-decode-layer.md) | 已完成 |
| 11 | [流处理与 TCP 重组](03-architecture-and-source/11-stream-tcp.md) | 已完成 |
| 12 | [应用层协议检测与解析](03-architecture-and-source/12-app-layer.md) | 已完成 |
| 13 | [检测引擎（上）：规则加载与 Signature 结构](03-architecture-and-source/13-detection-engine-part1.md) | 已完成 |
| 14 | [检测引擎（下）：多模式匹配与检测执行](03-architecture-and-source/14-detection-engine-part2.md) | 已完成 |
| 15 | [输出框架与 EVE JSON 生成](03-architecture-and-source/15-output-framework.md) | 已完成 |
| 16 | [线程模型与性能架构](03-architecture-and-source/16-threading-model.md) | 待完成 |

### 板块四：Rust 专题

| 编号 | 标题 | 状态 |
|------|------|------|
| 17 | [Rust 基础速成（面向 C 程序员）](04-rust/17-rust-crash-course.md) | 待完成 |
| 18 | [C-Rust FFI 边界详解](04-rust/18-ffi-boundary.md) | 待完成 |
| 19 | [Rust 协议解析器深度剖析](04-rust/19-rust-parser-deep-dive.md) | 待完成 |
| 20 | [JA4 指纹与高级 Rust 模块](04-rust/20-ja4-and-advanced-rust.md) | 待完成 |

### 板块五：二次开发实战

| 编号 | 标题 | 状态 |
|------|------|------|
| 21 | [开发新协议解析器（C 版）](05-development/21-new-parser-c.md) | 待完成 |
| 22 | [开发新协议解析器（Rust 版）](05-development/22-new-parser-rust.md) | 待完成 |
| 23 | [自定义检测关键字开发](05-development/23-custom-detect-keyword.md) | 待完成 |
| 24 | [自定义输出插件开发](05-development/24-custom-output-plugin.md) | 待完成 |
| 25 | [动态插件系统](05-development/25-plugin-system.md) | 待完成 |

---

## 关于

- **基准版本**：Suricata 8.0.3（commit: 3bd9f773b）
- **源码仓库**：https://github.com/OISF/suricata
- **许可证**：文章内容遵循 CC BY-SA 4.0，代码示例遵循 GPL-2.0（与 Suricata 一致）
