# Suricata C 语言协议解析插件开发流程（以 DNP3 为例）

## 一、需要创建的文件

以开发一个名为 `myproto` 的协议为例，需要创建以下文件：

| 文件 | 用途 |
|------|------|
| `src/app-layer-myproto.c` | 核心解析器（协议探测、请求/响应解析、状态管理） |
| `src/app-layer-myproto.h` | 数据结构和常量定义 |
| `src/detect-myproto.c` | 检测关键字实现（规则匹配） |
| `src/detect-myproto.h` | 检测模块头文件 |
| `src/output-json-myproto.c` | EVE JSON 日志输出 |
| `src/output-json-myproto.h` | 日志输出头文件 |
| `rules/myproto-events.rules` | 内置事件规则 |

## 二、核心开发步骤

### 第 1 步：定义协议数据结构（`app-layer-myproto.h`）

参考 `src/app-layer-dnp3.h`，需定义：

```c
// 1. 协议头结构体
typedef struct MyProtoHeader_ {
    uint16_t length;
    uint8_t  type;
    // ...协议特有字段
} MyProtoHeader;

// 2. 事务结构体（每个请求-响应对）
typedef struct MyProtoTransaction_ {
    uint64_t tx_id;           // 事务ID
    AppLayerTxData tx_data;   // 框架必需
    TAILQ_ENTRY(MyProtoTransaction_) next;
    // ...事务特有数据
} MyProtoTransaction;

// 3. 连接状态结构体
typedef struct MyProtoState_ {
    TAILQ_HEAD(, MyProtoTransaction_) tx_list;
    uint64_t transaction_max;
    // ...连接级状态
} MyProtoState;

// 4. 解码事件枚举
enum {
    MYPROTO_DECODER_EVENT_MALFORMED,
    MYPROTO_DECODER_EVENT_TOO_LARGE,
};
```

### 第 2 步：实现核心解析器（`app-layer-myproto.c`）

参考 `src/app-layer-dnp3.c`，必须实现以下函数：

#### 2.1 协议探测函数

```c
// 判断流量是否属于此协议（参考 dnp3 Line 280）
static uint16_t MyProtoProbingParser(Flow *f, uint8_t direction,
    const uint8_t *input, uint32_t len, uint8_t *rdir)
{
    // 检查魔数/特征字节，返回 ALPROTO_MYPROTO 或 ALPROTO_UNKNOWN
}
```

#### 2.2 请求/响应解析函数

```c
// 解析请求方向数据（参考 dnp3 Line 1120）
static AppLayerResult MyProtoParseRequest(Flow *f, void *state,
    AppLayerParserState *pstate, StreamSlice stream_slice)
{
    // 从 stream_slice 获取数据并解析
    // 创建事务、填充字段
    // 返回 APP_LAYER_OK / APP_LAYER_ERROR
}

// 解析响应方向数据（参考 dnp3 Line 1257）
static AppLayerResult MyProtoParseResponse(Flow *f, void *state,
    AppLayerParserState *pstate, StreamSlice stream_slice)
{
    // 类似请求解析
}
```

#### 2.3 状态管理函数

```c
static void *MyProtoStateAlloc(void *orig_state, AppProto proto_orig);
static void  MyProtoStateFree(void *state);
static void  MyProtoStateTxFree(void *state, uint64_t tx_id);
static void *MyProtoGetTx(void *state, uint64_t tx_id);
static uint64_t MyProtoGetTxCnt(void *state);
static int   MyProtoGetAlstateProgress(void *tx, uint8_t direction);
```

#### 2.4 注册函数（最关键）

```c
void RegisterMyProtoParsers(void)
{
    const char *proto_name = "myproto";

    // 1. 注册协议名称
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_MYPROTO, proto_name);

        // 2. 注册探测函数
        if (RunmodeIsUnittests()) {
            SCAppLayerProtoDetectPPRegister(IPPROTO_TCP, "12345",
                ALPROTO_MYPROTO, 0, sizeof(MyProtoHeader),
                STREAM_TOSERVER, MyProtoProbingParser, MyProtoProbingParser);
        }

        // 3. 注册解析器
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_MYPROTO,
            STREAM_TOSERVER, MyProtoParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_MYPROTO,
            STREAM_TOCLIENT, MyProtoParseResponse);

        // 4. 注册状态管理
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_MYPROTO,
            MyProtoStateAlloc, MyProtoStateFree);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_MYPROTO,
            MyProtoStateTxFree);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_MYPROTO,
            MyProtoGetTx);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_MYPROTO,
            MyProtoGetTxCnt);

        // 5. 注册进度跟踪
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_MYPROTO, MyProtoGetAlstateProgress);
        AppLayerParserRegisterStateProgressCompletionStatus(
            ALPROTO_MYPROTO, 1, 1);

        // 6. 注册事件处理
        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_MYPROTO,
            MyProtoStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_MYPROTO,
            MyProtoStateGetEventInfoById);

        // 7. 注册TxData获取
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_MYPROTO,
            MyProtoGetTxData);
    }
}
```

### 第 3 步：实现检测关键字（`src/detect-myproto.c`）

参考 `src/detect-dnp3.c:547`：

```c
void DetectMyProtoRegister(void)
{
    // 注册关键字，例如 myproto.command
    sigmatch_table[DETECT_AL_MYPROTO_CMD].name = "myproto.command";
    sigmatch_table[DETECT_AL_MYPROTO_CMD].desc = "match on myproto command";
    sigmatch_table[DETECT_AL_MYPROTO_CMD].Setup = DetectMyProtoCmdSetup;
    sigmatch_table[DETECT_AL_MYPROTO_CMD].Match = NULL;
    sigmatch_table[DETECT_AL_MYPROTO_CMD].AppLayerTxMatch = DetectMyProtoCmdMatch;
    sigmatch_table[DETECT_AL_MYPROTO_CMD].Free = DetectMyProtoCmdFree;
}
```

### 第 4 步：实现 JSON 日志输出（`src/output-json-myproto.c`）

参考 `src/output-json-dnp3.c:366`：

```c
void JsonMyProtoLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log",
        "JsonMyProtoLog", "eve-log.myproto",
        OutputJsonLogInitSub, ALPROTO_MYPROTO,
        JsonMyProtoLogger, JsonLogThreadInit,
        JsonLogThreadDeinit, NULL);
}
```

### 第 5 步：注册协议枚举值

在 `src/app-layer-protos.h` 中添加：

```c
ALPROTO_MYPROTO,
```

在 `src/detect-engine-register.h` 中添加检测关键字枚举。

### 第 6 步：接入框架初始化

需要在以下 3 个位置添加调用：

| 文件 | 添加内容 | DNP3 参考行号 |
|------|---------|-------------|
| `src/app-layer-parser.c:1799` | `RegisterMyProtoParsers()` | 协议解析器注册 |
| `src/detect-engine-register.c:579` | `DetectMyProtoRegister()` | 检测关键字注册 |
| `src/output.c:1155` | `JsonMyProtoLogRegister()` | JSON 日志注册 |

### 第 7 步：构建系统集成

在 `src/Makefile.am` 的 `libsuricata_c_a_SOURCES` 中添加所有 `.c` 和 `.h` 文件。

在 `rules/Makefile.am` 中添加 `myproto-events.rules`。

## 三、配置文件

在 `suricata.yaml` 中添加：

```yaml
app-layer:
  protocols:
    myproto:
      enabled: yes
      detection-ports:
        dp: 12345
```

## 四、DNP3 插件完整文件清单（参考）

### 核心源码文件

| 文件路径 | 行数 | 功能描述 |
|---------|------|---------|
| `src/app-layer-dnp3.c` | 2,685 | 主协议解析器实现 |
| `src/app-layer-dnp3.h` | 262 | 协议头和数据结构定义 |
| `src/app-layer-dnp3-objects.c` | 9,727 | DNP3 对象解码和定义 |
| `src/app-layer-dnp3-objects.h` | — | DNP3 对象类型定义 |
| `src/detect-dnp3.c` | 727 | 检测关键字实现 |
| `src/detect-dnp3.h` | 35 | 检测模块头文件 |
| `src/output-json-dnp3.c` | 371 | JSON 日志输出 |
| `src/output-json-dnp3.h` | — | JSON 输出头文件 |
| `src/output-json-dnp3-objects.c` | — | DNP3 对象 JSON 转换 |
| `src/output-json-dnp3-objects.h` | — | JSON 对象头文件 |
| `src/util-lua-dnp3.c` | 206 | Lua 库绑定 |
| `src/util-lua-dnp3.h` | 23 | Lua 模块头文件 |
| `src/util-lua-dnp3-objects.c` | — | Lua 对象绑定 |
| `src/util-lua-dnp3-objects.h` | — | Lua 对象头文件 |

### 文档和配置文件

| 文件路径 | 用途 |
|---------|------|
| `doc/userguide/rules/dnp3-keywords.rst` | 规则关键字文档 |
| `doc/userguide/lua/libs/dnp3.rst` | Lua 模块文档 |
| `rules/dnp3-events.rules` | 内置事件规则 |
| `scripts/dnp3-gen/dnp3-gen.py` | 代码生成脚本 |
| `scripts/dnp3-gen/dnp3-objects.yaml` | 对象定义文件 |

## 五、DNP3 关键注册函数一览

| 注册函数 | 文件位置 | 调用位置 |
|---------|---------|---------|
| `RegisterDNP3Parsers()` | `app-layer-dnp3.c:1562` | `app-layer-parser.c:1799` |
| `DetectDNP3Register()` | `detect-dnp3.c:547` | `detect-engine-register.c:579` |
| `JsonDNP3LogRegister()` | `output-json-dnp3.c:366` | `output.c:1155` |
| `SCLuaLoadDnp3Lib()` | `util-lua-dnp3.c:202` | `util-lua-builtins.c:48` |

## 六、DNP3 检测关键字

| 关键字 | 用途 | 语法示例 |
|--------|------|---------|
| `dnp3_func` / `dnp3.func` | 匹配功能码 | `dnp3_func:read;` |
| `dnp3_ind` / `dnp3.ind` | 匹配内部指示符标志 | `dnp3_ind:device_restart;` |
| `dnp3_obj` / `dnp3.obj` | 匹配对象类型 | `dnp3_obj:1.2;` |
| `dnp3.data` | 匹配原始应用层数据 | 用于 content 匹配 |

## 七、开发顺序总结

```
 1. app-layer-protos.h       → 添加 ALPROTO 枚举
 2. app-layer-myproto.h      → 定义数据结构
 3. app-layer-myproto.c      → 实现解析器 + RegisterMyProtoParsers()
 4. app-layer-parser.c       → 调用注册函数
 5. detect-myproto.c/h       → 实现检测关键字
 6. detect-engine-register.c → 调用检测注册
 7. output-json-myproto.c    → 实现 JSON 日志
 8. output.c                 → 调用日志注册
 9. Makefile.am              → 添加源文件
10. suricata.yaml            → 添加协议配置
```

> 这套框架是 Suricata 所有 C 语言协议解析器的标准模式，DNP3、Modbus、ENIP 等工控协议均遵循此结构。
