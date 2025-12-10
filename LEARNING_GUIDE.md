# ARM64DBI 学习指南

> 从零开始掌握 ARM64 动态二进制插桩技术

## 📚 目录

1. [前置知识](#1-前置知识)
2. [项目结构](#2-项目结构)
3. [核心概念](#3-核心概念)
4. [快速入门](#4-快速入门)
5. [深入理解](#5-深入理解)
6. [污点分析](#6-污点分析)
7. [实战练习](#7-实战练习)
8. [常见问题](#8-常见问题)

---

## 1. 前置知识

### 1.1 什么是动态二进制插桩 (DBI)?

**动态二进制插桩**是一种在程序运行时分析和修改二进制代码的技术。

```
┌─────────────────┐     翻译+插桩      ┌─────────────────┐
│   原始代码       │  ────────────►  │  插桩后代码      │
│   (未修改)       │                  │  (带回调)        │
└─────────────────┘                  └─────────────────┘
        │                                    │
        ▼                                    ▼
    正常执行                           每条指令都触发回调
```

### 1.2 为什么需要 DBI?

| 场景 | 说明 |
|------|------|
| 逆向分析 | 追踪加密算法的执行流程 |
| 漏洞挖掘 | 监控内存访问，发现越界读写 |
| 程序调试 | 无需源码即可分析程序行为 |
| 性能分析 | 统计热点代码和函数调用 |
| 污点分析 | 追踪敏感数据的传播路径 |

### 1.3 ARM64 基础知识

在学习本项目前，你需要了解：

**通用寄存器**:
- `X0-X7`: 函数参数/返回值
- `X8`: 间接结果寄存器
- `X9-X15`: 临时寄存器
- `X16-X17`: 平台保留 (IP0/IP1)
- `X18`: 平台寄存器
- `X19-X28`: 被调用者保存
- `X29 (FP)`: 帧指针
- `X30 (LR)`: 链接寄存器 (返回地址)
- `SP`: 栈指针

**常见指令**:
```asm
MOV X0, X1          ; 寄存器复制
ADD X0, X1, X2      ; 加法
SUB X0, X1, #10     ; 减法
LDR X0, [X1]        ; 从内存加载
STR X0, [X1]        ; 存储到内存
B label             ; 无条件跳转
BL func             ; 函数调用
RET                 ; 函数返回
```

---

## 2. 项目结构

```
ARM64DBI/
├── app/src/main/cpp/
│   ├── main.cpp              # 测试入口和示例代码
│   ├── types/
│   │   └── types.h           # 基础类型定义
│   └── dbi/
│       ├── DBI.h/cpp         # 核心控制器
│       ├── Translator.h/cpp  # 指令翻译器
│       ├── Assembler.h/cpp/S # ARM64 汇编生成
│       ├── Router.h/cpp/S    # 控制流路由
│       ├── Memory.h/cpp      # 内存管理
│       ├── Utils.h/cpp       # 工具函数
│       └── Taint.h/cpp       # 污点分析模块
├── README.md                 # 项目概述
├── TAINT_ANALYSIS.md         # 污点分析文档
└── LEARNING_GUIDE.md         # 本学习指南
```

### 2.1 核心组件关系图

```
┌─────────────────────────────────────────────────────────┐
│                        用户代码                          │
│  DBI::trace(target_addr, callback) ───────────────────►│
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│                      DBI (核心控制器)                     │
│  - 管理 Capstone 反汇编引擎                              │
│  - 存储用户回调函数                                      │
│  - 协调翻译和执行流程                                    │
└────────────────────────────┬────────────────────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│    Translator   │  │     Router      │  │     Memory      │
│   (指令翻译器)   │  │   (控制流路由)   │  │   (内存管理)     │
│                 │  │                 │  │                 │
│ - 扫描基本块     │  │ - 处理跳转指令   │  │ - mmap 内存池   │
│ - 翻译每条指令   │  │ - 缓存查找       │  │ - 基本块缓存    │
│ - 插入回调代码   │  │ - 按需翻译新块   │  │ - 地址映射表    │
└────────┬────────┘  └────────┬────────┘  └─────────────────┘
         │                    │
         └────────┬───────────┘
                  ▼
         ┌─────────────────┐
         │    Assembler    │
         │   (汇编生成器)   │
         │                 │
         │ - 生成机器码     │
         │ - prolog/epilog │
         │ - 跳转指令      │
         └─────────────────┘
```

---

## 3. 核心概念

### 3.1 CPU 上下文 (CPU_CONTEXT)

每次回调时，你都能获取完整的 CPU 状态：

```cpp
typedef struct CPU_CONTEXT {
    uint64_t fp;      // 帧指针 (X29)
    uint64_t lr;      // 返回地址 (X30)
    int64_t x[29];    // 通用寄存器 X0-X28
    uint64_t sp;      // 栈指针
    uint64_t pc;      // 当前指令地址
    uint64_t nzcv;    // 条件标志位
} CPU_CONTEXT;
```

### 3.2 基本块 (Basic Block)

**基本块**是一段连续的代码，只有一个入口和一个出口：

```
┌─────────────────────┐
│  入口点              │  ◄── 只能从这里进入
├─────────────────────┤
│  ADD X0, X1, X2     │
│  SUB X3, X0, #10    │
│  LDR X4, [X3]       │
│  CMP X4, X5         │
├─────────────────────┤
│  B.NE other_block   │  ◄── 只从这里离开
└─────────────────────┘
```

边界识别规则：
- 遇到 `B`, `BL`, `BR`, `RET` 等跳转指令时结束
- 遇到 `CBZ`, `CBNZ`, `TBZ`, `TBNZ` 等条件分支时结束

### 3.3 翻译过程

原始指令如何被翻译：

```
原始代码:                      翻译后代码:
────────                       ──────────

                              ┌─ prolog (保存寄存器)
                              │  STR 当前 PC 到 ctx.pc
ADD X0, X1, X2  ──翻译──►     │  MOV X0, SP
                              │  BLR callback (调用回调)
                              │  epilog (恢复寄存器)
                              └─ ADD X0, X1, X2 (复制原指令)
```

### 3.4 支持的指令类型

| 指令类型 | 示例 | 处理方式 |
|----------|------|----------|
| 普通指令 | ADD, SUB, AND | 直接复制 |
| 内存访问 | LDR, STR, LDP, STP | 直接复制 |
| 无条件跳转 | B | 计算目标 → Router |
| 条件跳转 | B.cond | 保持条件 → Router |
| 函数调用 | BL | 设置 LR → Router |
| 间接跳转 | BR | 从寄存器取目标 → Router |
| 间接调用 | BLR | 从寄存器取目标 → Router |
| 函数返回 | RET | 从 LR 取地址 → Router |
| 比较分支 | CBZ, CBNZ | 条件检查 → Router |
| 位测试分支 | TBZ, TBNZ | 位检查 → Router |
| 地址计算 | ADRP, ADR | 重新计算绝对地址 |

---

## 4. 快速入门

### 4.1 最小示例

```cpp
#include "dbi/DBI.h"

// 要追踪的目标函数
int add(int a, int b) {
    return a + b;
}

// 回调函数 - 每条指令执行前调用
void my_callback(const CPU_CONTEXT* ctx) {
    auto insn = DBI::disassemble(ctx->pc);
    LOGE("0x%llx: %s %s", ctx->pc, insn->mnemonic, insn->op_str);
}

// 使用 DBI
void test() {
    // 1. 开始追踪，获取翻译后的函数指针
    auto traced_add = (int(*)(int, int))
        DBI::trace((uint64_t)add, my_callback);
    
    // 2. 调用追踪后的函数
    int result = traced_add(10, 20);
    
    // 输出: 30 (功能与原函数完全相同)
    LOGE("Result: %d", result);
}
```

### 4.2 获取寄存器值

```cpp
// 从 Capstone 寄存器ID获取值
bool get_reg_value(aarch64_reg reg, const CPU_CONTEXT* ctx, uint64_t& out) {
    if (reg >= AARCH64_REG_X0 && reg <= AARCH64_REG_X28) {
        out = ctx->x[reg - AARCH64_REG_X0];
        return true;
    }
    if (reg >= AARCH64_REG_W0 && reg <= AARCH64_REG_W30) {
        out = ctx->x[reg - AARCH64_REG_W0] & 0xFFFFFFFF;
        return true;
    }
    switch (reg) {
        case AARCH64_REG_SP: out = ctx->sp; return true;
        case AARCH64_REG_FP: out = ctx->fp; return true;
        case AARCH64_REG_LR: out = ctx->lr; return true;
    }
    return false;
}

// 在回调中使用
void detailed_callback(const CPU_CONTEXT* ctx) {
    auto insn = DBI::disassemble(ctx->pc);
    
    // 遍历所有操作数
    for (int i = 0; i < insn->detail->aarch64.op_count; i++) {
        auto op = insn->detail->aarch64.operands[i];
        
        if (op.type == AARCH64_OP_REG) {
            const char* name = cs_reg_name(DBI::get_cs_handle(), op.reg);
            uint64_t value;
            get_reg_value(op.reg, ctx, value);
            LOGE("%s = 0x%llx", name, value);
        }
    }
}
```

---

## 5. 深入理解

### 5.1 Router 工作原理

Router 负责处理所有的控制流转移：

```cpp
// 简化版 Router 逻辑
uint64_t _router(uint64_t jump_addr, ROUTER_TYPE type) {
    // 1. 检查缓存
    auto cached = Memory::get_cache_block_meta(jump_addr);
    if (cached != nullptr) {
        return (uint64_t)cached->block_start;
    }
    
    // 2. 翻译新的基本块
    auto new_block = Memory::get_or_new_block_meta();
    Translator::scan(jump_addr, new_block, type);
    
    // 3. 返回翻译后代码地址
    return (uint64_t)new_block->block_start;
}
```

### 5.2 内存池结构

```
┌────────────────────────────────────────────────────────────┐
│                     内存池 (mmap 分配)                       │
│                     权限: RWX (可读/可写/可执行)              │
├──────────────┬──────────────┬──────────────┬──────────────┤
│  BlockMeta 0 │  BlockMeta 1 │  BlockMeta 2 │     ...      │
│  ┌────────┐  │  ┌────────┐  │  ┌────────┐  │              │
│  │ header │  │  │ header │  │  │ header │  │              │
│  │ - index│  │  │ - index│  │  │ - index│  │              │
│  │ - size │  │  │ - size │  │  │ - size │  │              │
│  ├────────┤  │  ├────────┤  │  ├────────┤  │              │
│  │  code  │  │  │  code  │  │  │  code  │  │              │
│  │ [1024] │  │  │ [1024] │  │  │ [1024] │  │              │
│  │ 条目   │  │  │ 条目   │  │  │ 条目   │  │              │
│  └────────┘  │  └────────┘  │  └────────┘  │              │
└──────────────┴──────────────┴──────────────┴──────────────┘
```

### 5.3 翻译后代码结构

一条普通指令翻译后的结构：

```
翻译后代码:
┌────────────────────────────────────────┐
│  prolog (保存上下文, ~20 条指令)         │
│    STP X29, X30, [SP, #-size]!         │
│    STP X0, X1, [SP, #16]               │
│    STP X2, X3, [SP, #32]               │
│    ... (保存所有寄存器)                  │
│    MRS X0, nzcv                        │
│    STR X0, [SP, #264]                  │
├────────────────────────────────────────┤
│  写入当前 PC                            │
│    MOVZ X0, #(pc[0:15])                │
│    MOVK X0, #(pc[16:31]), LSL #16      │
│    MOVK X0, #(pc[32:47]), LSL #32      │
│    MOVK X0, #(pc[48:63]), LSL #48      │
│    STR X0, [SP, #256]                  │
├────────────────────────────────────────┤
│  调用用户回调                           │
│    MOV X0, SP                          │
│    BLR callback_ptr                    │
├────────────────────────────────────────┤
│  epilog (恢复上下文, ~20 条指令)         │
│    LDR X0, [SP, #264]                  │
│    MSR nzcv, X0                        │
│    ... (恢复所有寄存器)                  │
│    LDP X29, X30, [SP], #size           │
├────────────────────────────────────────┤
│  原始指令                               │
│    ADD X0, X1, X2                      │
└────────────────────────────────────────┘
```

---

## 6. 污点分析

### 6.1 什么是污点分析?

**污点分析**用于追踪敏感数据在程序中的传播：

```
┌──────────────┐                      ┌──────────────┐
│   污点源      │ ────传播────►       │   污点汇      │
│  (敏感数据)   │                      │  (检查点)     │
│              │                      │              │
│ 用户输入      │  ──► 加密算法        │  输出函数     │
│ 密钥数据      │  ──► 数据处理        │  网络发送     │
│ 配置文件      │  ──► 内存操作        │  存储写入     │
└──────────────┘                      └──────────────┘
```

### 6.2 基本使用

```cpp
#include "dbi/Taint.h"

// 目标函数
void encrypt(uint8_t* data, uint8_t key, int len) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;  // XOR 加密
    }
}

// 使用污点分析
void analyze() {
    auto analyzer = TaintAnalyzer::getInstance();
    analyzer->reset();
    
    // 启用详细模式
    analyzer->get_state()->set_verbose(true);
    
    // 准备数据
    uint8_t data[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    
    // 标记污点源
    analyzer->add_watch_region((uint64_t)data, sizeof(data), TAINT_INPUT, "plaintext");
    analyzer->mark_reg_source(2, TAINT_KEY);  // key 参数在 X2
    
    // 开始追踪
    auto traced_encrypt = (void(*)(uint8_t*, uint8_t, int))
        analyzer->trace((uint64_t)encrypt);
    
    // 执行
    traced_encrypt(data, 0xAB, 5);
    
    // 查看结果
    analyzer->print_summary();
}
```

### 6.3 污点传播规则

| 指令类型 | 传播规则 |
|----------|----------|
| MOV Rd, Rn | Rd 继承 Rn 的污点 |
| ADD Rd, Rn, Rm | Rd = Rn污点 \| Rm污点 |
| EOR Rd, Rn, Rm | Rd = Rn污点 \| Rm污点 (加密常用) |
| LDR Rd, [Rn] | Rd 继承内存地址的污点 |
| STR Rs, [Rn] | 内存继承 Rs 的污点 |
| LDP Rd1, Rd2, [Rn] | 两个寄存器分别继承对应内存的污点 |

### 6.4 预定义污点标签

```cpp
#define TAINT_NONE      0x00  // 无污点
#define TAINT_INPUT     0x01  // 输入数据
#define TAINT_KEY       0x02  // 密钥数据
#define TAINT_IV        0x04  // 初始化向量
#define TAINT_OUTPUT    0x08  // 输出数据
#define TAINT_SENSITIVE 0x10  // 敏感数据
```

---

## 7. 实战练习

### 练习 1: 追踪函数调用链

目标: 追踪递归函数的调用过程

```cpp
// 斐波那契数列
int fib(int n) {
    if (n <= 1) return n;
    return fib(n-1) + fib(n-2);
}

// 任务: 实现回调，统计 fib 被调用的次数
// 提示: 检查 PC 是否等于 fib 函数入口
```

### 练习 2: 内存访问监控

目标: 检测数组越界访问

```cpp
void process_array(int* arr, int size) {
    for (int i = 0; i <= size; i++) {  // Bug: <= 应该是 <
        arr[i] = i;
    }
}

// 任务: 在回调中检测 STR/LDR 指令的访问地址
// 检查是否超出 arr 的合法范围
```

### 练习 3: 加密算法分析

目标: 分析简单加密函数的数据流

```cpp
void simple_cipher(uint8_t* data, const uint8_t* key, int len) {
    for (int i = 0; i < len; i++) {
        uint8_t k = key[i % 8];
        data[i] = (data[i] ^ k) + 0x20;
    }
}

// 任务: 
// 1. 标记 key 为 TAINT_KEY
// 2. 标记 data 为 TAINT_INPUT
// 3. 分析加密后 data 的污点状态
```

---

## 8. 常见问题

### Q1: 为什么追踪后程序变慢了?

**A**: 每条指令都会触发回调，开销很大。建议:
- 仅追踪关键函数
- 回调中避免复杂操作
- 使用条件过滤只处理感兴趣的指令

### Q2: 支持追踪系统库吗?

**A**: 理论上支持，但有以下限制:
- 系统库可能使用不支持的指令
- 某些库有反调试保护
- 需要正确解析 GOT/PLT

### Q3: 如何处理多线程?

**A**: 当前版本不支持多线程:
- 基本块缓存非线程安全
- 需要为每个线程维护独立状态
- 可以通过锁来简单支持

### Q4: 浮点/SIMD 指令支持吗?

**A**: 当前版本不保存/恢复 SIMD/FP 寄存器:
- 如果目标函数使用浮点运算，结果可能不正确
- 可以扩展 prolog/epilog 来支持

---

## 📖 进一步阅读

1. [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest)
2. [Capstone Disassembly Framework](https://www.capstone-engine.org/)
3. [项目 README](README.md)
4. [污点分析详解](TAINT_ANALYSIS.md)

---

## 🎯 学习路线建议

```
第1周: 理解基础
  ├── 阅读 ARM64 指令集基础
  ├── 运行项目自带的示例
  └── 阅读 DBI.h 和 main.cpp

第2周: 深入核心
  ├── 阅读 Translator.cpp 理解翻译过程
  ├── 阅读 Router.cpp 理解控制流
  └── 完成练习 1

第3周: 掌握污点分析
  ├── 阅读 Taint.h/cpp
  ├── 完成练习 2 和 3
  └── 尝试分析真实应用

第4周: 项目实践
  ├── 为新指令添加支持
  ├── 优化性能
  └── 编写自己的分析工具
```

---

**祝你学习愉快！** 🚀

