# ARM64DBI 污点分析模块使用指南

> Taint Analysis Module for ARM64DBI Framework

[![Module](https://img.shields.io/badge/module-Taint%20Analysis-red.svg)](.)
[![Platform](https://img.shields.io/badge/platform-Android%20ARM64-green.svg)](.)

## 目录

- [简介](#简介)
- [污点分析原理](#污点分析原理)
- [快速开始](#快速开始)
- [API 参考](#api-参考)
- [使用示例](#使用示例)
- [高级用法](#高级用法)
- [最佳实践](#最佳实践)
- [常见问题](#常见问题)

---

## 简介

ARM64DBI 污点分析模块是基于 ARM64DBI 动态二进制插桩框架的扩展，用于追踪数据在程序中的传播路径。它特别适用于：

| 应用场景 | 描述 |
|----------|------|
| **加密算法逆向** | 追踪密钥、明文在加密过程中的传播 |
| **安全漏洞分析** | 追踪不可信输入数据的流向 |
| **数据流分析** | 理解复杂算法中数据的处理流程 |
| **隐私泄露检测** | 监控敏感数据是否流向不安全的位置 |

### 核心特性

- ✅ **寄存器级污点追踪** - 追踪 X0-X30, SP 所有通用寄存器
- ✅ **内存级污点追踪** - 按字节粒度追踪内存污点
- ✅ **自动污点传播** - 根据指令语义自动传播污点
- ✅ **多标签支持** - 支持同时追踪多种污点类型
- ✅ **可配置规则** - 可自定义污点传播规则
- ✅ **事件记录** - 完整的污点传播事件日志
- ✅ **报告导出** - 支持导出分析报告

---

## 污点分析原理

### 基本概念

```
┌─────────────┐      ┌─────────────────┐      ┌─────────────┐
│  污点源     │ ───► │   污点传播       │ ───► │  污点汇     │
│  (Source)   │      │  (Propagation)   │      │  (Sink)     │
└─────────────┘      └─────────────────┘      └─────────────┘
     │                       │                       │
     │                       │                       │
  标记数据            根据指令语义              检测到污点
  为污点              传播污点标签              到达监控点
```

### 污点传播规则

| 指令类型 | 传播规则 | 示例 |
|----------|----------|------|
| **数据移动** | `taint(dst) = taint(src)` | `MOV X0, X1` |
| **算术运算** | `taint(dst) = taint(src1) \| taint(src2)` | `ADD X0, X1, X2` |
| **逻辑运算** | `taint(dst) = taint(src1) \| taint(src2)` | `EOR X0, X1, X2` |
| **内存加载** | `taint(reg) = taint(mem[addr])` | `LDR X0, [X1]` |
| **内存存储** | `taint(mem[addr]) = taint(reg)` | `STR X0, [X1]` |
| **常量赋值** | `taint(dst) = NONE` (可配置) | `MOV X0, #0x100` |

### 支持的污点标签

```cpp
#define TAINT_NONE      0x0  // 无污点
#define TAINT_INPUT     0x1  // 输入数据 (如明文)
#define TAINT_KEY       0x2  // 密钥数据
#define TAINT_IV        0x4  // 初始化向量
#define TAINT_OUTPUT    0x8  // 输出数据
#define TAINT_SENSITIVE 0x10 // 敏感数据
#define TAINT_USER1     0x100 // 用户自定义标签1
#define TAINT_USER2     0x200 // 用户自定义标签2
#define TAINT_USER3     0x400 // 用户自定义标签3
#define TAINT_USER4     0x800 // 用户自定义标签4
```

---

## 快速开始

### 1. 包含头文件

```cpp
#include "dbi/DBI.h"
#include "dbi/Taint.h"
```

### 2. 基本使用流程

```cpp
// 目标加密函数
extern "C" void aes_encrypt(uint8_t* input, uint8_t* key, uint8_t* output);

void analyze_crypto() {
    uint8_t input[16] = {0x00, 0x11, 0x22, ...};  // 明文
    uint8_t key[16] = {0xAA, 0xBB, 0xCC, ...};    // 密钥
    uint8_t output[16] = {0};                     // 密文
    
    // 1. 获取污点分析器实例
    auto* analyzer = TaintAnalyzer::getInstance();
    
    // 2. 配置污点源
    analyzer->mark_mem_source((uint64_t)input, 16, TAINT_INPUT);   // 标记明文
    analyzer->mark_mem_source((uint64_t)key, 16, TAINT_KEY);       // 标记密钥
    
    // 3. 配置污点汇 (监控输出)
    analyzer->add_watch_region((uint64_t)output, 16, TAINT_OUTPUT, "output buffer");
    
    // 4. 启用详细日志 (可选)
    analyzer->get_state()->set_verbose(true);
    
    // 5. 开始污点追踪
    auto traced_fn = (void(*)(uint8_t*, uint8_t*, uint8_t*))
        analyzer->trace((uint64_t)aes_encrypt);
    
    // 6. 执行被追踪的函数
    traced_fn(input, key, output);
    
    // 7. 打印分析结果
    analyzer->print_summary();
    
    // 8. 导出报告 (可选)
    analyzer->export_report("/data/local/tmp/taint_report.txt");
    
    // 9. 重置分析器 (可选)
    analyzer->reset();
}
```

---

## API 参考

### TaintAnalyzer 类

#### 获取实例

```cpp
static TaintAnalyzer* getInstance();
```

获取污点分析器单例实例。

---

#### 配置选项

```cpp
void set_track_arithmetic(bool enable);  // 追踪算术运算 (默认开启)
void set_track_logic(bool enable);       // 追踪逻辑运算 (默认开启)
void set_track_memory(bool enable);      // 追踪内存操作 (默认开启)
void set_track_control_flow(bool enable); // 追踪控制流 (默认关闭)
void set_auto_clear_on_const(bool enable); // 常量覆盖时清除污点 (默认开启)
```

---

#### 污点源配置

```cpp
// 标记函数参数为污点 (arg_idx: 0-7 对应 X0-X7)
void mark_arg_taint(int arg_idx, TaintTag taint);

// 标记寄存器为污点源
void mark_reg_source(int reg_idx, TaintTag taint);

// 标记内存区域为污点源
void mark_mem_source(uint64_t addr, size_t size, TaintTag taint);

// 添加监控内存区域 (自动在读取时标记为污点)
void add_watch_region(uint64_t start, size_t size, TaintTag taint, const char* name = nullptr);
```

---

#### 污点汇配置

```cpp
// 添加污点汇点
// addr: 指令地址 (0 = 任意地址)
// reg: 寄存器索引 (-1 = 任意寄存器)
// expected: 期望的污点标签
void add_sink_point(uint64_t addr, int reg, TaintTag expected, const char* name = nullptr);

// 添加返回值汇点 (监控 X0)
void add_return_sink(TaintTag expected, const char* name = nullptr);
```

---

#### 回调设置

```cpp
// 用户自定义污点分析回调
typedef void (*TaintCallback)(const CPU_CONTEXT* ctx, TaintState* state);
void set_user_callback(TaintCallback callback);

// 污点汇检测回调
typedef void (*TaintSinkCallback)(uint64_t pc, const std::string& location, TaintTag taint, void* user_data);
void set_sink_callback(TaintSinkCallback callback, void* user_data);
```

---

#### 分析执行

```cpp
// 开始污点追踪，返回可调用的函数指针
void* trace(uint64_t target_addr);

// 获取污点状态对象
TaintState* get_state();

// 重置分析器
void reset();
```

---

#### 结果输出

```cpp
// 打印分析摘要
void print_summary();

// 导出分析报告到文件
void export_report(const char* filename);
```

---

### TaintState 类

污点状态管理类，通过 `TaintAnalyzer::get_state()` 获取。

#### 寄存器污点操作

```cpp
void set_reg_taint(int reg_idx, TaintTag taint);  // 设置寄存器污点
TaintTag get_reg_taint(int reg_idx);              // 获取寄存器污点
void clear_reg_taint(int reg_idx);                // 清除寄存器污点
TaintTag merge_reg_taint(int reg1, int reg2);     // 合并两个寄存器的污点
```

#### 内存污点操作

```cpp
void set_mem_taint(uint64_t addr, size_t size, TaintTag taint);  // 设置内存污点
TaintTag get_mem_taint(uint64_t addr);                           // 获取单字节污点
TaintTag get_mem_taint_range(uint64_t addr, size_t size);        // 获取区域污点
void clear_mem_taint(uint64_t addr, size_t size);                // 清除内存污点
```

#### 状态管理

```cpp
void reset();                    // 重置所有状态
void set_verbose(bool enable);   // 启用详细日志
void dump_state();               // 打印当前污点状态
void dump_flow_graph();          // 打印污点流图
```

---

## 使用示例

### 示例 1: 追踪 AES 加密算法

```cpp
#include "dbi/Taint.h"

// AES S-Box 查表操作分析
void analyze_aes_sbox() {
    auto* analyzer = TaintAnalyzer::getInstance();
    
    // 标记明文输入
    uint8_t plaintext[16] = {...};
    analyzer->mark_mem_source((uint64_t)plaintext, 16, TAINT_INPUT);
    
    // 标记密钥
    uint8_t key[16] = {...};
    analyzer->mark_mem_source((uint64_t)key, 16, TAINT_KEY);
    
    // 设置自定义回调，检测查表操作
    analyzer->set_user_callback([](const CPU_CONTEXT* ctx, TaintState* state) {
        auto insn = DBI::disassemble(ctx->pc);
        
        // 检测 LDR 指令 (S-Box 查表)
        if (insn->id == AARCH64_INS_LDR) {
            // 检查基址寄存器是否带有污点
            // 如果有污点，说明是基于输入数据的查表
            for (int i = 0; i < 29; i++) {
                if (state->get_reg_taint(i) & (TAINT_INPUT | TAINT_KEY)) {
                    LOGI("S-Box lookup detected at 0x%llx", ctx->pc);
                }
            }
        }
    });
    
    // 开始追踪
    auto traced = (void(*)(uint8_t*, uint8_t*, uint8_t*))
        analyzer->trace((uint64_t)aes_encrypt);
    
    uint8_t ciphertext[16];
    traced(plaintext, key, ciphertext);
    
    analyzer->print_summary();
}
```

### 示例 2: 追踪 XOR 加密操作

```cpp
void analyze_xor_crypto() {
    auto* analyzer = TaintAnalyzer::getInstance();
    analyzer->get_state()->set_verbose(true);
    
    // 标记输入
    uint8_t data[64] = {...};
    uint8_t key[8] = {...};
    
    analyzer->mark_mem_source((uint64_t)data, 64, TAINT_INPUT);
    analyzer->mark_mem_source((uint64_t)key, 8, TAINT_KEY);
    
    // 设置回调，特别关注 XOR 操作
    analyzer->set_user_callback([](const CPU_CONTEXT* ctx, TaintState* state) {
        auto insn = DBI::disassemble(ctx->pc);
        
        // EOR 指令是 XOR 操作
        if (insn->id == AARCH64_INS_EOR) {
            // 获取目标寄存器
            auto& op = insn->detail->aarch64.operands[0];
            if (op.type == AARCH64_OP_REG) {
                int dst_idx = cs_reg_to_idx(op.reg);
                TaintTag taint = state->get_reg_taint(dst_idx);
                
                // 如果同时包含 INPUT 和 KEY 污点，说明是加密核心操作
                if ((taint & TAINT_INPUT) && (taint & TAINT_KEY)) {
                    LOGI("[CRYPTO CORE] XOR of input and key at 0x%llx", ctx->pc);
                }
            }
        }
    });
    
    auto traced = (void(*)(uint8_t*, uint8_t*, size_t))
        analyzer->trace((uint64_t)xor_encrypt);
    
    traced(data, key, 64);
    analyzer->print_summary();
}
```

### 示例 3: 检测密钥泄露

```cpp
void detect_key_leak() {
    auto* analyzer = TaintAnalyzer::getInstance();
    
    uint8_t key[32] = {...};  // 敏感密钥
    
    // 标记密钥为敏感数据
    analyzer->mark_mem_source((uint64_t)key, 32, TAINT_KEY | TAINT_SENSITIVE);
    
    // 设置汇点回调，检测密钥流向
    analyzer->set_sink_callback(
        [](uint64_t pc, const std::string& loc, TaintTag taint, void* data) {
            if (taint & TAINT_SENSITIVE) {
                LOGE("[SECURITY ALERT] Sensitive data at %s (PC=0x%llx)", 
                     loc.c_str(), pc);
            }
        }, 
        nullptr
    );
    
    // 添加敏感汇点：检测函数返回值是否泄露密钥
    analyzer->add_return_sink(TAINT_SENSITIVE, "Return value leak check");
    
    // 添加敏感汇点：检测特定内存区域
    extern uint8_t log_buffer[1024];
    analyzer->add_watch_region((uint64_t)log_buffer, 1024, TAINT_NONE, "log buffer");
    
    auto traced = (int(*)(uint8_t*, size_t))
        analyzer->trace((uint64_t)process_key);
    
    traced(key, 32);
    analyzer->print_summary();
}
```

### 示例 4: 分析函数参数依赖

```cpp
void analyze_function_deps() {
    auto* analyzer = TaintAnalyzer::getInstance();
    
    // 为每个参数分配不同的污点标签
    analyzer->mark_arg_taint(0, TAINT_USER1);  // X0 - 第一个参数
    analyzer->mark_arg_taint(1, TAINT_USER2);  // X1 - 第二个参数
    analyzer->mark_arg_taint(2, TAINT_USER3);  // X2 - 第三个参数
    
    // 监控返回值，查看哪些参数影响了结果
    analyzer->add_return_sink(
        TAINT_USER1 | TAINT_USER2 | TAINT_USER3, 
        "Return value dependency"
    );
    
    auto traced = (int(*)(int, int, int))
        analyzer->trace((uint64_t)target_function);
    
    int result = traced(100, 200, 300);
    
    // 分析返回值的污点，判断依赖关系
    TaintTag ret_taint = analyzer->get_state()->get_reg_taint(0);  // X0 是返回值
    
    LOGI("Return value depends on:");
    if (ret_taint & TAINT_USER1) LOGI("  - Argument 1 (X0)");
    if (ret_taint & TAINT_USER2) LOGI("  - Argument 2 (X1)");
    if (ret_taint & TAINT_USER3) LOGI("  - Argument 3 (X2)");
    
    analyzer->print_summary();
}
```

---

## 高级用法

### 自定义污点传播规则

```cpp
void custom_propagation() {
    auto* analyzer = TaintAnalyzer::getInstance();
    
    // 禁用默认的算术运算追踪
    analyzer->set_track_arithmetic(false);
    
    // 使用自定义回调实现特殊传播规则
    analyzer->set_user_callback([](const CPU_CONTEXT* ctx, TaintState* state) {
        auto insn = DBI::disassemble(ctx->pc);
        
        // 自定义规则：对于某些特殊函数，清除所有污点
        if (ctx->pc == 0x12345678) {  // 假设这是一个清洗函数
            for (int i = 0; i < 32; i++) {
                state->clear_reg_taint(i);
            }
            return;
        }
        
        // 自定义规则：ADD 指令只传播第一个源操作数的污点
        if (insn->id == AARCH64_INS_ADD) {
            auto& ops = insn->detail->aarch64.operands;
            int dst = cs_reg_to_idx(ops[0].reg);
            int src1 = cs_reg_to_idx(ops[1].reg);
            
            state->set_reg_taint(dst, state->get_reg_taint(src1));
        }
    });
}
```

### 条件性污点标记

```cpp
void conditional_tainting() {
    auto* analyzer = TaintAnalyzer::getInstance();
    
    // 根据运行时条件动态标记污点
    analyzer->set_user_callback([](const CPU_CONTEXT* ctx, TaintState* state) {
        // 检测到特定地址时，动态标记污点
        if (ctx->pc == 0xABCD1234) {
            // 假设 X0 指向动态分配的缓冲区
            uint64_t buf_addr = ctx->x[0];
            size_t buf_size = ctx->x[1];
            
            state->mark_source_mem(buf_addr, buf_size, TAINT_INPUT, ctx->pc, 
                                   "Dynamic buffer");
        }
    });
}
```

### 污点流分析

```cpp
void analyze_taint_flow() {
    auto* analyzer = TaintAnalyzer::getInstance();
    analyzer->get_state()->set_verbose(true);
    
    // 配置污点源和汇...
    
    // 执行追踪后，分析污点流
    auto traced = ...;
    traced(...);
    
    // 获取污点流记录
    const auto& flows = analyzer->get_state()->get_flows();
    
    LOGI("Taint Flow Analysis:");
    for (const auto& flow : flows) {
        LOGI("  0x%llx [%s] -> 0x%llx [%s] : %s",
             flow.source_pc, flow.source_loc.c_str(),
             flow.dest_pc, flow.dest_loc.c_str(),
             format_taint_tag(flow.taint).c_str());
    }
}
```

---

## 最佳实践

### 1. 精确标记污点源

```cpp
// ✅ 好的做法：精确标记每种数据类型
analyzer->mark_mem_source(plaintext_addr, 16, TAINT_INPUT);
analyzer->mark_mem_source(key_addr, 16, TAINT_KEY);
analyzer->mark_mem_source(iv_addr, 16, TAINT_IV);

// ❌ 不好的做法：使用统一标签
analyzer->mark_mem_source(all_data_addr, 48, TAINT_INPUT);  // 无法区分不同类型
```

### 2. 合理设置监控点

```cpp
// ✅ 好的做法：只监控关键位置
analyzer->add_sink_point(0, 0, TAINT_KEY, "Return value");  // 监控返回值
analyzer->add_watch_region(output_addr, output_size, TAINT_OUTPUT, "Output");

// ❌ 不好的做法：监控所有位置会产生大量日志
```

### 3. 使用详细模式调试

```cpp
// 开发阶段启用详细日志
#ifdef DEBUG
analyzer->get_state()->set_verbose(true);
#endif

// 生产环境关闭
analyzer->get_state()->set_verbose(false);
```

### 4. 及时重置状态

```cpp
// 分析多个函数时，记得重置
analyzer->reset();  // 清除所有状态

// 或者只清除污点状态，保留配置
analyzer->get_state()->reset();
```

---

## 常见问题

### Q1: 为什么某些指令没有传播污点？

**A**: 检查是否启用了对应的追踪选项：

```cpp
analyzer->set_track_arithmetic(true);  // 算术运算
analyzer->set_track_logic(true);       // 逻辑运算
analyzer->set_track_memory(true);      // 内存操作
```

### Q2: 如何追踪浮点运算？

**A**: 当前版本暂不支持 SIMD/FP 寄存器的污点追踪。如需此功能，请使用自定义回调处理。

### Q3: 污点分析对性能影响有多大？

**A**: 污点分析会在每条指令执行时进行额外计算，通常会使程序运行速度降低 10-50 倍。建议：
- 只追踪关键函数
- 关闭不需要的追踪选项
- 使用 `set_verbose(false)` 减少日志开销

### Q4: 如何处理间接跳转和函数调用？

**A**: ARM64DBI 的 Router 会自动处理间接跳转，污点分析会在整个执行路径上持续进行。

### Q5: 多线程环境下如何使用？

**A**: 当前版本的 TaintAnalyzer 是全局单例，不支持多线程。如需多线程支持，请为每个线程创建独立的 TaintState 实例。

---

## 架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│                      用户代码 (User Code)                        │
│                                                                  │
│   TaintAnalyzer::getInstance()->mark_mem_source(...)            │
│   TaintAnalyzer::getInstance()->trace(target_func)              │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    TaintAnalyzer (污点分析器)                     │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│   │ WatchRegions│   │ SinkPoints  │   │    Callbacks        │   │
│   │ (监控区域)   │   │ (汇点列表)  │   │ (用户回调)           │   │
│   └─────────────┘   └─────────────┘   └─────────────────────┘   │
│                                │                                 │
│                                ▼                                 │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    TaintState (污点状态)                  │   │
│   │   ┌──────────────┐   ┌──────────────┐   ┌───────────┐   │   │
│   │   │ reg_taint[32]│   │  mem_taint   │   │  events   │   │   │
│   │   │ (寄存器污点)  │   │ (内存污点表)  │   │ (事件记录) │   │   │
│   │   └──────────────┘   └──────────────┘   └───────────┘   │   │
│   └─────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                       DBI 核心 (DBI Core)                        │
│   ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐    │
│   │  Translator  │   │   Router     │   │    Assembler     │    │
│   │  (指令翻译)   │   │  (控制流路由) │   │   (机器码生成)    │    │
│   └──────────────┘   └──────────────┘   └──────────────────┘    │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    目标代码 (Target Code)                        │
│                    指令级追踪 + 污点传播                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 版本历史

| 版本 | 日期 | 更新内容 |
|------|------|----------|
| 1.0.0 | 2025-12-09 | 初始版本，支持基本污点分析 |

---

## 许可证

本模块作为 ARM64DBI 框架的扩展，采用与主项目相同的 MIT 许可证。

---

## 参考资料

- [ARM64DBI 主文档](README.md)
- [Capstone 反汇编引擎](https://www.capstone-engine.org/)
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest)
- [Taint Analysis - Wikipedia](https://en.wikipedia.org/wiki/Taint_checking)

