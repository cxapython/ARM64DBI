# ARM64DBI - ARM64 动态二进制插桩框架

> ARM64 Dynamic Binary Instrumentation Framework for Android

[![Platform](https://img.shields.io/badge/platform-Android-green.svg)](https://developer.android.com)
[![Architecture](https://img.shields.io/badge/arch-ARM64-blue.svg)](https://developer.arm.com)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE)

## 📖 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [系统架构](#系统架构)
- [核心组件详解](#核心组件详解)
- [工作原理](#工作原理)
- [快速开始](#快速开始)
- [API 参考](#api-参考)
- [使用示例](#使用示例)
- [技术细节](#技术细节)
- [构建指南](#构建指南)
- [注意事项](#注意事项)

---

## 项目简介

ARM64DBI 是一个轻量级的 ARM64 动态二进制插桩（Dynamic Binary Instrumentation）框架，专为 Android 平台设计。它允许在运行时对 ARM64 二进制代码进行追踪和分析，**无需修改源代码或重新编译目标程序**。

### 什么是动态二进制插桩 (DBI)?

动态二进制插桩是一种在程序运行时分析和修改二进制代码的技术。与静态分析不同，DBI 可以：

- 实时追踪程序执行流程
- 在每条指令执行前/后插入自定义代码
- 监控寄存器和内存状态
- 分析程序行为而不影响原有功能

### 典型应用场景

| 场景 | 描述 |
|------|------|
| **程序调试** | 追踪函数调用、分析执行路径 |
| **性能分析** | 统计指令执行次数、识别热点代码 |
| **安全研究** | 漏洞挖掘、恶意代码分析 |
| **逆向工程** | 动态追踪算法流程、提取加密逻辑 |
| **代码覆盖率** | Fuzzing 测试的代码覆盖率统计 |

---

## 核心特性

- ✅ **纯 ARM64 原生实现** - 无需依赖 QEMU 等模拟器
- ✅ **轻量级设计** - 核心代码精简，易于理解和扩展
- ✅ **指令级追踪** - 支持每条指令的回调通知
- ✅ **完整 CPU 上下文** - 回调时可访问所有通用寄存器和状态标志
- ✅ **基本块缓存** - 已翻译的代码块会被缓存，提高执行效率
- ✅ **透明执行** - 插桩后的程序功能与原程序完全一致

---

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        用户层 (User Layer)                       │
│  ┌───────────────────┐    ┌──────────────────────────────────┐  │
│  │  目标函数         │    │  用户回调函数 (DBICallback)        │  │
│  │  (Target Code)    │    │  - 获取 CPU 上下文                 │  │
│  │                   │    │  - 反汇编当前指令                  │  │
│  │  quick_sort()     │    │  - 记录/分析执行信息               │  │
│  └─────────┬─────────┘    └──────────────────────────────────┘  │
│            │                              ▲                      │
│            ▼                              │                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    DBI 入口点                                ││
│  │           DBI::trace(target_addr, callback)                 ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      DBI 核心层 (Core Layer)                     │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │  Translator  │◄──►│   Router     │◄──►│     Memory       │   │
│  │  (翻译器)     │    │  (路由器)     │    │   (内存管理)      │   │
│  │              │    │              │    │                  │   │
│  │ - 扫描基本块  │    │ - 控制流转移  │    │ - 代码块分配      │   │
│  │ - 翻译指令    │    │ - 寄存器保存  │    │ - 缓存管理        │   │
│  │ - 插入回调    │    │ - 地址路由    │    │ - mmap 内存池     │   │
│  └──────┬───────┘    └──────────────┘    └──────────────────┘   │
│         │                                                        │
│         ▼                                                        │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                     Assembler (汇编器)                       ││
│  │                                                              ││
│  │   生成 ARM64 机器码: movz, movk, str, blr, br, ret, b ...   ││
│  │   prolog/epilog: 保存/恢复 CPU 上下文                        ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     依赖层 (Dependencies)                        │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   Capstone 反汇编引擎                        ││
│  │           用于反汇编 ARM64 指令，解析操作数                   ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

---

## 核心组件详解

### 1. DBI 类 (`DBI.cpp/h`) - 核心控制器

**职责**：作为整个框架的入口点，管理反汇编引擎和用户回调。

```cpp
class DBI {
    // 单例模式
    static DBI* getInstance();
    
    // 核心入口：开始追踪目标函数
    static void* trace(uint64_t target_addr, DBICallback callback);
    
    // 反汇编指定地址的指令
    static cs_insn* disassemble(uint64_t pc);
    
    // 获取用户回调函数指针
    static DBICallback get_dbi_callback();
    
    // 获取 Capstone 句柄（用于寄存器名称查询等）
    static csh get_cs_handle();
    
    // 打印 DBI 当前状态（调试用）
    static void dump_status();
    
    // 释放 DBI 资源
    static void destroy();
};
```

**CPU 上下文结构**：

```cpp
typedef struct CPU_CONTEXT {
    uint64_t fp;      // 栈底 (X29)
    uint64_t lr;      // 链接寄存器 (X30)
    int64_t x[29];    // X0-X28 通用寄存器
    uint64_t sp;      // 栈顶
    uint64_t pc;      // 程序计数器
    uint64_t nzcv;    // 条件标志位
} CPU_CONTEXT;
```

---

### 2. Translator 类 (`Translator.cpp/h`) - 翻译器

**职责**：扫描原始代码基本块，将其翻译为插桩后的代码。

```cpp
class Translator {
    // 扫描并翻译基本块
    static void scan(uint64_t target_addr, BlockMeta* block_meta, ROUTER_TYPE type);
    
    // 各类指令的翻译处理
    static void b_ins_handle(uint32_t*& writer, uint64_t pc);       // B 无条件跳转
    static void bl_ins_handle(uint32_t*& writer, uint64_t pc);      // BL 函数调用
    static void br_ins_handle(uint32_t*& writer, uint64_t pc);      // BR 间接跳转
    static void blr_ins_handle(uint32_t*& writer, uint64_t pc);     // BLR 间接调用 (新增)
    static void b_cond_ins_handle(uint32_t*& writer, uint64_t pc);  // B.cond 条件跳转
    static void cbz_ins_handle(uint32_t*& writer, uint64_t pc, bool is_cbnz); // CBZ/CBNZ (新增)
    static void tbz_ins_handle(uint32_t*& writer, uint64_t pc, bool is_tbnz); // TBZ/TBNZ (新增)
    static void adrp_ins_handle(uint32_t*& writer, uint64_t pc);    // ADRP 大范围地址
    static void adr_ins_handle(uint32_t*& writer, uint64_t pc);     // ADR 小范围地址 (新增)
    static void ret_ins_handle(uint32_t*& writer, uint64_t pc);     // RET 返回
    static void default_ins_handle(uint32_t*& writer, uint64_t pc); // 普通指令
    
    // 插入回调代码
    static void callback(uint32_t*& writer, uint64_t pc);
};
```

**翻译流程**：

```
原始指令                        翻译后的代码
────────                        ────────────
                               ┌─ prolog (保存寄存器)
                               │  写入当前 PC 到上下文
ADD X0, X1, X2   ──翻译──►    │  调用用户回调
                               │  epilog (恢复寄存器)
                               └─ ADD X0, X1, X2 (原指令)
```

---

### 3. Assembler 类 (`Assembler.cpp/h/S`) - 汇编器

**职责**：生成 ARM64 机器码，处理寄存器保存/恢复。

**汇编代码模板** (`Assembler.S`)：

```asm
; prolog - 保存 CPU 上下文 (272 字节)
start_prolog:
    STP X29, X30, [SP, #-CPU_CONTEXT_SIZE]!  ; 保存 FP, LR
    ADD X29, SP, #CPU_CONTEXT_SIZE
    STP X0, X1, [SP, #16]                     ; 保存 X0-X28
    STP X2, X3, [SP, #32]
    ...
    MRS X0, nzcv                              ; 保存标志位
    STR X0, [SP, #264]
end_prolog:

; epilog - 恢复 CPU 上下文
start_epilog:
    LDR X0, [SP, #264]                        ; 恢复标志位
    MSR nzcv, X0
    ...
    LDP X29, X30, [SP], #CPU_CONTEXT_SIZE     ; 恢复 FP, LR
end_epilog:
```

**主要函数**：

| 函数 | 功能 |
|------|------|
| `movz()` | 生成 MOVZ 指令（加载立即数低16位） |
| `movk()` | 生成 MOVK 指令（保持并加载16位） |
| `write_value_to_reg()` | 将64位值写入寄存器（自动优化指令数） |
| `br_x16_jump()` | 生成间接跳转到目标地址 |
| `blr_x16_jump()` | 生成间接调用到目标地址 |
| `get_b_addr()` | 解析 B 指令的跳转目标地址 |
| `get_bl_addr()` | 解析 BL 指令的调用目标地址 |
| `get_adrp_addr()` | 计算 ADRP 指令的目标地址 |

---

### 4. Router 类 (`Router.cpp/h/S`) - 路由器

**职责**：管理控制流转移，处理跳转指令的路由逻辑。

**核心汇编代码** (`Router.S`)：

```asm
; 保存调用者寄存器
router_push_register:
    STP X29, X30, [SP, #-176]!
    STP X0, X1, [SP, #16]
    ...
    MRS X0, nzcv              ; 保存标志位
    STP X18, X0, [SP, #160]
router_end_push_register:

; 恢复调用者寄存器
router_pop_register:
    LDP X18, X0, [SP, #160]
    MSR nzcv, X0              ; 恢复标志位
    ...
    LDP X29, X30, [SP], #176
router_end_pop_register:

; 路由入口
router:
    BL _router                ; 调用 C++ 路由函数
    BR X0                     ; 跳转到翻译后的代码块
```

**C++ 路由逻辑**：

```cpp
uint64_t _router(uint64_t jump_addr, ROUTER_TYPE type) {
    // 1. 检查缓存：是否已翻译过该地址
    auto block_meta = Memory::get_cache_block_meta(jump_addr);
    
    if (block_meta == nullptr) {
        // 2. 未翻译：分配新块并翻译
        block_meta = Memory::get_or_new_block_meta();
        Translator::scan(jump_addr, block_meta, type);
    }
    
    // 3. 返回翻译后代码的起始地址
    return (uint64_t)block_meta->block_start;
}
```

**路由类型**：

```cpp
enum ROUTER_TYPE {
    ENDING_ROUTER_TYPE,  // 结束类型（从 trace 入口进入）
    B_ROUTER_TYPE,       // B 指令跳转
    BL_ROUTER_TYPE,      // BL 函数调用
    BR_ROUTER_TYPE,      // BR 间接跳转
    BLR_ROUTER_TYPE,     // BLR 间接调用
    RET_ROUTER_TYPE      // RET 函数返回
};
```

---

### 5. Memory 类 (`Memory.cpp/h`) - 内存管理

**职责**：管理插桩代码的内存分配和缓存。

```cpp
#define BLOCK_NUMBER 4096   // 最大基本块数量
#define BLOCK_SIZE 1024     // 每个块的指令容量

struct BlockMeta {
    int index;                    // 块索引
    void* code_start;             // 原始代码起始地址
    int code_size;                // 原始代码大小
    void* block_start;            // 翻译后代码起始地址
    int block_size;               // 翻译后代码大小
    BlockMeta* slice_block_meta;  // 大块拆分时的链表
    uint32_t code[BLOCK_SIZE];    // 翻译后的机器码存储
};

class Memory {
    // 预分配内存池（mmap 分配，具有执行权限）
    BlockMeta* first_block_meta;
    
    // 地址到块索引的映射（用于缓存查找）
    std::unordered_map<uint64_t, int> cache_block_meta;
    
    // 获取或创建基本块
    static BlockMeta* get_or_new_block_meta(int index = 99999999);
    
    // 缓存操作
    static bool set_cache_block_meta(uint64_t key, int value);
    static BlockMeta* get_cache_block_meta(uint64_t key);
};
```

**内存布局**：

```
┌────────────────────────────────────────────────────────────┐
│                   预分配内存池 (mmap)                       │
│                   权限: RWX (读写执行)                      │
├──────────────┬──────────────┬──────────────┬──────────────┤
│  BlockMeta 0 │  BlockMeta 1 │  BlockMeta 2 │     ...      │
│  ┌─────────┐ │  ┌─────────┐ │  ┌─────────┐ │              │
│  │ header  │ │  │ header  │ │  │ header  │ │              │
│  ├─────────┤ │  ├─────────┤ │  ├─────────┤ │              │
│  │  code   │ │  │  code   │ │  │  code   │ │              │
│  │ [1024]  │ │  │ [1024]  │ │  │ [1024]  │ │              │
│  └─────────┘ │  └─────────┘ │  └─────────┘ │              │
└──────────────┴──────────────┴──────────────┴──────────────┘
```

---

### 6. Utils 类 (`Utils.cpp/h`) - 工具类

**职责**：提供调试和辅助功能。

```cpp
class Utils {
    // 反汇编并打印代码
    static void show_code(void* code_addr, int number = 999);
    
    // 打印翻译后的基本块
    static void show_block_code(BlockMeta* block_meta);
};
```

---

## 工作原理

### 整体执行流程

```
┌──────────────────────────────────────────────────────────────────┐
│  1. 用户调用 DBI::trace(quick_sort, my_callback)                 │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  2. 分配 BlockMeta，调用 Translator::scan() 翻译第一个基本块      │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  3. Translator 遍历原始指令：                                    │
│     ┌────────────────────────────────────────────────────────┐   │
│     │  对于每条指令：                                         │   │
│     │    a. 生成 prolog (保存寄存器)                          │   │
│     │    b. 写入当前 PC 到 CPU_CONTEXT                        │   │
│     │    c. 调用用户回调函数                                   │   │
│     │    d. 生成 epilog (恢复寄存器)                          │   │
│     │    e. 处理指令：                                        │   │
│     │       - 普通指令: 直接复制                              │   │
│     │       - PC相关指令(ADRP): 重新计算地址                  │   │
│     │       - 跳转指令(B/BL/BR/RET): 跳转到 Router            │   │
│     └────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  4. 返回翻译后代码的起始地址，用户直接调用执行                     │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  5. 执行过程中遇到跳转指令时：                                    │
│     ┌────────────────────────────────────────────────────────┐   │
│     │  Router 接管控制流：                                    │   │
│     │    a. 保存寄存器状态                                    │   │
│     │    b. 查找目标地址是否已翻译（缓存查找）                  │   │
│     │    c. 未找到则翻译新的基本块                            │   │
│     │    d. 恢复寄存器状态                                    │   │
│     │    e. 跳转到翻译后的代码继续执行                         │   │
│     └────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  6. 遇到 RET 且返回地址为初始 LR 时，结束追踪，返回原调用者       │
└──────────────────────────────────────────────────────────────────┘
```

### 指令翻译示例

**原始 B 指令翻译**：

```
原始代码:                      翻译后代码:
                              
                              ; === 回调部分 ===
                              prolog                    ; 保存 X0-X28, FP, LR, NZCV
                              MOV X0, #pc               ; 写入当前 PC
                              STR X0, [SP, #256]        ; 存入 CPU_CONTEXT.pc
                              MOV X0, SP                ; 参数: CPU_CONTEXT*
B target    ──翻译──►         BLR X16                   ; 调用用户回调
                              epilog                    ; 恢复所有寄存器
                              
                              ; === 跳转部分 ===
                              push_register             ; Router 保存寄存器
                              MOV X1, #B_ROUTER_TYPE    ; 路由类型
                              MOV X0, #target           ; 跳转目标地址
                              MOV X16, #router          ; Router 地址
                              BR X16                    ; 跳转到 Router
```

**原始 ADRP 指令翻译**：

```
原始代码:                      翻译后代码:
                              
ADRP X0, #page  ──翻译──►     ; === 回调部分 ===
                              prolog
                              ... (调用回调)
                              epilog
                              
                              ; === 地址计算 ===
                              ; 直接计算出绝对地址，避免 PC 相对问题
                              MOVZ X0, #addr[0:15]
                              MOVK X0, #addr[16:31], LSL #16
                              MOVK X0, #addr[32:47], LSL #32
                              MOVK X0, #addr[48:63], LSL #48
```

---

## 快速开始

### 1. 环境要求

- Android Studio Arctic Fox 或更高版本
- Android NDK r21 或更高版本
- 支持 ARM64 的 Android 设备或模拟器
- 最低 Android API 24 (Android 7.0)

### 2. 克隆项目

```bash
git clone https://github.com/lidongyooo/ARM64DBI.git
cd ARM64DBI
```

### 3. 构建运行

```bash
# 使用 Android Studio 打开项目
# 或命令行构建
./gradlew assembleDebug

# 安装到设备
adb install app/build/outputs/apk/debug/app-debug.apk
```

---

## API 参考

### DBI::trace

```cpp
void* DBI::trace(uint64_t target_addr, DBICallback callback);
```

**参数**：
- `target_addr`: 要追踪的函数起始地址
- `callback`: 每条指令执行前调用的回调函数

**返回值**：
- 翻译后代码的入口地址，可强转为函数指针调用

---

### DBICallback

```cpp
typedef void (*DBICallback)(const CPU_CONTEXT* cpu_context);
```

**参数**：
- `cpu_context`: 指向当前 CPU 上下文的指针

**CPU_CONTEXT 成员**：

| 成员 | 类型 | 描述 |
|------|------|------|
| `fp` | `uint64_t` | 栈帧指针 (X29) |
| `lr` | `uint64_t` | 链接寄存器 (X30) |
| `x[29]` | `int64_t[]` | 通用寄存器 X0-X28 |
| `sp` | `uint64_t` | 栈指针 |
| `pc` | `uint64_t` | 当前指令地址 |
| `nzcv` | `uint64_t` | 条件标志位 |

---

### DBI::disassemble

```cpp
cs_insn* DBI::disassemble(uint64_t pc);
```

**参数**：
- `pc`: 要反汇编的指令地址

**返回值**：
- Capstone 反汇编结果结构体指针

---

## 使用示例

### 基础示例：追踪快速排序

```cpp
#include "dbi/DBI.h"

// 要追踪的目标函数
void quick_sort(int arr[], int left, int right) {
    if (left >= right) return;
    int i = left, j = right;
    int pivot = arr[left];
    while (i < j) {
        while (i < j && arr[j] >= pivot) j--;
        if (i < j) arr[i++] = arr[j];
        while (i < j && arr[i] <= pivot) i++;
        if (i < j) arr[j--] = arr[i];
    }
    arr[i] = pivot;
    quick_sort(arr, left, i - 1);
    quick_sort(arr, i + 1, right);
}

// DBI 回调函数
void dbi_callback(const CPU_CONTEXT* ctx) {
    // 反汇编当前指令
    auto insn = DBI::disassemble(ctx->pc);
    
    // 打印指令和寄存器状态
    LOGE("0x%llx: %s %s", ctx->pc, insn->mnemonic, insn->op_str);
    LOGE("  X0=0x%llx, X1=0x%llx, X2=0x%llx", ctx->x[0], ctx->x[1], ctx->x[2]);
}

// 使用 DBI 追踪
void test_dbi() {
    int arr[] = {9, 3, 5, 8, 10, 1, 2, 6, 4};
    int n = sizeof(arr) / sizeof(arr[0]);
    
    // 开始追踪，获取翻译后的函数指针
    auto dbi_quick_sort = (void(*)(int[], int, int))
        DBI::trace((uint64_t)quick_sort, dbi_callback);
    
    // 调用翻译后的函数（功能与原函数完全相同）
    dbi_quick_sort(arr, 0, n - 1);
    
    // 输出排序结果
    for (int i = 0; i < n; i++) {
        LOGE("arr[%d] = %d", i, arr[i]);
    }
}
```

### 高级示例：提取特定寄存器值

```cpp
// 辅助函数：从 CPU 上下文获取寄存器值
bool get_register_value(aarch64_reg reg, const CPU_CONTEXT* ctx, uint64_t& out) {
    if (reg >= AARCH64_REG_W0 && reg <= AARCH64_REG_W30) {
        int idx = reg - AARCH64_REG_W0;
        out = ctx->x[idx] & 0xFFFFFFFF;  // W 寄存器是 32 位
    } else if (reg >= AARCH64_REG_X0 && reg <= AARCH64_REG_X28) {
        int idx = reg - AARCH64_REG_X0;
        out = ctx->x[idx];
    } else {
        switch (reg) {
            case AARCH64_REG_SP: out = ctx->sp; break;
            case AARCH64_REG_FP: out = ctx->fp; break;
            case AARCH64_REG_LR: out = ctx->lr; break;
            default: return false;
        }
    }
    return true;
}

// 回调：打印每条指令使用的所有寄存器值
void detailed_callback(const CPU_CONTEXT* ctx) {
    auto insn = DBI::disassemble(ctx->pc);
    char reg_info[1024] = {};
    char* ptr = reg_info;
    
    // 遍历指令的所有操作数
    for (int i = 0; i < insn->detail->aarch64.op_count; i++) {
        auto op = insn->detail->aarch64.operands[i];
        
        if (op.type == AARCH64_OP_REG || op.type == AARCH64_OP_MEM_REG) {
            const char* name = cs_reg_name(DBI::get_cs_handle(), op.reg);
            uint64_t value;
            if (get_register_value(op.reg, ctx, value)) {
                ptr += snprintf(ptr, sizeof(reg_info) - (ptr - reg_info),
                               "%s=0x%llx ", name, value);
            }
        }
    }
    
    LOGE("0x%llx: %s %s ; %s", ctx->pc, insn->mnemonic, insn->op_str, reg_info);
}
```

### 示例输出

```
0x7b8f001234: stp x29, x30, [sp, #-0x40]! ; x29=0x7fff0000 x30=0x7b8f002000 sp=0x7fff0040
0x7b8f001238: mov x29, sp ; x29=0x7fff0000 sp=0x7fff0000
0x7b8f00123c: str x19, [sp, #0x10] ; x19=0x0 sp=0x7fff0000
0x7b8f001240: cmp w1, w2 ; w1=0x0 w2=0x8
0x7b8f001244: b.ge #0x7b8f001280 ; 
0x7b8f001248: mov w8, w1 ; w8=0x0 w1=0x0
...
```

---

## 技术细节

### 支持的指令类型

| 指令类型 | 处理方式 | 说明 |
|----------|----------|------|
| 普通算术/逻辑 | 直接复制 | ADD, SUB, AND, ORR 等 |
| 内存访问 | 直接复制 | LDR, STR, LDP, STP, LDUR, STUR 等 |
| B (无条件跳转) | 翻译 + Router | 计算目标地址，跳转到 Router |
| B.cond (条件跳转) | 翻译 + Router | 保持条件，调整跳转目标 |
| BL (函数调用) | 翻译 + Router | 设置 LR 后跳转到 Router |
| BR (间接跳转) | 翻译 + Router | 从寄存器获取目标地址 |
| **BLR (间接调用)** | 翻译 + Router | 从寄存器获取调用目标，设置 LR |
| RET (返回) | 翻译 + Router | 从 LR 获取返回地址 |
| ADRP (大范围地址) | 重新计算 | 将 PC 相对页地址转为绝对地址 |
| **ADR (小范围地址)** | 重新计算 | 将 PC 相对地址转为绝对地址 |
| **CBZ/CBNZ** | 翻译 + Router | 比较寄存器与零并分支 |
| **TBZ/TBNZ** | 翻译 + Router | 测试指定位并分支 |

### PC 相关指令处理

ARM64 中某些指令依赖 PC（程序计数器）的值：

1. **ADRP** - 计算 4KB 对齐的页地址
   - 原理：`target = (PC & ~0xFFF) + (imm << 12)`
   - 处理：预先计算绝对地址，使用 MOV 指令序列加载

2. **B/BL** - PC 相对跳转
   - 原理：`target = PC + (imm << 2)`
   - 处理：解析跳转目标，跳转到 Router 进行路由

### 基本块边界识别

翻译器通过以下指令识别基本块边界：
- `B` (无条件跳转)
- `BL` (函数调用)
- `BR` (间接跳转)
- `RET` (函数返回)

遇到这些指令时，当前基本块翻译结束，控制权转移给 Router。

---

## 构建指南

### CMake 配置

```cmake
cmake_minimum_required(VERSION 3.22.1)
project("arm64dbidemo")

# 源文件
file(GLOB SRC_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/dbi/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
)

# 汇编文件
file(GLOB ASM_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/dbi/*.S"
)

# 编译选项
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
enable_language(ASM)

# 链接库
target_link_libraries(${CMAKE_PROJECT_NAME}
    android
    log
    ${LIBS_PATH}/libcapstone.a
)
```

### 依赖说明

| 依赖 | 用途 |
|------|------|
| Capstone | ARM64 反汇编引擎 |
| Android Log | 日志输出 |

---

## 注意事项

### 限制

1. **仅支持 ARM64** - 不支持 ARM32 或其他架构
2. **不支持自修改代码** - 假设代码在执行期间不变
3. **浮点寄存器** - 当前版本不保存/恢复 SIMD/FP 寄存器
4. **信号处理** - 不支持信号处理程序中的代码追踪
5. **多线程** - 基本块缓存非线程安全

### 性能影响

由于每条指令都会触发回调，开启 DBI 后程序运行速度会显著降低。建议：

- 仅追踪感兴趣的关键函数
- 回调函数中避免复杂操作
- 利用基本块缓存减少翻译开销

### 安全考虑

- 翻译后的代码存储在 RWX 内存中
- 生产环境中应考虑安全加固措施
- 避免追踪不受信任的代码

---

## 更新日志

### v1.1.0 (2024-12-10)

#### 新增指令支持
- **BLR** - 间接函数调用指令
- **CBZ/CBNZ** - 比较并分支指令
- **TBZ/TBNZ** - 测试位并分支指令
- **ADR** - PC 相对地址计算指令（小范围）

#### 污点分析增强
- 修复 LDP/STP 双寄存器污点传播
- 添加 LDUR/STUR 非对齐内存访问支持
- 添加条件选择指令 (CSEL/CSINC/CSINV/CSNEG) 污点传播
- 添加字节序反转指令 (REV/REV16/REV32/REV64/RBIT) 污点传播
- 添加位域操作指令 (UBFM/SBFM/BFM/EXTR) 污点传播
- 添加扩展指令 (SXTB/SXTH/SXTW/UXTB/UXTH) 污点传播
- 添加位计数指令 (CLZ/CLS/CNT) 污点传播

#### 健壮性提升
- Memory 类添加内存池状态检查和诊断方法
- DBI 类添加参数验证和状态检查
- Translator 添加安全限制防止基本块溢出
- 添加 `DBI::dump_status()` 调试方法
- 添加 `DBI::destroy()` 资源清理方法

#### 代码质量
- 全部核心代码添加详细中文注释
- 修复编译警告
- 限制只编译 arm64-v8a 架构

### v1.0.0 (初始版本)
- 基础 DBI 框架实现
- 支持 B/BL/BR/RET/B.cond/ADRP 指令
- 基本污点分析功能

---

## 参考资料

- [ARM64 动态二进制插桩的原理与实现](https://mp.weixin.qq.com/s/FxzUCAcYwzLDvbxntA7aow) - 作者原文
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest) - ARM64 官方手册
- [Capstone Disassembly Framework](https://www.capstone-engine.org/) - 反汇编引擎

---

## 许可证

本项目采用 MIT 许可证。

## 作者

- **lidongyooo** - 初始开发

---

## 贡献

欢迎提交 Issue 和 Pull Request！
