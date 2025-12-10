# ARM64DBI AES追踪密文验证失败问题排查报告

## 问题概述

| 项目 | 内容 |
|------|------|
| 问题描述 | 使用 DBI 追踪 AES 加密函数时，追踪版本产生的密文与原始版本不一致 |
| 影响范围 | AES 白盒 DFA 攻击定位功能 |
| 严重程度 | 高（核心功能异常） |
| 修复状态 | ✅ 已修复 |

---

## 1. 问题现象

### 1.1 初始表现

```
▶ 原始密文:
  39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32

▶ 追踪版本密文:
  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

▶ 追踪版本密文验证: ✗ 不一致 (第一个差异在字节 0)
```

追踪版本的密文全为 0，说明输出缓冲区根本没有被写入。

### 1.2 问题特征

1. 快速排序追踪正常工作
2. AES 原始加密正确
3. AES 追踪版本输出全为 0
4. 有时伴随 SIGSEGV 或 SIGILL 崩溃

---

## 2. 排查过程

### 2.1 第一阶段：确认函数是否执行

**假设**：追踪版本的函数可能根本没有执行

**验证方法**：在 `aes_encrypt_wrapper` 中添加日志

```cpp
static void aes_encrypt_wrapper(const uint8_t* input, uint8_t* output) {
    LOGI("[AES Wrapper] Called with input=%p, output=%p", input, output);
    if (g_aes_instance) {
        g_aes_instance->encrypt_block(input, output);
        LOGI("[AES Wrapper] Encryption done, first byte: 0x%02X", output[0]);
    }
}
```

**结果**：程序崩溃！

```
Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0
backtrace:
  #00 pc 0000000000250efc  <anonymous:7c7dcf8000>
  #01 pc 0000000000008f50  /system/lib64/liblog.so (refresh_cache)
```

**发现**：崩溃发生在 `liblog.so` 中！

### 2.2 第二阶段：分析崩溃原因

**关键发现**：崩溃发生在 LOGI 调用中

当追踪器追踪 `aes_encrypt_wrapper` 时：
1. 遇到 `LOGI` 的 BL 调用指令
2. 追踪器将 BL 转换为通过 Router 的跳转
3. Router 尝试翻译 `liblog.so` 的代码
4. 系统库代码翻译失败导致崩溃

**结论**：被追踪函数内部不能调用外部库函数！

### 2.3 第三阶段：移除日志后仍然失败

移除 `aes_encrypt_wrapper` 中的日志后，不再崩溃，但密文仍然全为 0。

**进一步检查 `encrypt_block` 实现**：

```cpp
void AESWhitebox::encrypt_block(const uint8_t* input, uint8_t* output) {
    uint8_t state[16];
    memcpy(state, input, 16);  // ← 问题1: memcpy 是 libc 函数！
    
    // ... AES 加密逻辑 ...
    
    memcpy(output, state, 16);  // ← 问题2: memcpy 是 libc 函数！
}
```

**发现**：`memcpy` 也是外部函数（libc），追踪时会出问题！

**修复**：用内联循环替代 `memcpy`

```cpp
void AESWhitebox::encrypt_block(const uint8_t* input, uint8_t* output) {
    uint8_t state[16];
    
    // 内联复制（替代 memcpy）
    for (int i = 0; i < 16; i++) {
        state[i] = input[i];
    }
    
    // ... AES 加密逻辑 ...
    
    for (int i = 0; i < 16; i++) {
        output[i] = state[i];
    }
}
```

### 2.4 第四阶段：密文不再是全0，但仍不正确

修复 `memcpy` 问题后，密文有了变化：

```
▶ 原始密文:   39 25 84 1D ...
▶ 追踪版本密文: 00 00 00 00 ...  (初始化值)
```

添加调试信息：

```cpp
uint8_t ciphertext2[16];
memset(ciphertext2, 0xAA, 16);  // 用 0xAA 填充
traced_encrypt(plaintext, ciphertext2);
LOGI("After: ciphertext2[0]=0x%02X", ciphertext2[0]);  // 输出 0x00
```

**观察**：ciphertext2[0] 从 0xAA 变成了 0x00，说明有某些操作执行了，但结果不对。

### 2.5 第五阶段：定位回调函数问题

**原始回调函数**：

```cpp
static void aes_dfa_callback(const CPU_CONTEXT* ctx) {
    auto insn = DBI::disassemble(ctx->pc);  // ← 调用 Capstone 库
    if (!insn) return;
    
    if (insn->id == AARCH64_INS_EOR) {
        g_total_eor_count++;
    }
    
    // ... 更多分析代码 ...
}
```

**假设**：回调函数中调用 `DBI::disassemble()` 可能影响执行

**验证**：使用最简化的回调

```cpp
static volatile int g_instruction_count_aes = 0;

static void aes_dfa_callback(const CPU_CONTEXT* ctx) {
    g_instruction_count_aes++;  // 只增加计数器
}
```

**结果**：✅ 密文验证通过！

```
▶ 追踪版本密文验证: ✓ 一致
```

### 2.6 第六阶段：恢复功能时再次失败

尝试在回调中收集 PC 地址用于后续分析：

```cpp
static std::vector<uint64_t> g_traced_pcs;

static void aes_dfa_callback(const CPU_CONTEXT* ctx) {
    g_instruction_count_aes++;
    g_traced_pcs.push_back(ctx->pc);  // ← 问题！
}
```

**结果**：密文验证再次失败！

**原因分析**：
- `std::vector::push_back()` 可能触发内存重新分配
- 在追踪执行过程中进行动态内存分配会破坏程序状态
- 可能影响寄存器或栈的状态

**最终修复**：使用固定大小数组

```cpp
static const size_t MAX_TRACED_PCS = 10000;
static uint64_t g_traced_pcs_arr[MAX_TRACED_PCS];
static volatile size_t g_traced_pcs_count = 0;

static void aes_dfa_callback(const CPU_CONTEXT* ctx) {
    g_instruction_count_aes++;
    
    size_t idx = g_traced_pcs_count;
    if (idx < MAX_TRACED_PCS) {
        g_traced_pcs_arr[idx] = ctx->pc;
        g_traced_pcs_count = idx + 1;
    }
}
```

**结果**：✅ 密文验证通过！

---

## 3. 根本原因分析

### 3.1 问题根源

DBI（动态二进制插桩）框架在追踪函数时，会拦截并翻译每一条指令。当被追踪的代码调用外部函数时：

```
被追踪代码 → BL external_func → Router → 翻译 external_func → 问题！
```

问题类型：

| 类型 | 外部函数 | 问题 |
|------|----------|------|
| 1 | LOGI / printf | 翻译 liblog.so 失败，崩溃 |
| 2 | memcpy | 翻译 libc.so 失败，结果错误 |
| 3 | DBI::disassemble | 调用 Capstone，修改全局状态 |
| 4 | vector::push_back | 触发内存分配，破坏程序状态 |

### 3.2 DBI 回调的特殊性

回调函数在追踪过程中被频繁调用（每条指令一次），必须满足：

1. **不调用外部函数**：避免追踪器尝试翻译外部库代码
2. **不进行动态内存分配**：避免破坏程序状态
3. **执行时间尽量短**：减少对程序执行的干扰
4. **使用 volatile**：防止编译器优化掉关键操作

### 3.3 prolog/epilog 的作用

DBI 框架在每条指令前后插入 prolog 和 epilog 代码来保存/恢复寄存器：

```asm
prolog:
    STP X0, X1, [SP, #-xxx]!    ; 保存所有通用寄存器
    STP X2, X3, [SP, #xxx]
    ...
    
callback:                        ; 用户回调
    BL user_callback
    
epilog:
    LDP X2, X3, [SP, #xxx]      ; 恢复所有通用寄存器
    LDP X0, X1, [SP], #xxx
    ...
```

**但问题是**：如果回调函数内部调用了复杂函数（如 Capstone），可能会：
- 使用大量栈空间
- 修改某些全局状态
- 触发内存分配器

这些操作可能影响被追踪程序的状态，即使寄存器被正确恢复。

---

## 4. 修复方案

### 4.1 被追踪函数的要求

```cpp
// ❌ 错误：调用外部函数
void encrypt_wrapper(const uint8_t* input, uint8_t* output) {
    LOGI("Encrypting...");  // 外部函数！
    memcpy(state, input, 16);  // 外部函数！
}

// ✅ 正确：只使用内联代码
void encrypt_wrapper(const uint8_t* input, uint8_t* output) {
    for (int i = 0; i < 16; i++) {
        state[i] = input[i];  // 内联操作
    }
}
```

### 4.2 回调函数的要求

```cpp
// ❌ 错误：调用外部函数和动态内存分配
static void callback(const CPU_CONTEXT* ctx) {
    auto insn = DBI::disassemble(ctx->pc);  // 外部函数！
    g_pcs.push_back(ctx->pc);  // 可能内存分配！
}

// ✅ 正确：只做最简单的操作
static uint64_t g_pcs[10000];
static volatile size_t g_count = 0;

static void callback(const CPU_CONTEXT* ctx) {
    size_t idx = g_count;
    if (idx < 10000) {
        g_pcs[idx] = ctx->pc;
        g_count = idx + 1;
    }
}
```

### 4.3 后处理策略

将复杂分析放到追踪完成后进行：

```cpp
// 追踪期间：只收集数据
traced_encrypt(plaintext, ciphertext);

// 追踪完成后：进行分析
for (size_t i = 0; i < g_count; i++) {
    auto insn = DBI::disassemble(g_pcs[i]);  // 现在可以安全调用
    // ... 分析逻辑 ...
}
```

---

## 5. 验证结果

### 5.1 最终测试结果

```
▶ 原始密钥:
  2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C

▶ 第10轮密钥 (DFA攻击目标):
  D0 14 F9 A8 C9 EE 25 89 E1 3F 0C C8 B6 63 0C A6

▶ 明文:
  32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34

▶ 原始密文:
  39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32

▶ 追踪版本密文:
  39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32

▶ 追踪版本密文验证: ✓ 一致

▶ 追踪指令总数: 2492
▶ EOR 指令总数: 356

[SUCCESS] AES DFA 定位完成!
All tests completed!
```

### 5.2 性能指标

| 指标 | 数值 |
|------|------|
| 追踪指令数 | 2492 条 |
| EOR 指令数 | 356 次 |
| LDR/LDRB 指令 | 867 处 |
| 执行时间 | ~20ms |

---

## 6. 经验总结

### 6.1 DBI 开发的黄金法则

1. **被追踪代码不能调用外部库函数**
   - 不使用 printf/LOGI
   - 不使用 memcpy/memset
   - 不使用 malloc/free
   - 不使用任何 STL 容器

2. **回调函数必须极简**
   - 只做计数、赋值等基本操作
   - 使用固定大小数组而非动态容器
   - 使用 volatile 防止优化
   - 复杂分析放到后处理阶段

3. **调试时逐步排查**
   - 先用最简回调验证框架正确性
   - 再逐步添加功能
   - 每步都验证结果

### 6.2 常见问题速查表

| 现象 | 可能原因 | 解决方案 |
|------|----------|----------|
| SIGSEGV addr=0x0 | 调用了外部函数，翻译失败 | 移除外部函数调用 |
| SIGILL | 跳转偏移计算错误 | 使用回填技术修复 |
| 结果全为0 | memcpy 等函数未正确执行 | 用内联代码替代 |
| 结果不正确 | 回调函数副作用 | 简化回调函数 |
| 随机崩溃 | 动态内存分配 | 使用固定大小数组 |

### 6.3 最佳实践

```cpp
// 被追踪函数模板
__attribute__((noinline))
void traced_function(args...) {
    // 只使用：
    // - 基本算术运算
    // - 数组访问
    // - 循环和条件
    // - 函数调用（只调用同样遵守规则的函数）
    
    // 禁止使用：
    // - printf, LOGI 等日志函数
    // - memcpy, memset 等 libc 函数
    // - new, delete, malloc, free
    // - STL 容器
}

// 回调函数模板
static volatile int g_count = 0;
static uint64_t g_data[MAX_SIZE];  // 固定大小

static void dbi_callback(const CPU_CONTEXT* ctx) {
    // 只做简单记录
    if (g_count < MAX_SIZE) {
        g_data[g_count++] = ctx->pc;
    }
}

// 后处理模板
void analyze_results() {
    // 追踪完成后可以调用任何函数
    for (int i = 0; i < g_count; i++) {
        auto insn = disassemble(g_data[i]);
        // 复杂分析...
    }
}
```

---

## 7. 相关代码修改

### 7.1 修改文件列表

| 文件 | 修改内容 |
|------|----------|
| `AESWhitebox.cpp` | 用内联循环替代 memcpy |
| `main.cpp` | 简化回调函数，使用固定大小数组 |
| `Translator.cpp` | 修复条件分支跳转偏移计算 |

### 7.2 Git 提交记录

```
commit 0547f9d - 修复AES追踪密文验证失败的问题
commit 68f1a48 - 修复条件分支翻译的跳转偏移计算问题
commit 8548e65 - 修复块大小限制处理，添加AES DFA演示
```

---

## 8. 参考资料

- ARM64 指令集参考手册
- Capstone 反汇编引擎文档
- DBI (Dynamic Binary Instrumentation) 技术原理

---

*文档更新日期: 2024-12-10*
*作者: ARM64DBI 开发团队*

