# ARM64DBI 条件分支翻译修复详解

## 问题概述

| 项目 | 内容 |
|------|------|
| 问题描述 | 条件分支指令(B.cond/CBZ/CBNZ/TBZ/TBNZ)翻译后跳转偏移错误 |
| 影响范围 | 所有包含条件分支的代码追踪 |
| 根本原因 | 跳转偏移使用硬编码值，未考虑实际翻译后代码大小 |
| 修复方案 | 预留槽位 + 回填机制 |

---

## 1. 问题背景

### 1.1 条件分支指令类型

ARM64 有多种条件分支指令：

| 指令 | 描述 | 偏移范围 |
|------|------|----------|
| B.cond | 条件跳转 (EQ/NE/LT/GT等) | ±1MB |
| CBZ/CBNZ | 比较寄存器与零并分支 | ±1MB |
| TBZ/TBNZ | 测试指定位并分支 | ±32KB |

### 1.2 翻译前后对比

**原始代码**：
```asm
CMP X0, X1
B.EQ label    ; 如果相等则跳转到 label
ADD X2, X3, X4
...
label:
SUB X5, X6, X7
```

**翻译后代码（简化）**：
```asm
; === CMP X0, X1 的翻译 ===
prolog                    ; 保存上下文 (~20条指令)
... (回调调用)
epilog                    ; 恢复上下文 (~20条指令)
CMP X0, X1                ; 原指令

; === B.EQ label 的翻译 ===
prolog                    ; 保存上下文
... (回调调用)
epilog                    ; 恢复上下文
B.EQ skip_to_router       ; ← 跳转偏移必须正确！
B continue_next           ; 条件不满足则继续

skip_to_router:
... (跳转到 Router 处理)

continue_next:
; === ADD X2, X3, X4 的翻译 ===
...
```

---

## 2. 问题分析

### 2.1 原始代码的问题

原始翻译器使用**硬编码的跳转偏移**：

```cpp
// 错误示例：假设跳转偏移总是固定值
void b_cond_ins_handle(uint32_t*& writer, uint64_t pc) {
    // ... 生成 prolog 和回调代码 ...
    
    // 生成条件跳转（硬编码偏移 = 5 条指令）
    uint32_t b_cond = original_b_cond & 0xFF00001F;  // 保留条件码
    b_cond |= (5 << 5);  // ← 问题！硬编码偏移
    *writer++ = b_cond;
    
    // ... 生成后续代码 ...
}
```

### 2.2 为什么会出错？

翻译后的代码大小取决于多个因素：

1. **prolog/epilog 大小**：根据配置可能不同
2. **回调调用代码**：加载64位地址需要4条 MOVZ/MOVK 指令
3. **Router 跳转代码**：保存寄存器 + 加载地址 + 跳转

这些都不是固定大小，导致硬编码偏移计算错误。

### 2.3 错误表现

```
SIGILL (Illegal instruction)
```

或

```
程序跳转到错误位置，执行随机指令
```

---

## 3. 修复方案

### 3.1 核心思路：预留槽位 + 回填

```
翻译过程:
┌──────────────────────────────────────────────────────────────────┐
│ 第1步: 生成 prolog 和回调代码                                      │
│ 第2步: 预留条件分支指令槽位（记住位置）                              │
│ 第3步: 生成"条件不满足"时的代码                                    │
│ 第4步: 生成"条件满足"时的 Router 跳转代码                          │
│ 第5步: 计算实际偏移，回填条件分支指令                               │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 修复后的代码

```cpp
void b_cond_ins_handle(uint32_t*& writer, uint64_t pc) {
    cs_insn* insn = DBI::disassemble(pc);
    
    // 1. 获取原始条件码
    uint32_t original = *(uint32_t*)pc;
    uint32_t cond = original & 0xF;  // 条件码在低4位
    
    // 2. 生成 prolog 和回调代码
    callback(writer, pc);
    
    // 3. ★ 预留条件分支指令槽位
    uint32_t* b_cond_slot = writer;  // 记住位置
    *writer++ = 0;  // 占位符，稍后回填
    
    // 4. 生成"条件不满足"时的跳转（跳过 Router 代码）
    uint32_t* b_skip_slot = writer;  // 记住位置
    *writer++ = 0;  // 占位符
    
    // 5. 生成"条件满足"时的 Router 跳转代码
    uint32_t* router_start = writer;
    // ... 生成 Router 跳转代码 ...
    Assembler::router_push(writer);
    uint64_t target_addr = Assembler::get_b_addr(original, pc);
    Assembler::write_value_to_reg(writer, 0, target_addr);
    Assembler::write_value_to_reg(writer, 1, (uint64_t)B_ROUTER_TYPE);
    Assembler::write_value_to_reg(writer, 16, (uint64_t)Router::get_router_addr());
    *writer++ = Assembler::br(16);
    
    // 6. ★ 回填条件分支指令
    int64_t cond_offset = router_start - b_cond_slot;
    *b_cond_slot = 0x54000000 | ((cond_offset & 0x7FFFF) << 5) | cond;
    
    // 7. ★ 回填跳过指令
    int64_t skip_offset = writer - b_skip_slot;
    *b_skip_slot = 0x14000000 | (skip_offset & 0x3FFFFFF);
}
```

### 3.3 图解

```
翻译后代码布局:

         ┌─────────────────────────────────┐
         │  prolog (保存上下文)              │
         │  ... (回调调用)                   │
         │  epilog (恢复上下文)              │
         ├─────────────────────────────────┤
slot1 →  │  B.cond slot1_target  ◄──────────┐   ← 预留槽位1
         ├─────────────────────────────────┤   │
slot2 →  │  B slot2_target      ◄───────┐  │   ← 预留槽位2
         ├─────────────────────────────────┤│  │
         │  router_push                    ││  │
         │  MOV X0, target_addr           ││  │
router → │  MOV X1, B_ROUTER_TYPE  ◄───────┼──┘   ← 条件满足跳这里
         │  MOV X16, router_addr          ││
         │  BR X16                         ││
         ├─────────────────────────────────┤│
next →   │  下一条指令的翻译... ◄───────────┘     ← 条件不满足跳这里
         └─────────────────────────────────┘

回填计算:
  slot1 偏移 = router - slot1 (条指令数)
  slot2 偏移 = next - slot2 (条指令数)
```

---

## 4. 各类条件分支的处理

### 4.1 B.cond (条件跳转)

指令格式：
```
31 30 29 28 27 26 25 24 23        5 4  3  2  1  0
 0  1  0  1  0  1  0  0  [imm19]  0  [  cond  ]
```

回填公式：
```cpp
uint32_t b_cond = 0x54000000 | ((offset & 0x7FFFF) << 5) | cond;
```

### 4.2 CBZ/CBNZ (比较零分支)

指令格式：
```
31 30 29 28 27 26 25 24 23       5 4      0
sf  0  1  1  0  1  0 op [imm19]  [  Rt   ]
```

- `sf=0`: 32位操作 (W寄存器)
- `sf=1`: 64位操作 (X寄存器)
- `op=0`: CBZ (等于零跳转)
- `op=1`: CBNZ (不等于零跳转)

回填公式：
```cpp
uint32_t cbz = (sf << 31) | 0x34000000 | (op << 24) | ((offset & 0x7FFFF) << 5) | rt;
```

### 4.3 TBZ/TBNZ (测试位分支)

指令格式：
```
31 30    29 28 27 26 25 24 23           19 18      5 4      0
b5  0  1  1  0  1  1  op [b40]          [imm14]    [  Rt   ]
```

- `b5:b40`: 要测试的位索引 (0-63)
- `op=0`: TBZ (位为0跳转)
- `op=1`: TBNZ (位为1跳转)

⚠️ **注意**：TBZ/TBNZ 的偏移只有14位，范围 ±32KB！

回填公式：
```cpp
uint32_t tbz = (b5 << 31) | 0x36000000 | (op << 24) | (b40 << 19) | ((offset & 0x3FFF) << 5) | rt;
```

---

## 5. 完整修复代码

### 5.1 Translator.h 声明

```cpp
class Translator {
public:
    // 条件分支处理
    static void b_cond_ins_handle(uint32_t*& writer, uint64_t pc);
    static void cbz_ins_handle(uint32_t*& writer, uint64_t pc, bool is_cbnz);
    static void tbz_ins_handle(uint32_t*& writer, uint64_t pc, bool is_tbnz);
};
```

### 5.2 Translator.cpp 实现

```cpp
void Translator::b_cond_ins_handle(uint32_t*& writer, uint64_t pc) {
    uint32_t original = *(uint32_t*)pc;
    uint32_t cond = original & 0xF;
    
    // 生成回调
    callback(writer, pc);
    
    // 预留 B.cond 槽位
    uint32_t* b_cond_slot = writer++;
    
    // 预留 B (skip) 槽位
    uint32_t* b_skip_slot = writer++;
    
    // Router 跳转代码起点
    uint32_t* router_start = writer;
    
    // 生成 Router 代码
    Assembler::router_push(writer);
    uint64_t target = Assembler::get_b_addr(original, pc);
    Assembler::write_value_to_reg(writer, 0, target);
    Assembler::write_value_to_reg(writer, 1, (uint64_t)B_ROUTER_TYPE);
    Assembler::write_value_to_reg(writer, 16, (uint64_t)Router::get_router_addr());
    *writer++ = Assembler::br(16);
    
    // 回填 B.cond
    int64_t cond_off = router_start - b_cond_slot;
    *b_cond_slot = 0x54000000 | ((cond_off & 0x7FFFF) << 5) | cond;
    
    // 回填 B (skip)
    int64_t skip_off = writer - b_skip_slot;
    *b_skip_slot = 0x14000000 | (skip_off & 0x3FFFFFF);
}

void Translator::cbz_ins_handle(uint32_t*& writer, uint64_t pc, bool is_cbnz) {
    uint32_t original = *(uint32_t*)pc;
    uint32_t sf = (original >> 31) & 1;   // 32/64位
    uint32_t rt = original & 0x1F;         // 寄存器
    
    callback(writer, pc);
    
    uint32_t* cbz_slot = writer++;
    uint32_t* b_skip_slot = writer++;
    uint32_t* router_start = writer;
    
    Assembler::router_push(writer);
    uint64_t target = Assembler::get_cbz_addr(original, pc);
    Assembler::write_value_to_reg(writer, 0, target);
    Assembler::write_value_to_reg(writer, 1, (uint64_t)B_ROUTER_TYPE);
    Assembler::write_value_to_reg(writer, 16, (uint64_t)Router::get_router_addr());
    *writer++ = Assembler::br(16);
    
    // 回填 CBZ/CBNZ
    int64_t cond_off = router_start - cbz_slot;
    uint32_t op = is_cbnz ? 1 : 0;
    *cbz_slot = (sf << 31) | 0x34000000 | (op << 24) | ((cond_off & 0x7FFFF) << 5) | rt;
    
    // 回填 B (skip)
    int64_t skip_off = writer - b_skip_slot;
    *b_skip_slot = 0x14000000 | (skip_off & 0x3FFFFFF);
}

void Translator::tbz_ins_handle(uint32_t*& writer, uint64_t pc, bool is_tbnz) {
    uint32_t original = *(uint32_t*)pc;
    uint32_t b5 = (original >> 31) & 1;
    uint32_t b40 = (original >> 19) & 0x1F;
    uint32_t rt = original & 0x1F;
    
    callback(writer, pc);
    
    uint32_t* tbz_slot = writer++;
    uint32_t* b_skip_slot = writer++;
    uint32_t* router_start = writer;
    
    Assembler::router_push(writer);
    uint64_t target = Assembler::get_tbz_addr(original, pc);
    Assembler::write_value_to_reg(writer, 0, target);
    Assembler::write_value_to_reg(writer, 1, (uint64_t)B_ROUTER_TYPE);
    Assembler::write_value_to_reg(writer, 16, (uint64_t)Router::get_router_addr());
    *writer++ = Assembler::br(16);
    
    // 回填 TBZ/TBNZ (注意: imm14 范围有限)
    int64_t cond_off = router_start - tbz_slot;
    if (cond_off < -8192 || cond_off > 8191) {
        LOGE("TBZ/TBNZ offset out of range: %lld", cond_off);
        // 需要使用备用方案...
    }
    uint32_t op = is_tbnz ? 1 : 0;
    *tbz_slot = (b5 << 31) | 0x36000000 | (op << 24) | (b40 << 19) | 
                ((cond_off & 0x3FFF) << 5) | rt;
    
    // 回填 B (skip)
    int64_t skip_off = writer - b_skip_slot;
    *b_skip_slot = 0x14000000 | (skip_off & 0x3FFFFFF);
}
```

---

## 6. 验证方法

### 6.1 测试用例

```cpp
// 包含多种条件分支的测试函数
__attribute__((noinline))
int test_branches(int a, int b) {
    int result = 0;
    
    // 测试 B.EQ
    if (a == b) {
        result += 1;
    }
    
    // 测试 B.LT
    if (a < b) {
        result += 2;
    }
    
    // 测试 CBZ
    if (a == 0) {
        result += 4;
    }
    
    // 测试 CBNZ
    if (b != 0) {
        result += 8;
    }
    
    return result;
}

// 验证
void verify() {
    // 原始执行
    int orig_result = test_branches(5, 5);
    
    // 追踪执行
    auto traced = (int(*)(int, int))DBI::trace((uint64_t)test_branches, empty_callback);
    int traced_result = traced(5, 5);
    
    // 验证结果一致
    assert(orig_result == traced_result);
    LOGI("Conditional branch test PASSED!");
}
```

### 6.2 反汇编验证

```cpp
// 检查翻译后的代码
void dump_translated_code() {
    auto block = Memory::get_cache_block_meta((uint64_t)test_branches);
    if (block) {
        Utils::show_block_code(block);
        
        // 检查 B.cond 偏移是否正确
        uint32_t* code = block->code;
        for (int i = 0; i < block->block_size; i++) {
            uint32_t insn = code[i];
            if ((insn & 0xFF000010) == 0x54000000) {
                // B.cond 指令
                int64_t offset = ((int64_t)(insn >> 5) << 45) >> 45;  // 符号扩展
                LOGI("B.cond at offset %d, jump offset = %lld", i, offset);
            }
        }
    }
}
```

---

## 7. 经验总结

### 7.1 核心教训

1. **永远不要硬编码偏移** - 翻译后代码大小是动态的
2. **预留槽位 + 回填** - 解决任何前向引用问题
3. **注意偏移范围** - TBZ/TBNZ 只有 ±32KB

### 7.2 调试技巧

1. 使用 `Utils::show_block_code()` 查看翻译后代码
2. 检查条件分支的目标地址是否正确
3. 使用 lldb 的 `disassemble` 命令验证机器码

### 7.3 相关指令偏移范围

| 指令类型 | 偏移字段 | 范围 |
|----------|----------|------|
| B | imm26 | ±128MB |
| BL | imm26 | ±128MB |
| B.cond | imm19 | ±1MB |
| CBZ/CBNZ | imm19 | ±1MB |
| TBZ/TBNZ | imm14 | ±32KB |
| ADR | imm21 | ±1MB |
| ADRP | imm21 | ±4GB (页对齐) |

---

## 8. 参考资料

- [ARM64 Branch Instructions](https://developer.arm.com/documentation/ddi0596/latest/Base-Instructions/B-cond--Branch-conditionally-)
- [ARM64 Instruction Encoding](https://developer.arm.com/documentation/ddi0596/latest/Index-by-Encoding)

---

*文档更新日期: 2024-12-10*

