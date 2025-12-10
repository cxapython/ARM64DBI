/**
 * @file Translator.cpp
 * @brief ARM64 指令翻译器实现
 * @author lidongyooo
 * @date 2025/12/7
 * 
 * 本文件实现了 ARM64 指令的翻译逻辑，将原始代码翻译为带插桩的代码。
 * 
 * 翻译过程：
 * 1. 扫描原始代码的基本块
 * 2. 对每条指令插入回调代码 (prolog -> callback -> epilog)
 * 3. 处理控制流指令 (B, BL, BR, BLR, RET, CBZ, CBNZ, TBZ, TBNZ)
 * 4. 处理 PC 相关指令 (ADRP, ADR)
 * 5. 普通指令直接复制
 */

#include "Translator.h"

// ==================== 翻译器全局状态 ====================

/// Capstone 反汇编引擎句柄
static csh translator_handle = 0;

/// Capstone 指令结构体（复用以提高性能）
static cs_insn* translator_insn = nullptr;

/// 翻译器初始化标志
static bool translator_initialized = false;

/**
 * @brief 初始化翻译器
 * 
 * 初始化 Capstone 反汇编引擎，设置为 ARM64 模式。
 * 使用懒加载模式，只在首次调用时初始化。
 */
static void init_translator() {
    if (!translator_initialized) {
        // 初始化 Capstone 引擎
        cs_err err = cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &translator_handle);
        if (err != CS_ERR_OK) {
            LOGE("[Translator] Failed to initialize Capstone: %s", cs_strerror(err));
            return;
        }
        
        // 启用详细信息模式，获取操作数等细节
        cs_option(translator_handle, CS_OPT_DETAIL, CS_OPT_ON);
        
        // 预分配指令结构体
        translator_insn = cs_malloc(translator_handle);
        if (!translator_insn) {
            LOGE("[Translator] Failed to allocate cs_insn");
            cs_close(&translator_handle);
            return;
        }
        
        translator_initialized = true;
        LOGI("[Translator] Initialized successfully");
    }
}

/**
 * @brief 结束基本块翻译
 * 
 * 在翻译完一个基本块后调用，记录块的元数据并缓存。
 * 
 * @param type 路由类型
 * @param block_meta 基本块元数据
 * @param dbi_code 当前写入位置
 * @param target_addr 原始代码起始地址
 * @param pc 当前指令地址（基本块结束位置）
 */
void block_ending(ROUTER_TYPE type, BlockMeta* block_meta, uint8_t* dbi_code, 
                  uint64_t target_addr, uint64_t pc) {
    // 记录翻译后代码的位置和大小
    block_meta->block_start = (void*)block_meta->code;
    block_meta->block_size = dbi_code - (uint8_t*)block_meta->code;
    
    // 记录原始代码的位置和大小
    block_meta->code_start = (void*)target_addr;
    block_meta->code_size = pc - target_addr;

    // 缓存已翻译的基本块（入口块除外）
    // 入口块不缓存是因为它的地址是用户提供的，不会被再次跳转到
    if (type != ENDING_ROUTER_TYPE) {
        Memory::set_cache_block_meta(target_addr, block_meta->index);
    }
}

/**
 * @brief 扫描并翻译基本块
 * 
 * 这是翻译器的核心函数，遍历原始代码的每条指令，
 * 根据指令类型进行相应的翻译处理。
 * 
 * 翻译策略：
 * - 控制流指令（B, BL, BR, BLR, RET, CBZ, CBNZ, TBZ, TBNZ）：结束当前块，跳转到 Router
 * - PC 相关指令（ADRP, ADR）：重新计算地址
 * - 普通指令：插入回调后直接复制
 * 
 * @param target_addr 要翻译的原始代码地址
 * @param block_meta 基本块元数据，用于存储翻译后的代码
 * @param type 路由类型，决定块的开头处理方式
 */
void Translator::scan(uint64_t target_addr, BlockMeta* block_meta, ROUTER_TYPE type) {
    // ===== 确保翻译器已初始化 =====
    init_translator();
    if (!translator_initialized) {
        LOGE("[Translator] Not initialized, cannot scan");
        return;
    }

    // 获取代码写入位置
    auto dbi_code = (uint32_t*)block_meta->code;
    
    // ===== 根据路由类型处理块开头 =====
    switch (type) {
        case ENDING_ROUTER_TYPE:
            // 入口块：保存结束地址（用于检测函数返回）
            Router::save_ending_addr(dbi_code);
            break;
        default:
            // 非入口块：恢复 Router 保存的寄存器
            Router::pop_register(dbi_code);
            break;
    }

    // ===== 检查是否已到达结束地址 =====
    // 如果目标地址等于结束地址，说明函数已返回，生成 RET 指令
    if (Router::ending_addr == target_addr) {
        Assembler::ret(*dbi_code, REG_LR);
        dbi_code++;
        return block_ending(type, block_meta, (uint8_t*)dbi_code, target_addr, target_addr);
    }

    // ===== 遍历并翻译指令 =====
    int offset = 0;
    // 安全限制：防止无限循环导致块溢出
    const int max_instructions = BLOCK_SIZE / 10;

    while (offset / A64_INS_WIDTH < max_instructions) {
        uint64_t pc = target_addr + offset;
        
        // 使用 cs_disasm_iter 进行反汇编（比 cs_disasm 更高效）
        const uint8_t* code_ptr = (uint8_t*)pc;
        size_t code_size = A64_INS_WIDTH;  // ARM64 指令固定 4 字节
        uint64_t addr = pc;
        
        // 反汇编失败时，尝试作为普通指令处理
        if (!cs_disasm_iter(translator_handle, &code_ptr, &code_size, &addr, translator_insn)) {
            LOGE("[Translator] Failed to disassemble at 0x%llx", (unsigned long long)pc);
            default_ins_handle(dbi_code, pc);
            offset += A64_INS_WIDTH;
            continue;
        }

        // ===== 根据指令类型进行翻译 =====
        switch (translator_insn->id) {
            // ----- 无条件/条件分支指令 -----
            case AARCH64_INS_B:
                b_ins_handle(dbi_code, pc);
                return block_ending(type, block_meta, (uint8_t*)dbi_code, target_addr, pc);
            
            // ----- 函数调用指令 -----
            case AARCH64_INS_BL:
                bl_ins_handle(dbi_code, pc);
                return block_ending(type, block_meta, (uint8_t*)dbi_code, target_addr, pc);
            
            // ----- 间接跳转指令 -----
            case AARCH64_INS_BR:
                br_ins_handle(dbi_code, pc);
                return block_ending(type, block_meta, (uint8_t*)dbi_code, target_addr, pc);
            
            // ----- 间接函数调用指令 -----
            case AARCH64_INS_BLR:
                blr_ins_handle(dbi_code, pc);
                return block_ending(type, block_meta, (uint8_t*)dbi_code, target_addr, pc);
            
            // ----- 函数返回指令 -----
            case AARCH64_INS_RET:
                ret_ins_handle(dbi_code, pc);
                return block_ending(type, block_meta, (uint8_t*)dbi_code, target_addr, pc);
            
            // ----- 比较并分支指令 -----
            case AARCH64_INS_CBZ:
                cbz_ins_handle(dbi_code, pc, false);
                return block_ending(type, block_meta, (uint8_t*)dbi_code, target_addr, pc);
            
            case AARCH64_INS_CBNZ:
                cbz_ins_handle(dbi_code, pc, true);
                return block_ending(type, block_meta, (uint8_t*)dbi_code, target_addr, pc);
            
            // ----- 测试位并分支指令 -----
            case AARCH64_INS_TBZ:
                tbz_ins_handle(dbi_code, pc, false);
                return block_ending(type, block_meta, (uint8_t*)dbi_code, target_addr, pc);
            
            case AARCH64_INS_TBNZ:
                tbz_ins_handle(dbi_code, pc, true);
                return block_ending(type, block_meta, (uint8_t*)dbi_code, target_addr, pc);
            
            // ----- PC 相对地址计算指令 -----
            case AARCH64_INS_ADRP:
                adrp_ins_handle(dbi_code, pc);
                break;
            
            case AARCH64_INS_ADR:
                adr_ins_handle(dbi_code, pc);
                break;
            
            // ----- 普通指令 -----
            default:
                default_ins_handle(dbi_code, pc);
                break;
        }

        offset += A64_INS_WIDTH;
    }

    LOGE("[Translator] Warning: Block reached max instruction limit (%d)", max_instructions);
}

// ==================== 指令翻译处理函数 ====================

/**
 * @brief 翻译 B.cond 条件分支指令
 * 
 * 生成代码结构：
 *   push_register          ; 保存寄存器
 *   mov x1, B_ROUTER_TYPE  ; 设置路由类型
 *   b.cond taken_path      ; 条件成立跳转
 *   b not_taken_path       ; 条件不成立跳转
 * taken_path:
 *   mov x0, target_addr    ; 加载目标地址
 *   br router              ; 跳转到路由器
 * not_taken_path:
 *   mov x0, next_pc        ; 加载下一条指令地址
 *   br router              ; 跳转到路由器
 */
void Translator::b_cond_ins_handle(uint32_t *&writer, uint64_t pc) {
    // 1. 插入回调代码
    callback(writer, pc);

    // 2. 保存寄存器（Router 需要）
    Router::push_register(writer);

    // 3. 设置路由类型
    Assembler::write_value_to_reg(writer, REG_X1, B_ROUTER_TYPE);

    // 4. 生成条件分支指令（修改目标地址）
    uint32_t instruction;
    Assembler::modify_b_cond_addr(instruction, *(uint32_t*)translator_insn->bytes, 
                                   *writer, *writer + A64_INS_WIDTH * 2);
    *writer = instruction;
    writer++;

    // 5. 生成无条件跳转（跳过 taken_path）
    Assembler::b(instruction, *writer, *writer + A64_INS_WIDTH * 8);
    *writer = instruction;
    writer++;

    // 6. taken_path: 条件成立时的目标地址
    uint64_t b_addr;
    Assembler::get_b_addr(b_addr, pc, *(uint32_t*)translator_insn->bytes);
    Assembler::write_value_to_reg(writer, REG_X0, b_addr);
    Assembler::br_x16_jump(writer, (uint64_t)router);

    // 7. not_taken_path: 条件不成立时继续执行下一条
    Assembler::write_value_to_reg(writer, REG_X0, pc + A64_INS_WIDTH);
    Assembler::br_x16_jump(writer, (uint64_t)router);
}

/**
 * @brief 翻译 B 无条件分支指令
 * 
 * 检测是否为条件分支 (B.cond)，如果是则调用 b_cond_ins_handle。
 * 
 * 生成代码结构（无条件跳转）：
 *   callback               ; 用户回调
 *   push_register          ; 保存寄存器
 *   mov x1, B_ROUTER_TYPE  ; 设置路由类型
 *   mov x0, target_addr    ; 加载目标地址
 *   br router              ; 跳转到路由器
 */
void Translator::b_ins_handle(uint32_t *&writer, uint64_t pc) {
    // 检查是否为条件分支
    if (Assembler::b_is_cond(*(uint32_t*)translator_insn->bytes)) {
        b_cond_ins_handle(writer, pc);
        return;
    }

    // 无条件分支处理
    callback(writer, pc);
    Router::push_register(writer);
    Assembler::write_value_to_reg(writer, REG_X1, B_ROUTER_TYPE);

    // 计算跳转目标地址
    uint64_t b_addr;
    Assembler::get_b_addr(b_addr, pc, *(uint32_t*)translator_insn->bytes);
    Assembler::write_value_to_reg(writer, REG_X0, b_addr);

    Assembler::br_x16_jump(writer, (uint64_t)router);
}

/**
 * @brief 翻译 BL 函数调用指令
 * 
 * 生成代码结构：
 *   callback               ; 用户回调
 *   mov lr, next_pc        ; 设置返回地址
 *   push_register          ; 保存寄存器
 *   mov x1, BL_ROUTER_TYPE ; 设置路由类型
 *   mov x0, target_addr    ; 加载目标地址
 *   br router              ; 跳转到路由器
 */
void Translator::bl_ins_handle(uint32_t *&writer, uint64_t pc) {
    callback(writer, pc);

    // 设置 LR 为返回地址（下一条指令）
    Assembler::write_value_to_reg(writer, REG_LR, pc + A64_INS_WIDTH);

    Router::push_register(writer);
    Assembler::write_value_to_reg(writer, REG_X1, BL_ROUTER_TYPE);

    // 计算调用目标地址
    uint64_t bl_addr;
    Assembler::get_bl_addr(bl_addr, pc, *(uint32_t*)translator_insn->bytes);
    Assembler::write_value_to_reg(writer, REG_X0, bl_addr);

    Assembler::br_x16_jump(writer, (uint64_t)router);
}

/**
 * @brief 翻译 BR 间接跳转指令
 * 
 * BR Rn 从寄存器读取跳转目标地址。
 * 
 * 生成代码结构：
 *   callback               ; 用户回调
 *   push_register          ; 保存寄存器
 *   mov x1, BR_ROUTER_TYPE ; 设置路由类型
 *   mov x0, Rn             ; 从目标寄存器复制地址
 *   br router              ; 跳转到路由器
 */
void Translator::br_ins_handle(uint32_t *&writer, uint64_t pc) {
    callback(writer, pc);
    Router::push_register(writer);
    Assembler::write_value_to_reg(writer, REG_X1, BR_ROUTER_TYPE);

    // 获取 BR 指令的目标寄存器
    auto reg = Assembler::get_br_reg(*(uint32_t*)translator_insn->bytes);

    // 将目标地址复制到 X0
    uint32_t instruction;
    Assembler::mov_x_to_x(instruction, REG_X0, reg);
    *writer = instruction;
    writer++;

    Assembler::br_x16_jump(writer, (uint64_t)router);
}

/**
 * @brief 翻译 BLR 间接函数调用指令
 * 
 * BLR Rn 从寄存器读取调用目标地址，并设置返回地址。
 * 
 * 生成代码结构：
 *   callback                ; 用户回调
 *   mov lr, next_pc         ; 设置返回地址
 *   push_register           ; 保存寄存器
 *   mov x1, BLR_ROUTER_TYPE ; 设置路由类型
 *   mov x0, Rn              ; 从目标寄存器复制地址
 *   br router               ; 跳转到路由器
 */
void Translator::blr_ins_handle(uint32_t *&writer, uint64_t pc) {
    callback(writer, pc);

    // 设置 LR 为返回地址
    Assembler::write_value_to_reg(writer, REG_LR, pc + A64_INS_WIDTH);

    Router::push_register(writer);
    Assembler::write_value_to_reg(writer, REG_X1, BLR_ROUTER_TYPE);

    // 获取 BLR 指令的目标寄存器
    auto reg = Assembler::get_blr_reg(*(uint32_t*)translator_insn->bytes);

    // 将目标地址复制到 X0
    uint32_t instruction;
    Assembler::mov_x_to_x(instruction, REG_X0, reg);
    *writer = instruction;
    writer++;

    Assembler::br_x16_jump(writer, (uint64_t)router);
}

/**
 * @brief 翻译 ADRP 页地址计算指令
 * 
 * ADRP 计算 4KB 对齐的页地址：target = (PC & ~0xFFF) + (imm << 12)
 * 由于代码被重定位，需要预先计算绝对地址。
 * 
 * 生成代码结构：
 *   callback               ; 用户回调
 *   mov Rd, abs_addr       ; 直接加载计算好的绝对地址
 */
void Translator::adrp_ins_handle(uint32_t *&writer, uint64_t pc) {
    callback(writer, pc);

    // 计算 ADRP 的绝对目标地址
    uint64_t adrp_addr;
    Assembler::get_adrp_addr(adrp_addr, pc, *(uint32_t*)translator_insn->bytes);
    
    // 获取目标寄存器
    auto reg = Assembler::get_adrp_reg(*(uint32_t*)translator_insn->bytes);
    
    // 直接将绝对地址写入寄存器
    Assembler::write_value_to_reg(writer, reg, adrp_addr);
}

/**
 * @brief 翻译 ADR 地址计算指令
 * 
 * ADR 计算 PC 相对地址：target = PC + imm
 * 由于代码被重定位，需要预先计算绝对地址。
 * 
 * 生成代码结构：
 *   callback               ; 用户回调
 *   mov Rd, abs_addr       ; 直接加载计算好的绝对地址
 */
void Translator::adr_ins_handle(uint32_t *&writer, uint64_t pc) {
    callback(writer, pc);

    // 计算 ADR 的绝对目标地址
    uint64_t adr_addr;
    Assembler::get_adr_addr(adr_addr, pc, *(uint32_t*)translator_insn->bytes);
    
    // 获取目标寄存器
    auto reg = Assembler::get_adr_reg(*(uint32_t*)translator_insn->bytes);
    
    // 直接将绝对地址写入寄存器
    Assembler::write_value_to_reg(writer, reg, adr_addr);
}

/**
 * @brief 翻译 CBZ/CBNZ 比较并分支指令
 * 
 * CBZ: 如果寄存器为零则跳转
 * CBNZ: 如果寄存器不为零则跳转
 * 
 * 生成代码结构：
 *   callback               ; 用户回调
 *   push_register          ; 保存寄存器
 *   mov x1, B_ROUTER_TYPE  ; 设置路由类型
 *   cbz/cbnz Rt, taken     ; 条件分支
 *   b not_taken            ; 无条件跳转
 * taken:
 *   mov x0, target_addr    ; 条件成立目标
 *   br router
 * not_taken:
 *   mov x0, next_pc        ; 条件不成立，继续执行
 *   br router
 * 
 * @param is_cbnz true 表示 CBNZ，false 表示 CBZ
 */
void Translator::cbz_ins_handle(uint32_t *&writer, uint64_t pc, bool is_cbnz) {
    callback(writer, pc);
    Router::push_register(writer);
    Assembler::write_value_to_reg(writer, REG_X1, B_ROUTER_TYPE);

    // 获取 CBZ/CBNZ 的寄存器和位宽
    auto reg = Assembler::get_cbz_reg(*(uint32_t*)translator_insn->bytes);
    bool is_64bit = Assembler::cbz_is_64bit(*(uint32_t*)translator_insn->bytes);
    
    // 生成条件分支：跳过 1 条 B 指令
    uint32_t cbz_instr;
    Assembler::cbz(cbz_instr, reg, (uint64_t)writer, 
                   (uint64_t)writer + A64_INS_WIDTH * 2, is_64bit, is_cbnz);
    *writer = cbz_instr;
    writer++;

    // 生成无条件跳转：跳过 taken_path（约 9 条指令）
    uint32_t b_instr;
    Assembler::b(b_instr, (uint64_t)writer, (uint64_t)writer + A64_INS_WIDTH * 9);
    *writer = b_instr;
    writer++;

    // taken_path: 条件成立
    uint64_t cbz_target_addr;
    Assembler::get_cbz_addr(cbz_target_addr, pc, *(uint32_t*)translator_insn->bytes);
    Assembler::write_value_to_reg(writer, REG_X0, cbz_target_addr);
    Assembler::br_x16_jump(writer, (uint64_t)router);

    // not_taken_path: 条件不成立
    Assembler::write_value_to_reg(writer, REG_X0, pc + A64_INS_WIDTH);
    Assembler::br_x16_jump(writer, (uint64_t)router);
}

/**
 * @brief 翻译 TBZ/TBNZ 测试位并分支指令
 * 
 * TBZ: 如果指定位为零则跳转
 * TBNZ: 如果指定位不为零则跳转
 * 
 * @param is_tbnz true 表示 TBNZ，false 表示 TBZ
 */
void Translator::tbz_ins_handle(uint32_t *&writer, uint64_t pc, bool is_tbnz) {
    callback(writer, pc);
    Router::push_register(writer);
    Assembler::write_value_to_reg(writer, REG_X1, B_ROUTER_TYPE);

    // 获取 TBZ/TBNZ 的寄存器和测试位
    auto reg = Assembler::get_tbz_reg(*(uint32_t*)translator_insn->bytes);
    uint8_t bit = Assembler::get_tbz_bit(*(uint32_t*)translator_insn->bytes);
    
    // 生成条件分支
    uint32_t tbz_instr;
    Assembler::tbz(tbz_instr, reg, bit, (uint64_t)writer, 
                   (uint64_t)writer + A64_INS_WIDTH * 2, is_tbnz);
    *writer = tbz_instr;
    writer++;

    // 生成无条件跳转
    uint32_t b_instr;
    Assembler::b(b_instr, (uint64_t)writer, (uint64_t)writer + A64_INS_WIDTH * 9);
    *writer = b_instr;
    writer++;

    // taken_path: 条件成立
    uint64_t tbz_target_addr;
    Assembler::get_tbz_addr(tbz_target_addr, pc, *(uint32_t*)translator_insn->bytes);
    Assembler::write_value_to_reg(writer, REG_X0, tbz_target_addr);
    Assembler::br_x16_jump(writer, (uint64_t)router);

    // not_taken_path: 条件不成立
    Assembler::write_value_to_reg(writer, REG_X0, pc + A64_INS_WIDTH);
    Assembler::br_x16_jump(writer, (uint64_t)router);
}

/**
 * @brief 翻译 RET 函数返回指令
 * 
 * RET 默认从 LR (X30) 读取返回地址。
 * 
 * 生成代码结构：
 *   callback                ; 用户回调
 *   push_register           ; 保存寄存器
 *   mov x1, RET_ROUTER_TYPE ; 设置路由类型
 *   mov x0, lr              ; 从 LR 获取返回地址
 *   br router               ; 跳转到路由器
 */
void Translator::ret_ins_handle(uint32_t *&writer, uint64_t pc) {
    callback(writer, pc);
    Router::push_register(writer);
    Assembler::write_value_to_reg(writer, REG_X1, RET_ROUTER_TYPE);

    // 将 LR 的值复制到 X0
    uint32_t instruction;
    Assembler::mov_x_to_x(instruction, REG_X0, REG_LR);
    *writer = instruction;
    writer++;

    Assembler::br_x16_jump(writer, (uint64_t)router);
}

/**
 * @brief 生成回调代码
 * 
 * 在每条指令执行前调用用户回调函数。
 * 
 * 生成代码结构：
 *   prolog                  ; 保存所有寄存器到 CPU_CONTEXT
 *   mov [sp+256], pc        ; 写入当前 PC
 *   mov x0, sp              ; 参数 = CPU_CONTEXT 指针
 *   blr callback            ; 调用用户回调
 *   epilog                  ; 恢复所有寄存器
 */
void Translator::callback(uint32_t *&writer, uint64_t pc) {
    // 1. 保存寄存器 (prolog)
    Assembler::prolog(writer);
    
    // 2. 写入当前 PC 到 CPU_CONTEXT
    Assembler::write_pc_to_cpu(writer, pc);
    
    // 3. 设置参数：X0 = CPU_CONTEXT 指针
    Assembler::mov_sp_to_x(*writer, REG_X0);
    writer++;
    
    // 4. 调用用户回调
    Assembler::call_dbi_callback(writer);
    
    // 5. 恢复寄存器 (epilog)
    Assembler::epilog(writer);
}

/**
 * @brief 翻译普通指令（非控制流、非 PC 相关）
 * 
 * 对于不需要特殊处理的指令，直接插入回调后复制原指令。
 * 
 * 生成代码结构：
 *   callback                ; 用户回调
 *   <original instruction>  ; 原指令直接复制
 */
void Translator::default_ins_handle(uint32_t *&writer, uint64_t pc) {
    callback(writer, pc);
    
    // 直接复制原指令机器码
    *writer = *(uint32_t*)translator_insn->bytes;
    writer++;
}
