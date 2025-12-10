/**
 * @file Assembler.cpp
 * @brief ARM64 机器码生成器实现
 * @author lidongyooo
 * @date 2025/12/7
 * 
 * 本文件实现了 ARM64 指令的机器码生成功能，包括：
 * - 基本指令生成：MOV, STR, B, BL, BR, BLR, RET
 * - 地址解析：B, BL, ADRP, ADR, CBZ, CBNZ, TBZ, TBNZ
 * - 回调支持：prolog/epilog 寄存器保存/恢复
 * 
 * ARM64 指令编码参考：ARM Architecture Reference Manual
 */

#include "Assembler.h"

// ==================== 全局常量 ====================

/// prolog 代码大小（从汇编模板计算）
size_t prolog_size = ((uint64_t)end_prolog - (uint64_t)start_prolog) / A64_INS_WIDTH;
/// prolog 代码指针
auto prolog_ptr = (uint32_t*)start_prolog;

/// epilog 代码大小
size_t epilog_size = ((uint64_t)end_epilog - (uint64_t)start_epilog) / A64_INS_WIDTH;
/// epilog 代码指针
auto epilog_ptr = (uint32_t*)start_epilog;

// ==================== 寄存器保存/恢复 ====================

/**
 * @brief 生成 prolog 代码（保存寄存器）
 * 
 * 将所有通用寄存器保存到栈上，形成 CPU_CONTEXT 结构。
 * 代码从 Assembler.S 中的 start_prolog 复制。
 * 
 * @param writer 代码写入位置，执行后自动前移
 */
void Assembler::prolog(uint32_t *&writer) {
    for (int i = 0; i < prolog_size; ++i) {
        writer[i] = prolog_ptr[i];
    }
    writer += prolog_size;
}

/**
 * @brief 生成 epilog 代码（恢复寄存器）
 * 
 * 从栈上恢复所有通用寄存器。
 * 代码从 Assembler.S 中的 start_epilog 复制。
 * 
 * @param writer 代码写入位置
 */
void Assembler::epilog(uint32_t *&writer) {
    for (int i = 0; i < epilog_size; ++i) {
        writer[i] = epilog_ptr[i];
    }
    writer += epilog_size;
}

// ==================== 基本指令生成 ====================

/**
 * @brief 生成 MOVZ 指令
 * 
 * MOVZ 将立即数移动到寄存器，并将其他位清零。
 * 指令格式: 1 10 100101 hw imm16 Rd
 * 
 * @param instr 输出的机器码
 * @param reg 目标寄存器
 * @param immediate 16位立即数
 * @param shift 移位量 (0, 16, 32, 48)
 */
void Assembler::movz(uint32_t &instr, ARM64_REGISTER reg, uint16_t immediate, uint8_t shift) {
    uint8_t hw = shift / 16;  // hw 字段: 0=不移位, 1=左移16, 2=左移32, 3=左移48
    // 0xD2800000 = 1101 0010 1000 0000 0000 0000 0000 0000
    instr = 0xD2800000 | ((immediate & 0xFFFF) << 5) | ((hw & 0x3) << 21) | (reg & 0x1F);
}

/**
 * @brief 生成 MOVK 指令
 * 
 * MOVK 将立即数移动到寄存器的指定位置，保留其他位。
 * 指令格式: 1 11 100101 hw imm16 Rd
 * 
 * @param instr 输出的机器码
 * @param reg 目标寄存器
 * @param immediate 16位立即数
 * @param shift 移位量 (0, 16, 32, 48)
 */
void Assembler::movk(uint32_t &instr, ARM64_REGISTER reg, uint16_t immediate, uint8_t shift) {
    uint8_t hw = shift / 16;
    // 0xF2800000 = 1111 0010 1000 0000 0000 0000 0000 0000
    instr = 0xF2800000 | ((immediate & 0xFFFF) << 5) | ((hw & 0x3) << 21) | (reg & 0x1F);
}

/**
 * @brief 生成 STR 指令（64位存储）
 * 
 * 将寄存器值存储到内存。
 * 指令格式: 11 111 0 01 00 imm12 Rn Rt
 * 
 * @param instr 输出的机器码
 * @param src_reg 源寄存器
 * @param dst_reg 基址寄存器
 * @param dst_offset 偏移量（必须是8的倍数）
 */
void Assembler::str(uint32_t &instr, ARM64_REGISTER src_reg, ARM64_REGISTER dst_reg, int dst_offset) {
    const uint scale = 8;  // 64位存储，偏移量按8字节对齐
    auto imm12 = (uint32_t)(dst_offset / scale);

    uint32_t size = 0x3;  // 64位
    instr = 0x39000000 | (size << 30) | (imm12 << 10) | (dst_reg << 5) | src_reg;
}

/**
 * @brief 将64位值写入寄存器
 * 
 * 使用 MOVZ + MOVK 指令序列将任意64位值加载到寄存器。
 * 优化：跳过值为0的16位段。
 * 
 * 示例：
 * - 值 0x1234: MOVZ X0, #0x1234 (1条指令)
 * - 值 0x12345678: MOVZ X0, #0x5678; MOVK X0, #0x1234, LSL #16 (2条指令)
 * 
 * @param writer 代码写入位置
 * @param reg 目标寄存器
 * @param value 要加载的64位值
 */
void Assembler::write_value_to_reg(uint32_t *&writer, ARM64_REGISTER reg, uint64_t value) {
    // 将64位值分成4个16位段
    uint16_t parts[4] = {
        static_cast<uint16_t>(value & 0xFFFF),
        static_cast<uint16_t>((value >> 16) & 0xFFFF),
        static_cast<uint16_t>((value >> 32) & 0xFFFF),
        static_cast<uint16_t>((value >> 48) & 0xFFFF)
    };

    // 找到最高的非零段
    int first_nonzero = -1;
    for (int i = 3; i >= 0; i--) {
        if (parts[i] != 0) {
            first_nonzero = i;
            break;
        }
    }

    // 如果全为0，生成 MOVZ Rd, #0
    if (first_nonzero == -1) {
        movz(*writer, reg, 0, 0);
        writer++;
        return;
    }

    // 使用 MOVZ 加载最高非零段
    movz(*writer, reg, parts[first_nonzero], first_nonzero * 16);
    writer++;

    // 使用 MOVK 加载其余非零段
    for (int i = first_nonzero - 1; i >= 0; i--) {
        if (parts[i] != 0) {
            movk(*writer, reg, parts[i], i * 16);
            writer++;
        }
    }
}

/**
 * @brief 生成 MOV Xd, SP 指令
 * 
 * 将 SP 的值复制到通用寄存器。
 * 实际编码为: ADD Xd, SP, #0
 * 
 * @param instr 输出的机器码
 * @param rd 目标寄存器
 */
void Assembler::mov_sp_to_x(uint32_t &instr, ARM64_REGISTER rd) {
    // 0x910003E0 = ADD Xd, SP, #0
    // SP 编码为 31 (0x1F)
    instr = 0x910003E0;
    instr |= rd;
}

/**
 * @brief 生成 BLR 指令
 * 
 * 间接函数调用，目标地址在寄存器中。
 * 指令格式: 1101 0110 0011 1111 0000 00 Rn 00000
 * 
 * @param instr 输出的机器码
 * @param reg 包含目标地址的寄存器
 */
void Assembler::blr(uint32_t &instr, ARM64_REGISTER reg) {
    // 0xD63F0000 = BLR
    instr = 0xD63F0000 | (reg << 5);
}

/**
 * @brief 生成 RET 指令
 * 
 * 函数返回，默认从 LR 读取返回地址。
 * 指令格式: 1101 0110 0101 1111 0000 00 Rn 00000
 * 
 * @param instr 输出的机器码
 * @param reg 包含返回地址的寄存器（通常是 LR）
 */
void Assembler::ret(uint32_t &instr, ARM64_REGISTER reg) {
    // 0xD65F0000 = RET
    instr = 0xD65F0000 | (reg << 5);
}

/**
 * @brief 生成 BR 指令
 * 
 * 间接跳转，目标地址在寄存器中。
 * 指令格式: 1101 0110 0001 1111 0000 00 Rn 00000
 * 
 * @param instr 输出的机器码
 * @param reg 包含目标地址的寄存器
 */
void Assembler::br(uint32_t &instr, ARM64_REGISTER reg) {
    // 0xD61F0000 = BR
    instr = 0xD61F0000 | (reg << 5);
}

/**
 * @brief 生成 B 无条件分支指令
 * 
 * 指令格式: 000101 imm26
 * 跳转范围: ±128MB
 * 
 * @param instr 输出的机器码
 * @param pc 当前 PC
 * @param target 目标地址
 */
void Assembler::b(uint32_t &instr, uint64_t pc, uint64_t target) {
    int64_t offset = target - pc;
    int64_t word_offset = offset >> 2;  // 除以4，因为 ARM64 指令是4字节对齐
    uint32_t imm26 = word_offset & 0x03FFFFFF;
    // 0x14000000 = B
    instr = 0x14000000 | imm26;
}

/**
 * @brief 生成 MOV Xd, Xn 指令
 * 
 * 将源寄存器的值复制到目标寄存器。
 * 实际编码为: ORR Xd, XZR, Xn
 * 
 * @param instr 输出的机器码
 * @param dest_reg 目标寄存器
 * @param src_reg 源寄存器
 */
void Assembler::mov_x_to_x(uint32_t &instr, uint8_t dest_reg, uint8_t src_reg) {
    // 0xAA0003E0 = ORR Xd, XZR, Xm (即 MOV)
    instr = 0xAA0003E0 | (src_reg << 16) | (dest_reg & 0x1F);
}

// ==================== 辅助跳转函数 ====================

/**
 * @brief 生成间接跳转代码（使用 X16）
 * 
 * 生成代码序列：
 *   MOV X16, target_addr
 *   BR X16
 * 
 * @param writer 代码写入位置
 * @param target_addr 目标地址
 */
void Assembler::br_x16_jump(uint32_t *&writer, uint64_t target_addr) {
    write_value_to_reg(writer, REG_X16, target_addr);
    uint32_t instruction;
    br(instruction, REG_X16);
    *writer = instruction;
    writer++;
}

/**
 * @brief 生成间接调用代码（使用 X16）
 * 
 * 生成代码序列：
 *   MOV X16, target_addr
 *   BLR X16
 * 
 * @param writer 代码写入位置
 * @param target_addr 目标地址
 */
void Assembler::blr_x16_jump(uint32_t *&writer, uint64_t target_addr) {
    write_value_to_reg(writer, REG_X16, target_addr);
    uint32_t instruction;
    blr(instruction, REG_X16);
    *writer = instruction;
    writer++;
}

// ==================== CPU 上下文操作 ====================

/**
 * @brief 将 PC 写入 CPU_CONTEXT
 * 
 * 生成代码：
 *   MOV X0, pc_value
 *   STR X0, [SP, #256]  ; CPU_CONTEXT.pc 偏移量
 * 
 * @param writer 代码写入位置
 * @param pc 当前 PC 值
 */
void Assembler::write_pc_to_cpu(uint32_t *&writer, uint64_t pc) {
    write_value_to_reg(writer, REG_X0, pc);
    // CPU_CONTEXT.pc 在偏移 256 字节处 (32 * 8)
    str(*writer, REG_X0, REG_SP, POINTER_SIZE * 32);
    writer++;
}

/**
 * @brief 生成调用 DBI 回调的代码
 * 
 * @param writer 代码写入位置
 */
void Assembler::call_dbi_callback(uint32_t *&writer) {
    blr_x16_jump(writer, (uint64_t)DBI::get_dbi_callback());
}

// ==================== 指令解析函数 ====================

/**
 * @brief 解析 B/B.cond 指令的目标地址
 * 
 * B 指令: 000101 imm26 (PC + imm26*4)
 * B.cond: 01010100 imm19 0 cond (PC + imm19*4)
 * 
 * @param addr 输出的目标地址
 * @param pc 当前 PC
 * @param machine_code 指令机器码
 */
void Assembler::get_b_addr(uint64_t &addr, uint64_t pc, uint32_t machine_code) {
    // 检查是 B 还是 B.cond
    if ((machine_code & 0xFC000000) == 0x14000000) {
        // B 指令: 26位有符号偏移
        int32_t imm26 = machine_code & 0x03FFFFFF;
        // 符号扩展
        if (imm26 & 0x02000000) imm26 |= 0xFC000000;
        addr = pc + ((int64_t)imm26 << 2);
    } else {
        // B.cond 指令: 19位有符号偏移
        int32_t imm19 = (machine_code >> 5) & 0x7FFFF;
        // 符号扩展
        if (imm19 & 0x40000) imm19 |= 0xFFF80000;
        addr = pc + ((int64_t)imm19 << 2);
    }
}

/**
 * @brief 解析 BL 指令的目标地址
 * 
 * BL 指令格式: 100101 imm26
 * 目标地址: PC + sign_extend(imm26) * 4
 * 
 * @param addr 输出的目标地址
 * @param pc 当前 PC
 * @param machine_code 指令机器码
 */
void Assembler::get_bl_addr(uint64_t &addr, uint64_t pc, uint32_t machine_code) {
    int32_t imm26 = machine_code & 0x03FFFFFF;
    // 符号扩展
    if (imm26 & 0x02000000) {
        imm26 |= 0xFC000000;
    }
    addr = pc + ((int64_t)imm26 << 2);
}

/**
 * @brief 解析 ADRP 指令的目标地址
 * 
 * ADRP 计算页地址: (PC & ~0xFFF) + sign_extend(imm) * 4096
 * 指令格式: 1 immlo 10000 immhi Rd
 * 
 * @param addr 输出的目标地址
 * @param pc 当前 PC
 * @param machine_code 指令机器码
 */
void Assembler::get_adrp_addr(uint64_t &addr, uint64_t pc, uint32_t machine_code) {
    // 提取立即数: immhi (bits 23:5) 和 immlo (bits 30:29)
    int32_t immhi = (machine_code >> 5) & 0x7FFFF;
    int32_t immlo = (machine_code >> 29) & 0x3;
    int32_t imm = (immhi << 2) | immlo;

    // 符号扩展 (21位有符号数)
    if (imm & 0x00100000) {
        imm |= 0xFFE00000;
    }

    // ADRP: 页对齐后加偏移
    uint64_t page_base = pc & ~0xFFFULL;  // 清除低12位
    addr = page_base + ((int64_t)imm << 12);  // 偏移量乘以4096
}

/**
 * @brief 获取 ADRP 指令的目标寄存器
 * @param machine_code 指令机器码
 * @return 目标寄存器编号
 */
ARM64_REGISTER Assembler::get_adrp_reg(uint32_t machine_code) {
    return (ARM64_REGISTER)(machine_code & 0x1F);
}

/**
 * @brief 获取 BR 指令的目标寄存器
 * @param machine_code 指令机器码
 * @return 目标寄存器编号
 */
ARM64_REGISTER Assembler::get_br_reg(uint32_t machine_code) {
    // Rn 在 bits [9:5]
    return (ARM64_REGISTER)((machine_code >> 5) & 0x1F);
}

/**
 * @brief 获取 BLR 指令的目标寄存器
 * @param machine_code 指令机器码
 * @return 目标寄存器编号
 */
ARM64_REGISTER Assembler::get_blr_reg(uint32_t machine_code) {
    // BLR 与 BR 格式相同，Rn 在 bits [9:5]
    return (ARM64_REGISTER)((machine_code >> 5) & 0x1F);
}

/**
 * @brief 检查 B 指令是否为条件分支
 * 
 * B (无条件): 000101 imm26 -> 0x14000000
 * B.cond:     01010100 imm19 0 cond
 * 
 * @param machine_code 指令机器码
 * @return true 如果是条件分支
 */
bool Assembler::b_is_cond(uint32_t machine_code) {
    // 检查高6位是否为 000101 (B 无条件)
    return !((machine_code & 0xFC000000) == 0x14000000);
}

/**
 * @brief 修改 B.cond 指令的目标地址
 * 
 * @param instr 输出的机器码
 * @param machine_code 原指令机器码
 * @param current_pc 新代码的 PC
 * @param new_address 新的目标地址
 */
void Assembler::modify_b_cond_addr(uint32_t &instr, uint32_t machine_code, 
                                    uint64_t current_pc, uint64_t new_address) {
    // 保留条件码 (bits [3:0])
    uint8_t cond = machine_code & 0xF;

    // 计算新偏移
    int64_t byte_offset = new_address - current_pc;
    int32_t word_offset = byte_offset >> 2;

    // 构建新指令: 01010100 imm19 0 cond
    instr = 0x54000000;
    instr |= (word_offset & 0x7FFFF) << 5;
    instr |= cond;
}

// ==================== CBZ/CBNZ 指令相关 ====================

/**
 * @brief 解析 CBZ/CBNZ 指令的目标地址
 * 
 * 指令格式: sf 011010 o imm19 Rt
 * 目标地址: PC + sign_extend(imm19) * 4
 * 
 * @param addr 输出的目标地址
 * @param pc 当前 PC
 * @param machine_code 指令机器码
 */
void Assembler::get_cbz_addr(uint64_t &addr, uint64_t pc, uint32_t machine_code) {
    int32_t imm19 = (machine_code >> 5) & 0x7FFFF;
    // 符号扩展 (19位有符号数)
    if (imm19 & 0x40000) {
        imm19 |= 0xFFF80000;
    }
    addr = pc + ((int64_t)imm19 << 2);
}

/**
 * @brief 获取 CBZ/CBNZ 指令的测试寄存器
 * @param machine_code 指令机器码
 * @return 测试寄存器编号
 */
ARM64_REGISTER Assembler::get_cbz_reg(uint32_t machine_code) {
    return (ARM64_REGISTER)(machine_code & 0x1F);
}

/**
 * @brief 检查 CBZ/CBNZ 指令是否为64位版本
 * @param machine_code 指令机器码
 * @return true 如果是64位版本
 */
bool Assembler::cbz_is_64bit(uint32_t machine_code) {
    // sf 在 bit 31
    return (machine_code >> 31) & 1;
}

/**
 * @brief 生成 CBZ/CBNZ 指令
 * 
 * @param instr 输出的机器码
 * @param reg 测试寄存器
 * @param pc 当前 PC
 * @param target 目标地址
 * @param is_64bit 是否为64位版本
 * @param is_cbnz true 生成 CBNZ，false 生成 CBZ
 */
void Assembler::cbz(uint32_t &instr, ARM64_REGISTER reg, uint64_t pc, 
                    uint64_t target, bool is_64bit, bool is_cbnz) {
    int64_t offset = target - pc;
    int32_t imm19 = (offset >> 2) & 0x7FFFF;
    
    // 基础编码: 0 011010 0 imm19 Rt (CBZ 32-bit)
    instr = 0x34000000;
    if (is_64bit) {
        instr |= (1U << 31);  // sf = 1
    }
    if (is_cbnz) {
        instr |= (1U << 24);  // o = 1
    }
    instr |= (imm19 << 5);
    instr |= (reg & 0x1F);
}

// ==================== TBZ/TBNZ 指令相关 ====================

/**
 * @brief 解析 TBZ/TBNZ 指令的目标地址
 * 
 * 指令格式: b5 011011 o b40 imm14 Rt
 * 目标地址: PC + sign_extend(imm14) * 4
 * 
 * @param addr 输出的目标地址
 * @param pc 当前 PC
 * @param machine_code 指令机器码
 */
void Assembler::get_tbz_addr(uint64_t &addr, uint64_t pc, uint32_t machine_code) {
    int32_t imm14 = (machine_code >> 5) & 0x3FFF;
    // 符号扩展 (14位有符号数)
    if (imm14 & 0x2000) {
        imm14 |= 0xFFFFC000;
    }
    addr = pc + ((int64_t)imm14 << 2);
}

/**
 * @brief 获取 TBZ/TBNZ 指令的测试寄存器
 * @param machine_code 指令机器码
 * @return 测试寄存器编号
 */
ARM64_REGISTER Assembler::get_tbz_reg(uint32_t machine_code) {
    return (ARM64_REGISTER)(machine_code & 0x1F);
}

/**
 * @brief 获取 TBZ/TBNZ 指令的测试位号
 * 
 * 位号由 b5 (bit 31) 和 b40 (bits 23:19) 组成
 * 
 * @param machine_code 指令机器码
 * @return 测试位号 (0-63)
 */
uint8_t Assembler::get_tbz_bit(uint32_t machine_code) {
    uint8_t b5 = (machine_code >> 31) & 1;
    uint8_t b40 = (machine_code >> 19) & 0x1F;
    return (b5 << 5) | b40;
}

/**
 * @brief 生成 TBZ/TBNZ 指令
 * 
 * @param instr 输出的机器码
 * @param reg 测试寄存器
 * @param bit 测试位号
 * @param pc 当前 PC
 * @param target 目标地址
 * @param is_tbnz true 生成 TBNZ，false 生成 TBZ
 */
void Assembler::tbz(uint32_t &instr, ARM64_REGISTER reg, uint8_t bit, 
                    uint64_t pc, uint64_t target, bool is_tbnz) {
    int64_t offset = target - pc;
    int32_t imm14 = (offset >> 2) & 0x3FFF;
    
    uint8_t b5 = (bit >> 5) & 1;
    uint8_t b40 = bit & 0x1F;
    
    // 基础编码: b5 011011 0 b40 imm14 Rt (TBZ)
    instr = 0x36000000;
    instr |= (b5 << 31);
    if (is_tbnz) {
        instr |= (1U << 24);  // o = 1
    }
    instr |= (b40 << 19);
    instr |= (imm14 << 5);
    instr |= (reg & 0x1F);
}

// ==================== ADR 指令相关 ====================

/**
 * @brief 解析 ADR 指令的目标地址
 * 
 * ADR 计算 PC 相对地址: PC + sign_extend(imm)
 * 指令格式: 0 immlo 10000 immhi Rd
 * 
 * @param addr 输出的目标地址
 * @param pc 当前 PC
 * @param machine_code 指令机器码
 */
void Assembler::get_adr_addr(uint64_t &addr, uint64_t pc, uint32_t machine_code) {
    int32_t immhi = (machine_code >> 5) & 0x7FFFF;
    int32_t immlo = (machine_code >> 29) & 0x3;
    int32_t imm = (immhi << 2) | immlo;
    
    // 符号扩展 (21位有符号数)
    if (imm & 0x00100000) {
        imm |= 0xFFE00000;
    }
    
    // ADR: 直接 PC + imm（不像 ADRP 那样页对齐）
    addr = pc + imm;
}

/**
 * @brief 获取 ADR 指令的目标寄存器
 * @param machine_code 指令机器码
 * @return 目标寄存器编号
 */
ARM64_REGISTER Assembler::get_adr_reg(uint32_t machine_code) {
    return (ARM64_REGISTER)(machine_code & 0x1F);
}
