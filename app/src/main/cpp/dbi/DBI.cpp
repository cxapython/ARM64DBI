/**
 * @file DBI.cpp
 * @brief ARM64 动态二进制插桩核心实现
 * @author lidongyooo
 * @date 2025/12/7
 * 
 * 本文件实现了 DBI 类的所有成员函数，是框架的核心控制逻辑。
 */

#include "DBI.h"

/// 单例实例初始化为空
DBI* DBI::instance = nullptr;

/**
 * @brief 开始追踪目标函数
 * 
 * 工作流程：
 * 1. 验证输入参数
 * 2. 检查 Capstone 和内存池初始化状态
 * 3. 分配基本块元数据
 * 4. 调用翻译器扫描并翻译目标代码
 * 5. 返回翻译后代码的入口地址
 * 
 * @param target_addr 要追踪的目标函数地址
 * @param dbi_callback 用户回调函数
 * @return 翻译后代码的入口地址，失败返回 nullptr
 */
void* DBI::trace(uint64_t target_addr, DBICallback dbi_callback) {
    auto self = getInstance();
    
    // ===== 参数验证 =====
    if (target_addr == 0) {
        LOGE("[DBI] Invalid target address: 0x0");
        return nullptr;
    }
    
    if (dbi_callback == nullptr) {
        LOGE("[DBI] Warning: DBI callback is null, no instrumentation will occur");
    }
    
    // ===== 检查 Capstone 初始化 =====
    if (self->dbi_cs_handle == 0) {
        LOGE("[DBI] Capstone disassembler not initialized");
        return nullptr;
    }
    
    // ===== 检查内存池状态 =====
    if (!Memory::is_initialized()) {
        LOGE("[DBI] Memory pool not initialized");
        return nullptr;
    }

    // ===== 保存用户回调函数 =====
    self->dbi_callback_ptr = dbi_callback;
    
    // ===== 分配基本块元数据 =====
    auto block_meta = Memory::get_or_new_block_meta();
    if (block_meta == nullptr) {
        LOGE("[DBI] Failed to allocate block metadata");
        return nullptr;
    }
    
    // ===== 调用翻译器翻译目标代码 =====
    // ENDING_ROUTER_TYPE 表示这是追踪入口，需要保存结束地址
    Translator::scan((uint64_t)target_addr, block_meta, ENDING_ROUTER_TYPE);
    
    // ===== 验证翻译结果 =====
    if (block_meta->block_start == nullptr) {
        LOGE("[DBI] Translation failed for address 0x%llx", (unsigned long long)target_addr);
        return nullptr;
    }
    
    // ===== 输出调试信息 =====
    LOGI("[DBI] Trace started successfully:");
    LOGI("[DBI]   Target address: 0x%llx", (unsigned long long)target_addr);
    LOGI("[DBI]   Translated code: %p", block_meta->block_start);
    LOGI("[DBI]   Code size: %d bytes", block_meta->block_size);

    return block_meta->block_start;
}

/**
 * @brief 获取当前设置的用户回调函数
 * @return 用户回调函数指针
 */
DBICallback DBI::get_dbi_callback() {
    return getInstance()->dbi_callback_ptr;
}

/**
 * @brief 反汇编指定地址的指令
 * 
 * 使用 Capstone 引擎反汇编单条 ARM64 指令。
 * 
 * @param pc 要反汇编的指令地址
 * @return Capstone 指令结构体指针，包含：
 *         - mnemonic: 指令助记符 (如 "add", "ldr")
 *         - op_str: 操作数字符串 (如 "x0, x1, x2")
 *         - detail: 详细信息，包含操作数类型、寄存器等
 */
cs_insn* DBI::disassemble(uint64_t pc) {
    auto self = getInstance();
    
    // 参数验证
    if (self->dbi_cs_handle == 0) {
        LOGE("[DBI] Capstone not initialized");
        return nullptr;
    }
    
    if (pc == 0) {
        LOGE("[DBI] Invalid PC: 0x0");
        return nullptr;
    }

    // 反汇编单条指令
    // 参数: handle, 代码指针, 代码大小, 地址, 指令数量, 输出
    size_t count = cs_disasm(self->dbi_cs_handle, 
                             (uint8_t*)pc, 
                             A64_INS_WIDTH,  // 4 字节
                             pc, 
                             1,              // 只反汇编 1 条
                             &self->dbi_cs_insn);
    
    if (count == 0) {
        LOGE("[DBI] Failed to disassemble at 0x%llx: %s", 
             (unsigned long long)pc, 
             cs_strerror(cs_errno(self->dbi_cs_handle)));
        return nullptr;
    }
    
    return self->dbi_cs_insn;
}

/**
 * @brief 获取 Capstone 引擎句柄
 * @return Capstone 句柄
 */
csh DBI::get_cs_handle() {
    return getInstance()->dbi_cs_handle;
}

/**
 * @brief 打印 DBI 框架状态信息
 * 
 * 用于调试和监控，输出当前框架的运行状态
 */
void DBI::print_status() {
    auto self = getInstance();
    
    LOGI("========== DBI Status ==========");
    LOGI("Capstone handle: %s", self->dbi_cs_handle ? "initialized" : "NOT initialized");
    LOGI("User callback: %s", self->dbi_callback_ptr ? "set" : "NOT set");
    LOGI("Memory pool: %s", Memory::is_initialized() ? "initialized" : "NOT initialized");
    LOGI("Blocks used: %d / %d", Memory::get_used_block_count(), BLOCK_NUMBER);
    LOGI("Blocks available: %d", Memory::get_available_block_count());
    LOGI("================================");
}
