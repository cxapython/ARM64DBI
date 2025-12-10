/**
 * @file DBI.h
 * @brief ARM64 动态二进制插桩 (Dynamic Binary Instrumentation) 核心头文件
 * @author lidongyooo
 * @date 2025/12/7
 * 
 * 本文件定义了 DBI 框架的核心类和数据结构，包括：
 * - CPU_CONTEXT: CPU 上下文结构，用于保存和恢复寄存器状态
 * - DBICallback: 用户回调函数类型定义
 * - DBI: 核心控制器类，提供追踪和反汇编功能
 */

#ifndef ARM64DBIDEMO_DBI_H
#define ARM64DBIDEMO_DBI_H

#include "../types/types.h"
#include "Memory.h"
#include "Utils.h"
#include "Router.h"
#include "Translator.h"

/**
 * @struct CPU_CONTEXT
 * @brief ARM64 CPU 上下文结构
 * 
 * 该结构体用于在指令执行期间保存完整的 CPU 状态，
 * 使用户回调函数可以访问所有寄存器的值。
 * 
 * 内存布局 (共 272 字节):
 * - offset 0:   fp (X29)
 * - offset 8:   lr (X30)
 * - offset 16:  x[0] - x[28]
 * - offset 248: sp
 * - offset 256: pc
 * - offset 264: nzcv
 */
typedef struct CPU_CONTEXT {
    uint64_t fp;      ///< 栈帧指针 (Frame Pointer, X29)
    uint64_t lr;      ///< 链接寄存器 (Link Register, X30)，存储函数返回地址
    int64_t x[29];    ///< 通用寄存器 X0-X28
    uint64_t sp;      ///< 栈指针 (Stack Pointer)
    uint64_t pc;      ///< 程序计数器 (Program Counter)，当前指令地址
    uint64_t nzcv;    ///< 条件标志位 (Negative, Zero, Carry, oVerflow)
} CPU_CONTEXT;

/**
 * @typedef DBICallback
 * @brief 用户自定义回调函数类型
 * 
 * 每条指令执行前都会调用此回调函数，用户可以在回调中：
 * - 读取当前 CPU 上下文
 * - 反汇编当前指令
 * - 记录执行日志
 * - 进行污点分析
 * 
 * @param cpu_context 指向当前 CPU 上下文的常量指针
 */
typedef void (*DBICallback)(const CPU_CONTEXT* cpu_context);

/**
 * @class DBI
 * @brief 动态二进制插桩核心控制器
 * 
 * DBI 类是整个框架的入口点，采用单例模式设计。
 * 主要功能：
 * - 管理 Capstone 反汇编引擎
 * - 提供追踪入口 (trace)
 * - 存储和管理用户回调函数
 * 
 * 使用示例:
 * @code
 * void my_callback(const CPU_CONTEXT* ctx) {
 *     auto insn = DBI::disassemble(ctx->pc);
 *     LOGE("0x%llx: %s %s", ctx->pc, insn->mnemonic, insn->op_str);
 * }
 * 
 * auto traced_func = (int(*)(int, int))DBI::trace((uint64_t)target_func, my_callback);
 * int result = traced_func(1, 2);
 * @endcode
 */
class DBI {
private:
    csh dbi_cs_handle;              ///< Capstone 反汇编引擎句柄
    cs_insn* dbi_cs_insn;           ///< Capstone 指令结构体指针
    static DBI* instance;           ///< 单例实例指针
    DBICallback dbi_callback_ptr;   ///< 用户回调函数指针
    
    /**
     * @brief 私有构造函数（单例模式）
     * 
     * 初始化 Capstone 反汇编引擎，设置为 ARM64 架构模式，
     * 并启用详细信息选项以获取操作数细节。
     */
    DBI() {
        cs_err err = cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &dbi_cs_handle);
        if (err != CS_ERR_OK) {
            LOGE("Failed to initialize Capstone: %s", cs_strerror(err));
            dbi_cs_handle = 0;
        } else {
            cs_option(dbi_cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
        }
        dbi_cs_insn = nullptr;
        dbi_callback_ptr = nullptr;
    }

public:
    // 禁用拷贝构造和赋值运算符（单例模式）
    DBI(const DBI&) = delete;
    DBI& operator=(const DBI&) = delete;

    /**
     * @brief 获取 DBI 单例实例
     * @return DBI 单例指针
     */
    static DBI* getInstance() {
        if (!instance) {
            instance = new DBI();
        }
        return instance;
    }

    /**
     * @brief 开始追踪目标函数
     * 
     * 这是 DBI 框架的核心入口函数。它会：
     * 1. 分配基本块元数据
     * 2. 调用翻译器翻译目标代码
     * 3. 返回翻译后代码的入口地址
     * 
     * @param target_addr 要追踪的目标函数地址
     * @param callback 用户回调函数，每条指令执行前调用
     * @return 翻译后代码的入口地址，可强转为函数指针调用
     */
    static void* trace(uint64_t target_addr, DBICallback callback);

    /**
     * @brief 获取当前设置的用户回调函数
     * @return 用户回调函数指针
     */
    static DBICallback get_dbi_callback();

    /**
     * @brief 反汇编指定地址的指令
     * 
     * 使用 Capstone 引擎反汇编单条 ARM64 指令。
     * 返回的结构体包含指令的助记符、操作数、详细信息等。
     * 
     * @param pc 要反汇编的指令地址
     * @return Capstone 指令结构体指针，失败返回 nullptr
     */
    static cs_insn* disassemble(uint64_t pc);
    
    /**
     * @brief 获取 Capstone 引擎句柄
     * @return Capstone 句柄，可用于高级操作
     */
    static csh get_cs_handle();
    
    /**
     * @brief 打印 DBI 状态信息
     * 
     * 输出当前 DBI 框架的运行状态，包括：
     * - Capstone 初始化状态
     * - 回调函数设置状态
     * - 内存池使用情况
     */
    static void print_status();
};

#endif //ARM64DBIDEMO_DBI_H
