#include <jni.h>
#include <string>
#include "dbi/DBI.h"
#include "dbi/Taint.h"
#include "dbi/DataTracer.h"
#include "dbi/TraceFile.h"

// ============================================================================
// ARM64DBI 综合测试文件
// 
// 本文件包含:
// 1. 指令追踪测试 - 验证各类 ARM64 指令的正确处理
// 2. 污点分析测试 - 验证污点传播的正确性
// ============================================================================

// ==================== 辅助函数 ====================

/**
 * 从 CPU 上下文获取寄存器值
 * 
 * @param reg Capstone 寄存器ID
 * @param ctx CPU 上下文指针
 * @param out_value 输出寄存器值
 * @return 是否成功获取
 */
bool get_register_value(aarch64_reg reg, const CPU_CONTEXT* ctx, uint64_t& out_value) {
    uint64_t value = 0;

    // 处理 W 寄存器 (32位)
    if (reg >= AARCH64_REG_W0 && reg <= AARCH64_REG_W30) {
        int idx = reg - AARCH64_REG_W0;
        value = ctx->x[idx] & 0xFFFFFFFF;
    }
    // 处理 X 寄存器 (64位)
    else if (reg >= AARCH64_REG_X0 && reg <= AARCH64_REG_X28) {
        int idx = reg - AARCH64_REG_X0;
        value = ctx->x[idx];
    }
    // 处理特殊寄存器
    else {
        switch (reg) {
            case AARCH64_REG_SP: value = ctx->sp; break;
            case AARCH64_REG_FP: value = ctx->fp; break;
            case AARCH64_REG_LR: value = ctx->lr; break;
            default:
                return false;
        }
    }

    out_value = value;
    return true;
}

// ==================== 测试1: 快速排序 (基本指令测试) ====================
// 覆盖指令: B, BL, B.cond, RET, ADD, SUB, CMP, MOV, LDR, STR, STP, LDP, ADRP

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
void quick_sort_end(){}

// ==================== 测试2: 函数指针调用 (BLR 指令测试) ====================

typedef int (*binary_op_func)(int, int);

__attribute__((noinline))
int add_func(int a, int b) { return a + b; }

__attribute__((noinline))
int sub_func(int a, int b) { return a - b; }

__attribute__((noinline))
int mul_func(int a, int b) { return a * b; }

// 通过函数指针调用 - 产生 BLR 指令
__attribute__((noinline))
int call_via_ptr(binary_op_func fn, int a, int b) {
    return fn(a, b);  // BLR instruction
}

void test_blr_end(){}

// ==================== 测试3: 位测试分支 (CBZ/CBNZ/TBZ/TBNZ 指令测试) ====================

__attribute__((noinline))
int test_cbz(int* ptr) {
    // CBZ - 如果指针为空，返回 -1
    if (ptr == nullptr) {  // CBZ
        return -1;
    }
    return *ptr;
}

__attribute__((noinline))
int test_cbnz(int value) {
    // CBNZ - 如果值不为零
    if (value) {  // CBNZ
        return value * 2;
    }
    return 0;
}

__attribute__((noinline))
int test_tbz(int flags) {
    int result = 0;
    // TBZ/TBNZ - 测试特定位
    if (flags & 0x1) {  // 测试第0位
        result += 1;
    }
    if (flags & 0x2) {  // 测试第1位
        result += 10;
    }
    if (flags & 0x4) {  // 测试第2位
        result += 100;
    }
    return result;
}

void test_branch_end(){}

// ==================== 测试4: 加密相关操作 (污点分析核心测试) ====================

// 简单的 XOR 加密 (演示污点传播)
__attribute__((noinline))
void simple_xor_encrypt(uint8_t* data, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;  // EOR 指令 - 加密核心操作
    }
}

// 字节反转 (大小端转换)
__attribute__((noinline))
uint32_t byte_swap32(uint32_t value) {
    // 产生 REV 指令
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x000000FF) << 24);
}

// 位旋转
__attribute__((noinline))
uint32_t rotate_right(uint32_t value, int bits) {
    // 产生 ROR 指令
    return (value >> bits) | (value << (32 - bits));
}

// 条件选择 (加密中常用)
__attribute__((noinline))
int conditional_select(int a, int b, int condition) {
    // 产生 CSEL 指令
    return condition ? a : b;
}

void test_crypto_end(){}

// ==================== 测试5: 综合污点分析示例 ====================

// 模拟密钥派生函数
__attribute__((noinline))
void derive_key(uint8_t* derived, const uint8_t* master_key, const uint8_t* salt, size_t len) {
    for (size_t i = 0; i < len; i++) {
        // 混合操作 - 污点应该从 master_key 和 salt 传播到 derived
        uint8_t tmp = master_key[i];      // 从内存加载污点
        tmp ^= salt[i];                   // XOR 操作传播
        tmp = (tmp << 3) | (tmp >> 5);    // 位旋转
        derived[i] = tmp;                 // 存储到内存
    }
}

void test_derive_end(){}

// ==================== DBI 回调函数 ====================

// 基本追踪回调 - 打印每条指令及寄存器值
void trace_callback(const CPU_CONTEXT* cpu_context) {
    auto cs_insn = DBI::disassemble(cpu_context->pc);
    if (!cs_insn) return;
    
    char reg_value_info[1024] = {};
    char *reg_value_info_ptr = reg_value_info;

    // 收集所有操作数寄存器的值
    for (int i = 0; i < cs_insn->detail->aarch64.op_count; i++) {
        auto op = cs_insn->detail->aarch64.operands[i];
        const char* reg_name;
        uint64_t reg_value;
        if (op.type == AARCH64_OP_REG || op.type == AARCH64_OP_MEM_REG) {
            reg_name = cs_reg_name(DBI::get_cs_handle(), op.reg);
            get_register_value(op.reg, cpu_context, reg_value);
            int len = snprintf(reg_value_info_ptr, sizeof(reg_value_info) - (reg_value_info_ptr - reg_value_info),
                               "%s=0x%llx ", reg_name, (unsigned long long)reg_value);
            reg_value_info_ptr += len;
        }
    }
    LOGE("0x%llx: %s %s; %s", (unsigned long long)cpu_context->pc, 
         cs_insn->mnemonic, cs_insn->op_str, reg_value_info);
}

// 污点分析回调 - 额外处理污点信息
void taint_callback(const CPU_CONTEXT* ctx, TaintState* state) {
    auto insn = DBI::disassemble(ctx->pc);
    if (!insn) return;
    
    // 检查是否有寄存器带有污点
    bool has_taint = false;
    for (int i = 0; i < 32; i++) {
        if (state->get_reg_taint(i) != TAINT_NONE) {
            has_taint = true;
            break;
        }
    }
    
    if (has_taint) {
        LOGD("[TAINT TRACE] 0x%llx: %s %s", 
             (unsigned long long)ctx->pc, insn->mnemonic, insn->op_str);
    }
}

// 污点汇回调 - 当检测到敏感数据到达特定位置时调用
void sink_detected_callback(uint64_t pc, const std::string& location, TaintTag taint, void* user_data) {
    LOGE("!!! SENSITIVE DATA DETECTED !!!");
    LOGE("  PC: 0x%llx", (unsigned long long)pc);
    LOGE("  Location: %s", location.c_str());
    LOGE("  Taint: %s", format_taint_tag(taint).c_str());
}

// ==================== 测试执行函数 ====================

// 测试1: 基本指令追踪
void run_basic_trace_test() {
    LOGI("========================================");
    LOGI("TEST 1: Basic Instruction Tracing");
    LOGI("Testing: B, BL, B.cond, RET, LDR, STR, LDP, STP, ADRP");
    LOGI("========================================");
    
    int arr[] = {9, 3, 5, 8, 10, 1, 2, 6, 4};
    int n = sizeof(arr) / sizeof(arr[0]);
    
    // 开始追踪
    auto dbi_quick_sort = (void(*)(int[], int, int))
        DBI::trace((uint64_t)quick_sort, trace_callback);
    
    if (dbi_quick_sort) {
        dbi_quick_sort(arr, 0, n - 1);
        
        LOGI("Sorted result:");
        for (int i = 0; i < n; i++) {
            LOGI("  arr[%d] = %d", i, arr[i]);
        }
    } else {
        LOGE("Failed to start trace!");
    }
}

// 测试2: BLR 指令测试
void run_blr_test() {
    LOGI("========================================");
    LOGI("TEST 2: Indirect Call (BLR) Tracing");
    LOGI("========================================");
    
    auto dbi_call = (int(*)(binary_op_func, int, int))
        DBI::trace((uint64_t)call_via_ptr, trace_callback);
    
    if (dbi_call) {
        int result_add = dbi_call(add_func, 10, 5);
        LOGI("add_func(10, 5) = %d", result_add);
        
        int result_sub = dbi_call(sub_func, 10, 5);
        LOGI("sub_func(10, 5) = %d", result_sub);
        
        int result_mul = dbi_call(mul_func, 10, 5);
        LOGI("mul_func(10, 5) = %d", result_mul);
    }
}

// 测试3: 条件分支指令测试
void run_branch_test() {
    LOGI("========================================");
    LOGI("TEST 3: Branch Instructions (CBZ/CBNZ/TBZ/TBNZ)");
    LOGI("========================================");
    
    // CBZ 测试
    auto dbi_cbz = (int(*)(int*))DBI::trace((uint64_t)test_cbz, trace_callback);
    if (dbi_cbz) {
        int value = 42;
        LOGI("test_cbz(&value) = %d", dbi_cbz(&value));
        LOGI("test_cbz(nullptr) = %d", dbi_cbz(nullptr));
    }
    
    // CBNZ 测试
    auto dbi_cbnz = (int(*)(int))DBI::trace((uint64_t)test_cbnz, trace_callback);
    if (dbi_cbnz) {
        LOGI("test_cbnz(5) = %d", dbi_cbnz(5));
        LOGI("test_cbnz(0) = %d", dbi_cbnz(0));
    }
    
    // TBZ/TBNZ 测试
    auto dbi_tbz = (int(*)(int))DBI::trace((uint64_t)test_tbz, trace_callback);
    if (dbi_tbz) {
        LOGI("test_tbz(0b111) = %d", dbi_tbz(0b111));  // 应该返回 111
        LOGI("test_tbz(0b101) = %d", dbi_tbz(0b101));  // 应该返回 101
        LOGI("test_tbz(0b000) = %d", dbi_tbz(0b000));  // 应该返回 0
    }
}

// 测试4: 污点分析测试
void run_taint_test() {
    LOGI("========================================");
    LOGI("TEST 4: Taint Analysis");
    LOGI("========================================");
    
    // 获取污点分析器实例
    auto analyzer = TaintAnalyzer::getInstance();
    analyzer->reset();
    
    // 启用详细模式
    analyzer->get_state()->set_verbose(true);
    
    // 设置用户回调
    analyzer->set_user_callback(taint_callback);
    analyzer->set_sink_callback(sink_detected_callback, nullptr);
    
    // 准备测试数据
    uint8_t plaintext[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21};  // "Hello!"
    uint8_t key = 0xAB;
    size_t len = sizeof(plaintext);
    
    LOGI("Original data: %02X %02X %02X %02X %02X %02X",
         plaintext[0], plaintext[1], plaintext[2], 
         plaintext[3], plaintext[4], plaintext[5]);
    
    // 标记输入数据为污点源
    analyzer->add_watch_region((uint64_t)plaintext, len, TAINT_INPUT, "plaintext");
    
    // 标记密钥为污点源
    analyzer->mark_reg_source(2, TAINT_KEY);  // key 参数在 X2
    
    // 添加返回值汇点监控
    analyzer->add_return_sink(TAINT_INPUT | TAINT_KEY, "encrypted output");
    
    // 开始污点追踪
    auto dbi_encrypt = (void(*)(uint8_t*, size_t, uint8_t))
        analyzer->trace((uint64_t)simple_xor_encrypt);
    
    if (dbi_encrypt) {
        dbi_encrypt(plaintext, len, key);
        
        LOGI("Encrypted data: %02X %02X %02X %02X %02X %02X",
             plaintext[0], plaintext[1], plaintext[2], 
             plaintext[3], plaintext[4], plaintext[5]);
    }
    
    // 打印分析摘要
    analyzer->print_summary();
}

// 测试5: 完整污点流分析
void run_full_taint_flow_test() {
    LOGI("========================================");
    LOGI("TEST 5: Full Taint Flow Analysis");
    LOGI("========================================");
    
    auto analyzer = TaintAnalyzer::getInstance();
    analyzer->reset();
    analyzer->get_state()->set_verbose(true);
    
    // 测试数据
    uint8_t master_key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t salt[8] = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t derived[8] = {0};
    
    // 标记污点源
    analyzer->add_watch_region((uint64_t)master_key, 8, TAINT_KEY, "master_key");
    analyzer->add_watch_region((uint64_t)salt, 8, TAINT_IV, "salt");
    
    // 监控输出区域
    analyzer->add_sink_point(0, 0, TAINT_KEY | TAINT_IV, "derived_key_check");
    
    // 开始追踪
    auto dbi_derive = (void(*)(uint8_t*, const uint8_t*, const uint8_t*, size_t))
        analyzer->trace((uint64_t)derive_key);
    
    if (dbi_derive) {
        dbi_derive(derived, master_key, salt, 8);
        
        LOGI("Derived key: %02X %02X %02X %02X %02X %02X %02X %02X",
             derived[0], derived[1], derived[2], derived[3],
             derived[4], derived[5], derived[6], derived[7]);
    }
    
    // 打印污点状态
    analyzer->get_state()->dump_state();
    
    // 打印流图
    analyzer->get_state()->dump_flow_graph();
}

// ==================== 测试6: 数据溯源示例 ====================

// 简单的数据变换函数 (用于演示数据溯源)
__attribute__((noinline))
uint64_t transform_data(uint64_t input) {
    uint64_t a = input ^ 0x5A5A5A5A;     // XOR 操作
    uint64_t b = a + 0x12345678;          // 加法操作
    uint64_t c = (b << 8) | (b >> 56);    // 位旋转
    uint64_t d = c & 0xFF00FF00FF00FF00;  // 掩码操作
    return d;
}

void transform_end(){}

// 当监控值被触发时的回调
void on_value_found(const DataSource& source, void* user_data) {
    LOGI(">>> User callback: Found value source!");
    LOGI(">>> Type: %s", source_type_name(source.type));
    LOGI(">>> PC: 0x%llx", (unsigned long long)source.pc);
    LOGI(">>> Instruction: %s", source.instruction.c_str());
}

// 测试6: 数据溯源功能
void run_data_trace_test() {
    LOGI("========================================");
    LOGI("TEST 6: Data Source Tracing");
    LOGI("========================================");
    
    auto tracer = DataTracer::getInstance();
    tracer->reset();
    
    // 设置回调
    tracer->set_source_callback(on_value_found, nullptr);
    
    // 添加值监控点
    // 假设我们想知道 0xE5 这个值是怎么产生的
    // 这里我们监控一个变换后的特定值
    uint64_t test_input = 0x12345678;
    uint64_t expected_output = transform_data(test_input);
    
    LOGI("Input: 0x%llx", (unsigned long long)test_input);
    LOGI("Expected output: 0x%llx", (unsigned long long)expected_output);
    LOGI("Adding watch for output value...");
    
    // 监控 X0 寄存器中出现 expected_output 值
    tracer->add_watch(0, expected_output, 0xFFFFFFFFFFFFFFFF, "transform_result");
    
    // 开始追踪
    auto traced_func = (uint64_t(*)(uint64_t))tracer->trace((uint64_t)transform_data);
    
    if (traced_func) {
        uint64_t result = traced_func(test_input);
        LOGI("Actual result: 0x%llx", (unsigned long long)result);
        
        // 手动追溯 X0 的来源
        LOGI("--- Manual trace of X0 ---");
        auto source = tracer->trace_register(0);  // 追溯 X0
        tracer->print_source(source);
        
        // 获取完整追溯链
        LOGI("--- Full trace chain ---");
        auto chain = tracer->get_full_trace(0, 0, 10);
        tracer->print_trace_chain(chain);
    }
    
    // 打印统计
    size_t hist_size, watch_count;
    uint64_t timestamp;
    tracer->get_stats(&hist_size, &watch_count, &timestamp);
    LOGI("Statistics: history=%zu, watches=%zu, instructions=%llu",
         hist_size, watch_count, (unsigned long long)timestamp);
}

// ==================== 测试7: Trace 文件生成 ====================

// 测试: 生成 trace 文件用于算法还原
void run_trace_file_test() {
    LOGI("========================================");
    LOGI("TEST 7: Trace File Generation");
    LOGI("========================================");
    
    auto tf = TraceFile::getInstance();
    
    // 扫描已加载模块
    tf->scan_modules();
    tf->print_modules();
    
    // 配置
    TraceConfig config;
    config.output_path = "/data/local/tmp/quick_sort_trace";
    config.output_text = true;
    config.output_json = true;
    config.record_regs = true;
    config.record_memory = true;
    config.record_opcodes = true;
    config.max_records = 1000;  // 限制记录数
    
    tf->set_config(config);
    
    // 方式1: 直接指定函数地址
    LOGI("Starting trace of quick_sort function...");
    auto traced_sort = (void(*)(int[], int, int))tf->start_trace((uint64_t)quick_sort);
    
    if (traced_sort) {
        int arr[] = {5, 3, 8, 1, 9};
        traced_sort(arr, 0, 4);
        
        LOGI("Sorted: %d %d %d %d %d", arr[0], arr[1], arr[2], arr[3], arr[4]);
    }
    
    // 保存 trace 文件
    tf->save();
    
    // 导出不同格式
    tf->export_unidbg_format("/data/local/tmp/quick_sort_unidbg.txt");
    tf->export_ida_format("/data/local/tmp/quick_sort_ida.txt");
    tf->export_summary("/data/local/tmp/quick_sort_summary.txt");
    
    // 分析结果
    auto& records = tf->get_records();
    LOGI("Total trace records: %zu", records.size());
    
    // 查找特定指令
    auto eor_insns = tf->find_instructions("eor");
    LOGI("Found %zu EOR instructions (crypto operations)", eor_insns.size());
    
    LOGI("Trace files saved to /data/local/tmp/");
}

// ==================== JNI 入口 ====================

typedef int (*quick_sort_sign)(int arr[], int left, int right);

extern "C" JNIEXPORT jstring JNICALL
Java_com_lidongyooo_arm64dbidemo_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    
    LOGI("============================================================");
    LOGI("ARM64DBI Comprehensive Test Suite");
    LOGI("============================================================");
    
    // 打印 DBI 状态
    DBI::print_status();
    
    // 运行所有测试
    
    // 测试1: 基本指令追踪 (快速排序)
    run_basic_trace_test();
    
    // 注意: 后续测试需要重新初始化 DBI 内存池
    // 在实际使用中，通常只追踪一个函数
    
    // 测试2: BLR 指令 (函数指针调用)
    // run_blr_test();
    
    // 测试3: 条件分支指令
    // run_branch_test();
    
    // 测试4: 污点分析
    // run_taint_test();
    
    // 测试5: 完整污点流
    // run_full_taint_flow_test();
    
    // 测试6: 数据溯源 (追踪值的来源)
    // run_data_trace_test();
    
    // 测试7: Trace 文件生成 (用于算法还原)
    run_trace_file_test();
    
    LOGI("============================================================");
    LOGI("All tests completed!");
    LOGI("============================================================");

    std::string hello = "ARM64DBI Tests Completed";
    return env->NewStringUTF(hello.c_str());
}
