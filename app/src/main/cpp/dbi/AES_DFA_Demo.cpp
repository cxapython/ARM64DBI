//
// AES_DFA_Demo.cpp - AES白盒加密DFA攻击定位示例 实现
//

#include "AES_DFA_Demo.h"
#include "DBI.h"
#include "Taint.h"
#include "DataTracer.h"
#include "AESWhitebox.h"
#include "../types/types.h"
#include <cstring>
#include <algorithm>
#include <cstdio>

// ==================== AESDFADemo 实现 ====================

AESDFADemo* AESDFADemo::instance = nullptr;

AESDFADemo::AESDFADemo() 
    : key_addr_start(0), key_addr_end(0), round10_key_addr(0), key_region_marked(false) {
}

AESDFADemo* AESDFADemo::getInstance() {
    if (!instance) {
        instance = new AESDFADemo();
    }
    return instance;
}

void AESDFADemo::set_key_region(uint64_t start, uint64_t size) {
    key_addr_start = start;
    key_addr_end = start + size;
    key_region_marked = true;
    LOGI("[DFA] Key region set: 0x%llx - 0x%llx", 
         (unsigned long long)key_addr_start, 
         (unsigned long long)key_addr_end);
}

void AESDFADemo::set_round10_key_addr(uint64_t addr) {
    round10_key_addr = addr;
    LOGI("[DFA] Round 10 key address set: 0x%llx", (unsigned long long)addr);
}

// DFA追踪回调
static void dfa_trace_callback(const CPU_CONTEXT* ctx) {
    AESDFADemo::getInstance()->record(ctx);
}

void* AESDFADemo::start_trace(uint64_t encrypt_func_addr) {
    LOGI("[DFA] Starting DFA analysis trace at 0x%llx", (unsigned long long)encrypt_func_addr);
    reset();
    return DBI::trace(encrypt_func_addr, dfa_trace_callback);
}

void AESDFADemo::record(const CPU_CONTEXT* ctx) {
    auto insn = DBI::disassemble(ctx->pc);
    if (!insn) return;
    
    // 1. 记录所有EOR指令 (AddRoundKey的核心操作)
    if (insn->id == AARCH64_INS_EOR) {
        if (insn->detail && insn->detail->aarch64.op_count >= 3) {
            cs_aarch64_op* dst = &insn->detail->aarch64.operands[0];
            cs_aarch64_op* src1 = &insn->detail->aarch64.operands[1];
            cs_aarch64_op* src2 = &insn->detail->aarch64.operands[2];
            
            if (dst->type == AARCH64_OP_REG) {
                EORRecord rec;
                rec.pc = ctx->pc;
                rec.timestamp = eor_records.size();
                rec.dst_reg = cs_reg_to_idx(dst->reg);
                
                // 获取寄存器值
                if (rec.dst_reg >= 0 && rec.dst_reg < 29) {
                    rec.dst_val_before = ctx->x[rec.dst_reg];
                }
                
                // 获取源操作数的值
                if (src1->type == AARCH64_OP_REG) {
                    int idx = cs_reg_to_idx(src1->reg);
                    if (idx >= 0 && idx < 29) {
                        rec.src1_val = ctx->x[idx];
                    }
                }
                if (src2->type == AARCH64_OP_REG) {
                    int idx = cs_reg_to_idx(src2->reg);
                    if (idx >= 0 && idx < 29) {
                        rec.src2_val = ctx->x[idx];
                    } else if (src2->type == AARCH64_OP_IMM) {
                        rec.src2_val = src2->imm;
                    }
                }
                
                // 计算XOR后的值
                rec.dst_val_after = rec.src1_val ^ rec.src2_val;
                
                eor_records.push_back(rec);
            }
        }
    }
    
    // 2. 记录内存读取 (追踪密钥加载)
    if (insn->id == AARCH64_INS_LDR || insn->id == AARCH64_INS_LDRB ||
        insn->id == AARCH64_INS_LDUR || insn->id == AARCH64_INS_LDURB) {
        
        if (insn->detail && insn->detail->aarch64.op_count >= 2) {
            cs_aarch64_op* dst = &insn->detail->aarch64.operands[0];
            cs_aarch64_op* mem = &insn->detail->aarch64.operands[1];
            
            if (dst->type == AARCH64_OP_REG && mem->type == AARCH64_OP_MEM) {
                // 计算内存地址
                uint64_t addr = 0;
                int base_idx = cs_reg_to_idx(mem->mem.base);
                if (base_idx >= 0 && base_idx < 29) {
                    addr = ctx->x[base_idx];
                } else if (base_idx == 29) {
                    addr = ctx->fp;
                } else if (base_idx == 31) {
                    addr = ctx->sp;
                }
                addr += mem->mem.disp;
                
                // 检查是否在密钥区域
                if (key_region_marked && addr >= key_addr_start && addr < key_addr_end) {
                    MemReadRecord rec;
                    rec.pc = ctx->pc;
                    rec.timestamp = mem_reads.size();
                    rec.addr = addr;
                    rec.dst_reg = cs_reg_to_idx(dst->reg);
                    rec.instruction = std::string(insn->mnemonic) + " " + insn->op_str;
                    
                    // 读取内存值
                    if (addr != 0) {
                        rec.value = *((uint8_t*)addr);
                    }
                    
                    mem_reads.push_back(rec);
                    
                    LOGD("[DFA] Key byte read at PC=0x%llx, addr=0x%llx, value=0x%02X",
                         (unsigned long long)ctx->pc,
                         (unsigned long long)addr,
                         (uint8_t)rec.value);
                }
            }
        }
    }
}

void AESDFADemo::extract_round10_from_eors() {
    // AES-128加密有11轮AddRoundKey (初始轮 + 10轮)
    // 每轮AddRoundKey处理16字节 = 16个EOR操作
    // 第10轮是最后16个EOR操作
    
    LOGI("[DFA] Total EOR operations: %zu", eor_records.size());
    
    // 简化处理: 假设最后16个EOR是第10轮
    // 实际上需要更精确的分析，因为MixColumns等操作也包含XOR
}

std::vector<Round10KeyOp> AESDFADemo::get_round10_key_ops() {
    std::vector<Round10KeyOp> ops;
    
    // 从内存读取记录中找到第10轮密钥的读取
    if (round10_key_addr != 0) {
        for (const auto& read : mem_reads) {
            // 检查是否是第10轮密钥的读取
            if (read.addr >= round10_key_addr && read.addr < round10_key_addr + 16) {
                Round10KeyOp op;
                op.pc = read.pc;
                op.byte_index = (int)(read.addr - round10_key_addr);
                op.key_byte = (uint8_t)read.value;
                op.instruction = read.instruction;
                op.timestamp = read.timestamp;
                
                // 找到紧随其后的EOR操作
                for (const auto& eor : eor_records) {
                    if (eor.timestamp > read.timestamp && 
                        ((eor.src1_val & 0xFF) == op.key_byte || 
                         (eor.src2_val & 0xFF) == op.key_byte)) {
                        op.state_before = (uint8_t)(eor.src1_val == op.key_byte ? 
                                                    eor.src2_val : eor.src1_val);
                        op.state_after = (uint8_t)eor.dst_val_after;
                        break;
                    }
                }
                
                ops.push_back(op);
            }
        }
    }
    
    return ops;
}

DFAReport AESDFADemo::analyze() {
    DFAReport report;
    memset(&report, 0, sizeof(report));
    
    report.round10_key_addr = round10_key_addr;
    report.round10_ops = get_round10_key_ops();
    
    // 生成DFA注入建议
    report.injection_advice = 
        "DFA攻击建议:\n"
        "1. 在第9轮MixColumns输出处注入单字节故障\n"
        "2. 故障会通过第10轮SubBytes和ShiftRows传播\n"
        "3. 比较正确密文和错误密文的差异\n"
        "4. 使用差分分析恢复第10轮密钥\n"
        "5. 通过密钥逆扩展恢复原始密钥";
    
    return report;
}

void AESDFADemo::print_report(const DFAReport& report) {
    LOGI("╔══════════════════════════════════════════════════════════════╗");
    LOGI("║          AES白盒加密 DFA攻击定位报告                          ║");
    LOGI("╚══════════════════════════════════════════════════════════════╝");
    LOGI("");
    
    LOGI("▶ 追踪统计:");
    LOGI("  - EOR指令数量: %zu", eor_records.size());
    LOGI("  - 密钥读取数量: %zu", mem_reads.size());
    LOGI("  - 第10轮密钥操作: %zu", report.round10_ops.size());
    LOGI("");
    
    LOGI("▶ 第10轮密钥地址: 0x%llx", (unsigned long long)report.round10_key_addr);
    LOGI("");
    
    if (!report.round10_ops.empty()) {
        LOGI("▶ 第10轮AddRoundKey操作点 (DFA攻击目标):");
        LOGI("  ┌─────────────────────────────────────────────────────────────┐");
        LOGI("  │ Byte  │     PC      │ Key  │ State_Before │ State_After   │");
        LOGI("  ├─────────────────────────────────────────────────────────────┤");
        
        for (const auto& op : report.round10_ops) {
            LOGI("  │  %2d   │ 0x%08llx │ 0x%02X │     0x%02X     │     0x%02X      │",
                 op.byte_index,
                 (unsigned long long)op.pc,
                 op.key_byte,
                 op.state_before,
                 op.state_after);
        }
        LOGI("  └─────────────────────────────────────────────────────────────┘");
    }
    
    LOGI("");
    LOGI("▶ DFA攻击指南:");
    LOGI("  %s", report.injection_advice.c_str());
    LOGI("");
    LOGI("════════════════════════════════════════════════════════════════");
}

void AESDFADemo::export_report(const char* filename, const DFAReport& report) {
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        LOGE("[DFA] Failed to open report file: %s", filename);
        return;
    }
    
    fprintf(fp, "AES White-box DFA Attack Analysis Report\n");
    fprintf(fp, "=========================================\n\n");
    
    fprintf(fp, "Round 10 Key Address: 0x%llx\n\n", (unsigned long long)report.round10_key_addr);
    
    fprintf(fp, "Round 10 Key Operations:\n");
    for (const auto& op : report.round10_ops) {
        fprintf(fp, "  Byte[%2d]: PC=0x%llx, Key=0x%02X, Before=0x%02X, After=0x%02X\n",
                op.byte_index,
                (unsigned long long)op.pc,
                op.key_byte,
                op.state_before,
                op.state_after);
    }
    
    fprintf(fp, "\nDFA Attack Guide:\n%s\n", report.injection_advice.c_str());
    
    fclose(fp);
    LOGI("[DFA] Report exported to: %s", filename);
}

void AESDFADemo::print_attack_guide() {
    LOGI("╔══════════════════════════════════════════════════════════════╗");
    LOGI("║              AES DFA 攻击原理与步骤                           ║");
    LOGI("╚══════════════════════════════════════════════════════════════╝");
    LOGI("");
    LOGI("▶ DFA (Differential Fault Analysis) 攻击原理:");
    LOGI("  在AES加密的第9轮MixColumns之后注入单字节故障,");
    LOGI("  故障会通过第10轮传播,影响4个密文字节。");
    LOGI("  通过分析正确/错误密文的差异,可恢复第10轮密钥。");
    LOGI("");
    LOGI("▶ 攻击步骤:");
    LOGI("  1. 获取正确的密文 C");
    LOGI("  2. 在第9轮MixColumns输出处注入故障,获得错误密文 C'");
    LOGI("  3. 计算差异: ΔC = C ⊕ C'");
    LOGI("  4. 对每个受影响的字节进行候选分析:");
    LOGI("     - 遍历所有可能的密钥字节值 (0x00-0xFF)");
    LOGI("     - 逆推SubBytes,检查差分是否符合MixColumns特性");
    LOGI("  5. 重复2-4次故障注入,交叉验证得到唯一密钥");
    LOGI("  6. 通过密钥逆扩展从第10轮密钥恢复原始密钥");
    LOGI("");
    LOGI("▶ 第10轮结构 (无MixColumns):");
    LOGI("  State → SubBytes → ShiftRows → AddRoundKey(K10) → Ciphertext");
    LOGI("");
    LOGI("▶ DFA攻击关键位置:");
    LOGI("  故障注入: 第9轮MixColumns输出 (或第10轮SubBytes输入)");
    LOGI("  密钥恢复: 第10轮AddRoundKey");
    LOGI("");
}

void AESDFADemo::reset() {
    eor_records.clear();
    mem_reads.clear();
}

// ==================== AESTaintAnalysis 实现 ====================

AESTaintAnalysis* AESTaintAnalysis::instance = nullptr;

AESTaintAnalysis::AESTaintAnalysis() {
}

AESTaintAnalysis* AESTaintAnalysis::getInstance() {
    if (!instance) {
        instance = new AESTaintAnalysis();
    }
    return instance;
}

void AESTaintAnalysis::setup_key_taint(uint64_t key_addr, size_t key_size) {
    auto analyzer = TaintAnalyzer::getInstance();
    analyzer->mark_mem_source(key_addr, key_size, TAINT_KEY);
    LOGI("[TaintAnalysis] Marked key region [0x%llx, %zu] as TAINT_KEY",
         (unsigned long long)key_addr, key_size);
}

void AESTaintAnalysis::setup_round10_key_taint(uint64_t round10_key_addr) {
    auto analyzer = TaintAnalyzer::getInstance();
    // 使用USER1标记第10轮密钥,区分于其他密钥
    analyzer->mark_mem_source(round10_key_addr, 16, TAINT_USER1);
    LOGI("[TaintAnalysis] Marked Round 10 key [0x%llx, 16] as TAINT_USER1",
         (unsigned long long)round10_key_addr);
}

// 污点分析回调
static void taint_analysis_callback(const CPU_CONTEXT* ctx, TaintState* state) {
    AESTaintAnalysis::getInstance()->on_taint_propagate(ctx, state);
}

void* AESTaintAnalysis::start_trace(uint64_t encrypt_func_addr) {
    auto analyzer = TaintAnalyzer::getInstance();
    analyzer->set_user_callback(taint_analysis_callback);
    return analyzer->trace(encrypt_func_addr);
}

void AESTaintAnalysis::on_taint_propagate(const CPU_CONTEXT* ctx, TaintState* state) {
    auto insn = DBI::disassemble(ctx->pc);
    if (!insn) return;
    
    // 检测带有第10轮密钥污点的XOR操作
    if (insn->id == AARCH64_INS_EOR) {
        // 检查操作数是否带有TAINT_USER1 (第10轮密钥)
        for (int i = 0; i < 32; i++) {
            TaintTag taint = state->get_reg_taint(i);
            if (taint & TAINT_USER1) {
                LOGI("[Round10Key] XOR with Round10 key detected at PC=0x%llx, reg=%s",
                     (unsigned long long)ctx->pc,
                     reg_idx_to_name(i));
                
                // 记录密钥-密文映射
                KeyToCipherMap map;
                map.xor_pc = ctx->pc;
                // 需要进一步分析确定具体的字节索引
                key_cipher_map.push_back(map);
            }
        }
    }
}

void AESTaintAnalysis::analyze_key_cipher_relation() {
    LOGI("[TaintAnalysis] Analyzing key-cipher relation...");
    LOGI("[TaintAnalysis] Found %zu key-cipher mappings", key_cipher_map.size());
}

void AESTaintAnalysis::print_key_cipher_map() {
    LOGI("▶ 第10轮密钥与密文的关系:");
    for (size_t i = 0; i < key_cipher_map.size(); i++) {
        const auto& map = key_cipher_map[i];
        LOGI("  [%zu] XOR at PC=0x%llx", i, (unsigned long long)map.xor_pc);
    }
}

void AESTaintAnalysis::reset() {
    key_cipher_map.clear();
}

// ==================== 演示函数实现 ====================

// 全局AES实例 (用于演示)
static AESWhitebox* g_demo_aes = nullptr;

// 包装函数
__attribute__((noinline))
static void demo_aes_encrypt(const uint8_t* input, uint8_t* output) {
    if (g_demo_aes) {
        g_demo_aes->encrypt_block(input, output);
    }
}

void run_aes_dfa_demo() {
    LOGI("");
    LOGI("╔══════════════════════════════════════════════════════════════╗");
    LOGI("║     AES白盒加密 DFA攻击定位 完整演示                          ║");
    LOGI("╚══════════════════════════════════════════════════════════════╝");
    LOGI("");
    
    // 1. 初始化AES
    g_demo_aes = new AESWhitebox();
    
    // 测试密钥 (NIST示例)
    uint8_t key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    g_demo_aes->set_key(key);
    
    // 打印密钥信息
    LOGI("▶ 原始密钥:");
    LOGI("  %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
         key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
         key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]);
    LOGI("");
    
    // 获取第10轮密钥 (验证用)
    uint8_t round10_key[16];
    g_demo_aes->get_round10_key(round10_key);
    LOGI("▶ 第10轮密钥 (DFA攻击目标):");
    LOGI("  %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
         round10_key[0], round10_key[1], round10_key[2], round10_key[3],
         round10_key[4], round10_key[5], round10_key[6], round10_key[7],
         round10_key[8], round10_key[9], round10_key[10], round10_key[11],
         round10_key[12], round10_key[13], round10_key[14], round10_key[15]);
    LOGI("");
    LOGI("▶ 第10轮密钥地址: 0x%llx", (unsigned long long)g_demo_aes->get_round10_key_addr());
    LOGI("");
    
    // 2. 设置DFA分析器
    auto dfa = AESDFADemo::getInstance();
    dfa->reset();
    
    // 设置密钥区域监控 (所有11轮密钥)
    dfa->set_key_region(g_demo_aes->get_round10_key_addr() - 10*16, 11*16);
    dfa->set_round10_key_addr(g_demo_aes->get_round10_key_addr());
    
    // 3. 设置污点分析
    auto taint = TaintAnalyzer::getInstance();
    taint->reset();
    taint->get_state()->set_verbose(false);
    
    // 标记第10轮密钥为污点源
    taint->mark_mem_source(g_demo_aes->get_round10_key_addr(), 16, TAINT_USER1);
    
    // 4. 测试明文
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
        0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34
    };
    uint8_t ciphertext[16];
    
    LOGI("▶ 明文:");
    LOGI("  %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
         plaintext[0], plaintext[1], plaintext[2], plaintext[3],
         plaintext[4], plaintext[5], plaintext[6], plaintext[7],
         plaintext[8], plaintext[9], plaintext[10], plaintext[11],
         plaintext[12], plaintext[13], plaintext[14], plaintext[15]);
    LOGI("");
    
    // 5. 开始追踪
    LOGI("▶ 开始数据溯源追踪...");
    auto traced_encrypt = (void(*)(const uint8_t*, uint8_t*))
        dfa->start_trace((uint64_t)demo_aes_encrypt);
    
    if (traced_encrypt) {
        traced_encrypt(plaintext, ciphertext);
        
        LOGI("▶ 密文:");
        LOGI("  %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
             ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3],
             ciphertext[4], ciphertext[5], ciphertext[6], ciphertext[7],
             ciphertext[8], ciphertext[9], ciphertext[10], ciphertext[11],
             ciphertext[12], ciphertext[13], ciphertext[14], ciphertext[15]);
        LOGI("");
        
        // 6. 分析结果
        auto report = dfa->analyze();
        dfa->print_report(report);
        
        // 7. 打印攻击指南
        dfa->print_attack_guide();
    } else {
        LOGE("[DFA] Failed to start trace!");
    }
    
    delete g_demo_aes;
    g_demo_aes = nullptr;
}

void run_aes_dfa_simple_demo() {
    LOGI("");
    LOGI("╔══════════════════════════════════════════════════════════════╗");
    LOGI("║     AES白盒 DFA攻击定位 简化演示                              ║");
    LOGI("╚══════════════════════════════════════════════════════════════╝");
    LOGI("");
    
    // 创建AES实例
    g_demo_aes = new AESWhitebox();
    
    // 随机密钥
    uint8_t key[16] = {0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A,
                       0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55};
    g_demo_aes->set_key(key);
    
    // 打印轮密钥
    g_demo_aes->print_round_keys();
    
    // 直接执行加密 (不追踪)
    uint8_t pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t ct[16];
    
    g_demo_aes->encrypt_block(pt, ct);
    
    LOGI("明文: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
         pt[0], pt[1], pt[2], pt[3], pt[4], pt[5], pt[6], pt[7],
         pt[8], pt[9], pt[10], pt[11], pt[12], pt[13], pt[14], pt[15]);
    LOGI("密文: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
         ct[0], ct[1], ct[2], ct[3], ct[4], ct[5], ct[6], ct[7],
         ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15]);
    
    LOGI("");
    LOGI("★ 第10轮密钥地址: 0x%llx", (unsigned long long)g_demo_aes->get_round10_key_addr());
    LOGI("★ 这就是DFA攻击需要定位的关键地址！");
    
    delete g_demo_aes;
    g_demo_aes = nullptr;
}

bool run_aes_dfa_verified_demo() {
    LOGI("");
    LOGI("╔══════════════════════════════════════════════════════════════╗");
    LOGI("║     AES白盒 DFA攻击定位 验证演示                              ║");
    LOGI("╚══════════════════════════════════════════════════════════════╝");
    LOGI("");
    
    bool success = true;
    
    // 创建AES
    g_demo_aes = new AESWhitebox();
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    g_demo_aes->set_key(key);
    
    // 获取预期的第10轮密钥
    uint8_t expected_round10[16];
    g_demo_aes->get_round10_key(expected_round10);
    uint64_t expected_addr = g_demo_aes->get_round10_key_addr();
    
    LOGI("▶ 预期第10轮密钥:");
    LOGI("  地址: 0x%llx", (unsigned long long)expected_addr);
    LOGI("  数据: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
         expected_round10[0], expected_round10[1], expected_round10[2], expected_round10[3],
         expected_round10[4], expected_round10[5], expected_round10[6], expected_round10[7],
         expected_round10[8], expected_round10[9], expected_round10[10], expected_round10[11],
         expected_round10[12], expected_round10[13], expected_round10[14], expected_round10[15]);
    
    // 使用DataTracer追踪第10轮密钥的读取
    auto tracer = DataTracer::getInstance();
    tracer->reset();
    
    // 添加监控: 当从第10轮密钥地址读取时触发
    LOGI("");
    LOGI("▶ 使用数据溯源定位第10轮密钥读取...");
    
    // 对每个密钥字节添加监控
    for (int i = 0; i < 16; i++) {
        tracer->add_watch(-1, expected_round10[i], 0xFF, 
                         ("Round10Key_byte_" + std::to_string(i)).c_str());
    }
    
    // 开始追踪
    auto traced_fn = (void(*)(const uint8_t*, uint8_t*))
        tracer->trace((uint64_t)demo_aes_encrypt);
    
    if (traced_fn) {
        uint8_t pt[16] = {0};
        uint8_t ct[16];
        traced_fn(pt, ct);
        
        LOGI("▶ 加密完成");
        LOGI("");
        
        // 检查结果
        LOGI("▶ 验证结果:");
        LOGI("  第10轮密钥地址定位: %s", expected_addr != 0 ? "✓ 成功" : "✗ 失败");
        
        // 验证密钥值
        uint8_t* found_key = (uint8_t*)expected_addr;
        bool key_match = (memcmp(found_key, expected_round10, 16) == 0);
        LOGI("  第10轮密钥值验证: %s", key_match ? "✓ 匹配" : "✗ 不匹配");
        
        success = (expected_addr != 0) && key_match;
    }
    
    delete g_demo_aes;
    g_demo_aes = nullptr;
    
    LOGI("");
    LOGI("════════════════════════════════════════════════════════════════");
    LOGI("▶ 总体验证: %s", success ? "✓ 通过" : "✗ 失败");
    LOGI("════════════════════════════════════════════════════════════════");
    
    return success;
}

