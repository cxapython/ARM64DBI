//
// AES_DFA_Demo.h - AES白盒加密DFA攻击定位示例
// 
// 功能:
//   1. 通过污点分析追踪密钥数据传播
//   2. 通过数据溯源精确定位第10轮密钥操作
//   3. 提供DFA攻击注入点信息
//   4. 生成攻击报告
//

#ifndef ARM64DBIDEMO_AES_DFA_DEMO_H
#define ARM64DBIDEMO_AES_DFA_DEMO_H

#include <cstdint>
#include <vector>
#include <string>

// ==================== DFA攻击点信息 ====================

// 第10轮密钥操作信息
struct Round10KeyOp {
    uint64_t pc;              // 指令地址
    int byte_index;           // 状态字节索引 (0-15)
    uint8_t state_before;     // XOR前的状态值
    uint8_t key_byte;         // 密钥字节值
    uint8_t state_after;      // XOR后的状态值
    std::string instruction;  // 指令文本
    uint64_t timestamp;       // 执行时间戳
};

// DFA攻击报告
struct DFAReport {
    // 基本信息
    uint8_t plaintext[16];
    uint8_t ciphertext[16];
    uint8_t expected_round10_key[16];
    
    // 第10轮操作点
    std::vector<Round10KeyOp> round10_ops;
    
    // 第10轮密钥的内存地址
    uint64_t round10_key_addr;
    
    // SubBytes之后、AddRoundKey之前的状态地址
    uint64_t pre_addroundkey_state_addr;
    
    // DFA注入建议
    std::string injection_advice;
};

// ==================== DFA分析器 ====================

class AESDFADemo {
private:
    // 追踪状态
    static AESDFADemo* instance;
    
    // EOR指令记录
    struct EORRecord {
        uint64_t pc;
        uint64_t timestamp;
        int dst_reg;
        uint64_t dst_val_before;
        uint64_t dst_val_after;
        uint64_t src1_val;
        uint64_t src2_val;
    };
    std::vector<EORRecord> eor_records;
    
    // 内存读取记录 (用于追踪密钥读取)
    struct MemReadRecord {
        uint64_t pc;
        uint64_t timestamp;
        uint64_t addr;
        uint64_t value;
        int dst_reg;
        std::string instruction;
    };
    std::vector<MemReadRecord> mem_reads;
    
    // 当前追踪信息
    uint64_t key_addr_start;
    uint64_t key_addr_end;
    uint64_t round10_key_addr;
    
    // 污点标记的密钥范围
    bool key_region_marked;
    
    AESDFADemo();
    
public:
    AESDFADemo(const AESDFADemo&) = delete;
    AESDFADemo& operator=(const AESDFADemo&) = delete;
    
    static AESDFADemo* getInstance();
    
    // ==================== 配置 ====================
    
    // 设置密钥内存范围 (用于追踪密钥读取)
    void set_key_region(uint64_t start, uint64_t size);
    
    // 设置第10轮密钥地址 (用于验证)
    void set_round10_key_addr(uint64_t addr);
    
    // ==================== 追踪接口 ====================
    
    // 开始DFA分析追踪
    // 返回可调用的函数指针
    void* start_trace(uint64_t encrypt_func_addr);
    
    // 记录回调 (内部使用)
    void record(const CPU_CONTEXT* ctx);
    
    // ==================== 分析接口 ====================
    
    // 分析并定位第10轮密钥操作
    DFAReport analyze();
    
    // 获取第10轮密钥操作列表
    std::vector<Round10KeyOp> get_round10_key_ops();
    
    // 从EOR记录中提取第10轮操作
    // AES-128: 第10轮是最后16个与密钥相关的EOR
    void extract_round10_from_eors();
    
    // ==================== 输出接口 ====================
    
    // 打印分析报告
    void print_report(const DFAReport& report);
    
    // 导出报告到文件
    void export_report(const char* filename, const DFAReport& report);
    
    // 打印DFA攻击指南
    void print_attack_guide();
    
    // ==================== 状态管理 ====================
    
    // 重置分析器
    void reset();
    
    // 获取统计信息
    size_t get_eor_count() const { return eor_records.size(); }
    size_t get_mem_read_count() const { return mem_reads.size(); }
};

// ==================== 污点分析辅助 ====================

// 使用污点分析定位第10轮密钥
// 这是另一种方法：标记密钥为污点源，追踪其传播
class AESTaintAnalysis {
private:
    static AESTaintAnalysis* instance;
    
    // 记录密钥字节与密文的关系
    struct KeyToCipherMap {
        int key_byte_idx;      // 密钥字节索引
        int cipher_byte_idx;   // 影响的密文字节索引
        uint64_t xor_pc;       // XOR操作的PC
    };
    std::vector<KeyToCipherMap> key_cipher_map;
    
    AESTaintAnalysis();
    
public:
    AESTaintAnalysis(const AESTaintAnalysis&) = delete;
    AESTaintAnalysis& operator=(const AESTaintAnalysis&) = delete;
    
    static AESTaintAnalysis* getInstance();
    
    // 设置密钥为污点源并追踪
    void setup_key_taint(uint64_t key_addr, size_t key_size);
    
    // 设置第10轮密钥为污点源
    void setup_round10_key_taint(uint64_t round10_key_addr);
    
    // 开始追踪
    void* start_trace(uint64_t encrypt_func_addr);
    
    // 污点回调
    void on_taint_propagate(const CPU_CONTEXT* ctx, class TaintState* state);
    
    // 分析密钥-密文映射关系
    void analyze_key_cipher_relation();
    
    // 打印映射关系
    void print_key_cipher_map();
    
    // 重置
    void reset();
};

// ==================== 完整DFA攻击演示 ====================

// 运行完整的DFA攻击定位演示
// 包括:
//   1. 使用污点分析追踪密钥传播
//   2. 使用数据溯源定位第10轮操作
//   3. 生成DFA攻击报告
void run_aes_dfa_demo();

// 简化版: 仅使用数据溯源定位第10轮密钥
void run_aes_dfa_simple_demo();

// 带验证的演示: 验证定位结果是否正确
bool run_aes_dfa_verified_demo();

#endif //ARM64DBIDEMO_AES_DFA_DEMO_H

