//
// AESWhitebox.h - AES白盒加密示例
// 
// 用于演示如何使用数据溯源定位AES第10轮密钥
// 这对于DFA（差分故障分析）攻击非常重要
//

#ifndef ARM64DBIDEMO_AESWHITEBOX_H
#define ARM64DBIDEMO_AESWHITEBOX_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// AES常量
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16
#define AES_ROUNDS 10

// ==================== AES S-Box ====================
extern const uint8_t AES_SBOX[256];
extern const uint8_t AES_INV_SBOX[256];

// ==================== AES实现 ====================

class AESWhitebox {
private:
    // 轮密钥 (每轮16字节，共11轮)
    uint8_t round_keys[11][16];
    
    // 记录第10轮密钥位置 (用于验证溯源结果)
    uint64_t round10_key_addr;
    
    // 密钥扩展
    void key_expansion(const uint8_t* key);
    
    // AES轮函数
    void sub_bytes(uint8_t* state);
    void shift_rows(uint8_t* state);
    void mix_columns(uint8_t* state);
    void add_round_key(uint8_t* state, int round);
    
public:
    AESWhitebox();
    ~AESWhitebox();
    
    // 设置密钥
    void set_key(const uint8_t* key);
    
    // 加密单个块 (16字节)
    void encrypt_block(const uint8_t* input, uint8_t* output);
    
    // 获取第10轮密钥地址 (用于验证)
    uint64_t get_round10_key_addr() const { return round10_key_addr; }
    
    // 获取第10轮密钥 (用于验证DFA攻击结果)
    void get_round10_key(uint8_t* key_out) const;
    
    // 打印轮密钥 (调试用)
    void print_round_keys() const;
};

// ==================== DFA攻击辅助 ====================

// DFA攻击点结构
struct DFAPoint {
    uint64_t pc;                // 指令地址
    int round;                  // 轮次
    int byte_index;             // 字节索引 (0-15)
    uint64_t value;             // 值
    std::string instruction;    // 指令
};

// DFA分析器
class DFAAnalyzer {
private:
    std::vector<DFAPoint> attack_points;
    uint8_t recovered_key[16];
    int recovered_bytes;
    
public:
    DFAAnalyzer();
    
    // 记录攻击点
    void record_point(uint64_t pc, int round, int byte_idx, uint64_t value, const char* insn);
    
    // 分析第10轮密钥
    void analyze_round10();
    
    // 获取恢复的密钥
    bool get_recovered_key(uint8_t* key_out) const;
    
    // 打印分析结果
    void print_results() const;
};

#endif //ARM64DBIDEMO_AESWHITEBOX_H

