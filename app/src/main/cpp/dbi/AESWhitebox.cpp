//
// AESWhitebox.cpp - AES白盒加密实现
//

#include "AESWhitebox.h"
#include "../types/types.h"
#include <cstdio>

// ==================== AES S-Box ====================

const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t AES_INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rcon常量
static const uint8_t RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// ==================== AESWhitebox 实现 ====================

AESWhitebox::AESWhitebox() : round10_key_addr(0) {
    memset(round_keys, 0, sizeof(round_keys));
}

AESWhitebox::~AESWhitebox() {
}

void AESWhitebox::key_expansion(const uint8_t* key) {
    // 复制初始密钥
    memcpy(round_keys[0], key, 16);
    
    // 扩展密钥
    for (int i = 1; i <= 10; i++) {
        uint8_t temp[4];
        
        // 取上一轮密钥的最后4字节
        temp[0] = round_keys[i-1][12];
        temp[1] = round_keys[i-1][13];
        temp[2] = round_keys[i-1][14];
        temp[3] = round_keys[i-1][15];
        
        // RotWord
        uint8_t t = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = t;
        
        // SubWord
        temp[0] = AES_SBOX[temp[0]];
        temp[1] = AES_SBOX[temp[1]];
        temp[2] = AES_SBOX[temp[2]];
        temp[3] = AES_SBOX[temp[3]];
        
        // XOR with Rcon
        temp[0] ^= RCON[i-1];
        
        // 生成新的轮密钥
        for (int j = 0; j < 4; j++) {
            round_keys[i][j*4+0] = round_keys[i-1][j*4+0] ^ temp[0];
            round_keys[i][j*4+1] = round_keys[i-1][j*4+1] ^ temp[1];
            round_keys[i][j*4+2] = round_keys[i-1][j*4+2] ^ temp[2];
            round_keys[i][j*4+3] = round_keys[i-1][j*4+3] ^ temp[3];
            
            temp[0] = round_keys[i][j*4+0];
            temp[1] = round_keys[i][j*4+1];
            temp[2] = round_keys[i][j*4+2];
            temp[3] = round_keys[i][j*4+3];
        }
    }
    
    // 记录第10轮密钥地址
    round10_key_addr = (uint64_t)&round_keys[10][0];
}

void AESWhitebox::set_key(const uint8_t* key) {
    key_expansion(key);
}

// SubBytes - S盒替换
__attribute__((noinline))
void AESWhitebox::sub_bytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = AES_SBOX[state[i]];
    }
}

// ShiftRows - 行移位
__attribute__((noinline))
void AESWhitebox::shift_rows(uint8_t* state) {
    uint8_t temp;
    
    // 第1行: 左移1位
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // 第2行: 左移2位
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // 第3行: 左移3位
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

// GF(2^8) 乘法
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a = (a << 1) ^ ((a & 0x80) ? 0x1b : 0);
        b >>= 1;
    }
    return result;
}

// MixColumns - 列混合
__attribute__((noinline))
void AESWhitebox::mix_columns(uint8_t* state) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[c*4+0];
        uint8_t s1 = state[c*4+1];
        uint8_t s2 = state[c*4+2];
        uint8_t s3 = state[c*4+3];
        
        state[c*4+0] = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2 ^ s3;
        state[c*4+1] = s0 ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3;
        state[c*4+2] = s0 ^ s1 ^ gf_mul(s2, 2) ^ gf_mul(s3, 3);
        state[c*4+3] = gf_mul(s0, 3) ^ s1 ^ s2 ^ gf_mul(s3, 2);
    }
}

// AddRoundKey - 轮密钥加
// 这是DFA攻击的关键点！
__attribute__((noinline))
void AESWhitebox::add_round_key(uint8_t* state, int round) {
    // 标记: 第10轮密钥加是DFA攻击的目标
    // 在这里，state[i] ^= round_keys[round][i]
    // 如果是第10轮 (round == 10)，这里使用的就是最后一轮密钥
    
    for (int i = 0; i < 16; i++) {
        // 这个XOR操作是追踪的关键！
        // DFA攻击需要在这里注入故障
        state[i] ^= round_keys[round][i];
    }
}

// 加密单个块
// 注意：不使用 memcpy 以避免追踪外部库函数
__attribute__((noinline))
void AESWhitebox::encrypt_block(const uint8_t* input, uint8_t* output) {
    uint8_t state[16];
    
    // 内联复制输入（替代 memcpy）
    for (int i = 0; i < 16; i++) {
        state[i] = input[i];
    }
    
    // 初始轮密钥加
    add_round_key(state, 0);
    
    // 前9轮 (完整轮)
    for (int round = 1; round <= 9; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round);
    }
    
    // 第10轮 (最后一轮，无MixColumns)
    // 这是DFA攻击的关键位置！
    sub_bytes(state);       // SubBytes
    shift_rows(state);      // ShiftRows
    add_round_key(state, 10);  // ★★★ 第10轮密钥加 - DFA目标 ★★★
    
    // 内联复制输出（替代 memcpy）
    for (int i = 0; i < 16; i++) {
        output[i] = state[i];
    }
}

void AESWhitebox::get_round10_key(uint8_t* key_out) const {
    for (int i = 0; i < 16; i++) {
        key_out[i] = round_keys[10][i];
    }
}

void AESWhitebox::print_round_keys() const {
    LOGI("========== AES Round Keys ==========");
    for (int r = 0; r <= 10; r++) {
        LOGI("Round %2d: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
             r,
             round_keys[r][0], round_keys[r][1], round_keys[r][2], round_keys[r][3],
             round_keys[r][4], round_keys[r][5], round_keys[r][6], round_keys[r][7],
             round_keys[r][8], round_keys[r][9], round_keys[r][10], round_keys[r][11],
             round_keys[r][12], round_keys[r][13], round_keys[r][14], round_keys[r][15]);
    }
    LOGI("=====================================");
}

// ==================== DFAAnalyzer 实现 ====================

DFAAnalyzer::DFAAnalyzer() : recovered_bytes(0) {
    memset(recovered_key, 0, sizeof(recovered_key));
}

void DFAAnalyzer::record_point(uint64_t pc, int round, int byte_idx, uint64_t value, const char* insn) {
    DFAPoint point;
    point.pc = pc;
    point.round = round;
    point.byte_index = byte_idx;
    point.value = value;
    point.instruction = insn ? insn : "";
    attack_points.push_back(point);
}

void DFAAnalyzer::analyze_round10() {
    LOGI("========== DFA Analysis: Round 10 ==========");
    
    // 找到第10轮的所有EOR操作
    for (const auto& point : attack_points) {
        if (point.round == 10) {
            LOGI("Round 10 byte[%d]: value=0x%02X at PC=0x%llx (%s)",
                 point.byte_index,
                 (uint8_t)point.value,
                 (unsigned long long)point.pc,
                 point.instruction.c_str());
            
            // 记录恢复的密钥字节
            if (point.byte_index >= 0 && point.byte_index < 16) {
                recovered_key[point.byte_index] = (uint8_t)point.value;
                recovered_bytes++;
            }
        }
    }
    
    LOGI("==============================================");
}

bool DFAAnalyzer::get_recovered_key(uint8_t* key_out) const {
    if (recovered_bytes < 16) return false;
    memcpy(key_out, recovered_key, 16);
    return true;
}

void DFAAnalyzer::print_results() const {
    LOGI("========== DFA Recovery Results ==========");
    LOGI("Recovered %d/16 key bytes", recovered_bytes);
    
    if (recovered_bytes > 0) {
        LOGI("Partial key: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
             recovered_key[0], recovered_key[1], recovered_key[2], recovered_key[3],
             recovered_key[4], recovered_key[5], recovered_key[6], recovered_key[7],
             recovered_key[8], recovered_key[9], recovered_key[10], recovered_key[11],
             recovered_key[12], recovered_key[13], recovered_key[14], recovered_key[15]);
    }
    
    LOGI("==========================================");
}

