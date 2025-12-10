//
// TraceFile.h - Trace 文件生成模块
// 
// 功能: 
//   1. 指定 SO 文件和起始地址进行 trace
//   2. 生成标准格式的 trace 文件（兼容 IDA/Ghidra/unidbg）
//   3. 支持离线分析和算法还原
//
// 使用场景:
//   - 加密算法还原
//   - 协议分析
//   - 逆向工程
//

#ifndef ARM64DBIDEMO_TRACEFILE_H
#define ARM64DBIDEMO_TRACEFILE_H

#include "../types/types.h"
#include "DBI.h"
#include "DataTracer.h"
#include <string>
#include <vector>
#include <fstream>
#include <unordered_map>

// ==================== Trace 记录格式 ====================

// 单条 trace 记录
struct TraceRecord {
    uint64_t index;             // 序号
    uint64_t pc;                // 指令地址
    uint64_t offset;            // 相对于 SO 基址的偏移
    std::string mnemonic;       // 助记符
    std::string operands;       // 操作数
    uint32_t opcode;            // 机器码
    
    // 寄存器状态
    uint64_t regs[32];          // X0-X30, SP
    
    // 内存访问
    bool has_mem_access;
    bool is_mem_read;
    uint64_t mem_addr;
    uint64_t mem_value;
    size_t mem_size;
};

// SO 模块信息
struct ModuleInfo {
    std::string name;           // 模块名 (如 "libnative.so")
    uint64_t base;              // 加载基址
    uint64_t size;              // 模块大小
    std::string path;           // 完整路径
};

// Trace 配置
struct TraceConfig {
    // 地址范围
    uint64_t start_addr;        // 起始地址 (0 = 自动)
    uint64_t end_addr;          // 结束地址 (0 = 无限制)
    
    // 模块过滤
    std::string target_module;  // 目标模块名 (为空则不过滤)
    bool trace_all_modules;     // 是否追踪所有模块
    
    // 记录选项
    bool record_regs;           // 记录寄存器
    bool record_memory;         // 记录内存访问
    bool record_opcodes;        // 记录机器码
    
    // 输出选项
    std::string output_path;    // 输出文件路径
    bool output_text;           // 输出文本格式
    bool output_json;           // 输出 JSON 格式
    bool output_binary;         // 输出二进制格式
    
    // 限制
    size_t max_records;         // 最大记录数 (0 = 无限制)
    
    TraceConfig() : 
        start_addr(0), end_addr(0),
        trace_all_modules(false),
        record_regs(true), record_memory(true), record_opcodes(true),
        output_text(true), output_json(false), output_binary(false),
        max_records(0) {}
};

// ==================== Trace 文件生成器 ====================

class TraceFile {
private:
    static TraceFile* instance;
    
    // 配置
    TraceConfig config;
    
    // 模块信息
    std::vector<ModuleInfo> modules;
    std::unordered_map<std::string, ModuleInfo*> module_map;
    
    // Trace 记录
    std::vector<TraceRecord> records;
    uint64_t record_count;
    
    // 文件句柄
    std::ofstream text_file;
    std::ofstream json_file;
    std::ofstream bin_file;
    
    // 状态
    bool is_tracing;
    uint64_t trace_start_time;
    
    TraceFile();
    
    // 内部方法
    void write_text_record(const TraceRecord& rec);
    void write_json_record(const TraceRecord& rec, bool is_last);
    void write_binary_record(const TraceRecord& rec);
    ModuleInfo* find_module(uint64_t addr);
    
public:
    TraceFile(const TraceFile&) = delete;
    TraceFile& operator=(const TraceFile&) = delete;
    
    static TraceFile* getInstance();
    
    // ==================== 模块管理 ====================
    
    // 扫描已加载的模块
    void scan_modules();
    
    // 手动添加模块
    void add_module(const char* name, uint64_t base, uint64_t size, const char* path = nullptr);
    
    // 通过名称查找模块
    ModuleInfo* get_module(const char* name);
    
    // 获取所有模块
    const std::vector<ModuleInfo>& get_modules() const;
    
    // 打印模块列表
    void print_modules();
    
    // ==================== 配置 ====================
    
    // 设置配置
    void set_config(const TraceConfig& cfg);
    
    // 获取配置
    TraceConfig& get_config();
    
    // 设置目标模块
    void set_target_module(const char* module_name);
    
    // 设置地址范围
    void set_address_range(uint64_t start, uint64_t end);
    
    // 设置输出路径
    void set_output_path(const char* path);
    
    // ==================== Trace 控制 ====================
    
    // 开始 trace (指定函数地址)
    void* start_trace(uint64_t func_addr);
    
    // 开始 trace (指定模块和偏移)
    void* start_trace(const char* module_name, uint64_t offset);
    
    // 停止 trace
    void stop_trace();
    
    // 记录指令 (内部调用)
    void record_instruction(const CPU_CONTEXT* ctx);
    
    // ==================== 结果分析 ====================
    
    // 获取所有记录
    const std::vector<TraceRecord>& get_records() const;
    
    // 查找特定指令
    std::vector<TraceRecord> find_instructions(const char* mnemonic);
    
    // 查找内存访问
    std::vector<TraceRecord> find_memory_access(uint64_t addr, bool read = true, bool write = true);
    
    // 查找寄存器值
    std::vector<TraceRecord> find_register_value(int reg, uint64_t value);
    
    // ==================== 文件输出 ====================
    
    // 保存 trace 文件
    void save();
    
    // 导出为 unidbg 格式
    void export_unidbg_format(const char* filename);
    
    // 导出为 IDA trace 格式
    void export_ida_format(const char* filename);
    
    // 导出摘要报告
    void export_summary(const char* filename);
    
    // ==================== 状态 ====================
    
    // 获取统计
    void get_stats(size_t* total_records, size_t* module_count);
    
    // 重置
    void reset();
};

// ==================== 便捷函数 ====================

// 快速 trace 函数
// 返回翻译后的函数指针，trace 结果保存到文件
void* quick_trace(uint64_t func_addr, const char* output_file);

// 通过模块名和偏移 trace
void* quick_trace_module(const char* module_name, uint64_t offset, const char* output_file);

// 查找模块基址
uint64_t find_module_base(const char* module_name);

// 计算模块内偏移
uint64_t get_module_offset(const char* module_name, uint64_t addr);

#endif //ARM64DBIDEMO_TRACEFILE_H

