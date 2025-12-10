//
// DataTracer.h - 数据溯源模块
// 
// 功能: 追踪寄存器值的来源，支持反向数据流分析
// 使用场景:
//   - 追踪某个特定值是如何计算出来的
//   - 分析加密算法中的数据变换过程
//   - 定位关键数据的产生位置
//

#ifndef ARM64DBIDEMO_DATATRACER_H
#define ARM64DBIDEMO_DATATRACER_H

#include "../types/types.h"
#include "DBI.h"
#include <vector>
#include <unordered_map>
#include <string>
#include <functional>

// ==================== 数据来源类型 ====================

enum DataSourceType {
    SOURCE_UNKNOWN,         // 未知来源
    SOURCE_IMMEDIATE,       // 立即数 (MOV X0, #0x123)
    SOURCE_REGISTER,        // 寄存器传递 (MOV X0, X1)
    SOURCE_MEMORY,          // 内存加载 (LDR X0, [X1])
    SOURCE_ARITHMETIC,      // 算术运算 (ADD X0, X1, X2)
    SOURCE_LOGIC,           // 逻辑运算 (EOR X0, X1, X2)
    SOURCE_SHIFT,           // 移位运算 (LSL X0, X1, #3)
    SOURCE_FUNCTION_RETURN, // 函数返回值
    SOURCE_FUNCTION_ARG,    // 函数参数
};

// ==================== 指令执行记录 ====================

struct InstructionRecord {
    uint64_t pc;                    // 指令地址
    uint64_t timestamp;             // 执行时间戳 (序号)
    std::string mnemonic;           // 指令助记符
    std::string op_str;             // 操作数字符串
    
    // 执行前的寄存器状态
    uint64_t regs_before[32];       // X0-X30, SP
    
    // 执行后的寄存器状态 (下一条指令的before)
    uint64_t regs_after[32];
    
    // 内存访问信息
    bool is_memory_read;
    bool is_memory_write;
    uint64_t memory_addr;
    uint64_t memory_value;
    size_t memory_size;
};

// ==================== 数据来源信息 ====================

struct DataSource {
    DataSourceType type;            // 来源类型
    uint64_t pc;                    // 产生该值的指令地址
    uint64_t timestamp;             // 时间戳
    std::string instruction;        // 指令文本
    
    // 详细信息
    uint64_t value;                 // 值
    int target_reg;                 // 目标寄存器
    
    // 源操作数
    std::vector<int> source_regs;   // 源寄存器列表
    uint64_t immediate;             // 立即数值
    uint64_t memory_addr;           // 内存地址
    
    // 递归来源 (用于完整追溯)
    std::vector<DataSource> parents;
};

// ==================== 值监控点 ====================

struct ValueWatch {
    int reg;                        // 监控的寄存器 (-1 表示任意)
    uint64_t value;                 // 监控的值
    uint64_t mask;                  // 掩码 (0xFFFFFFFFFFFFFFFF 表示精确匹配)
    std::string name;               // 监控点名称
    bool triggered;                 // 是否已触发
    uint64_t trigger_pc;            // 触发时的 PC
    uint64_t trigger_timestamp;     // 触发时的时间戳
};

// ==================== 数据追踪器 ====================

// 追踪回调类型
typedef void (*DataSourceCallback)(const DataSource& source, void* user_data);

class DataTracer {
private:
    static DataTracer* instance;
    
    // 执行历史记录
    std::vector<InstructionRecord> history;
    uint64_t current_timestamp;
    
    // 上一条指令的寄存器状态 (用于计算 regs_after)
    uint64_t last_regs[32];
    bool has_last_regs;
    
    // 值监控列表
    std::vector<ValueWatch> watches;
    
    // 回调函数
    DataSourceCallback source_callback;
    void* callback_user_data;
    
    // 配置
    size_t max_history_size;        // 最大历史记录数
    int max_trace_depth;            // 最大追溯深度
    bool auto_trace_on_watch;       // 监控点触发时自动追溯
    
    DataTracer();
    
    // 内部方法
    void update_regs_after(const CPU_CONTEXT* ctx);
    DataSourceType classify_instruction(cs_insn* insn);
    void extract_operands(cs_insn* insn, DataSource& source);
    
public:
    DataTracer(const DataTracer&) = delete;
    DataTracer& operator=(const DataTracer&) = delete;
    
    static DataTracer* getInstance();
    
    // ==================== 配置 ====================
    
    // 设置最大历史记录数 (默认 100000)
    void set_max_history(size_t max_size);
    
    // 设置最大追溯深度 (默认 50)
    void set_max_trace_depth(int depth);
    
    // 设置追溯回调
    void set_source_callback(DataSourceCallback callback, void* user_data);
    
    // ==================== 值监控 ====================
    
    // 添加值监控点
    // reg: 寄存器索引 (0-30, 31=SP, -1=任意寄存器)
    // value: 要监控的值
    // mask: 掩码，用于部分匹配 (如只匹配低8位: mask=0xFF)
    void add_watch(int reg, uint64_t value, uint64_t mask = 0xFFFFFFFFFFFFFFFF, 
                   const char* name = nullptr);
    
    // 移除监控点
    void remove_watch(int reg, uint64_t value);
    
    // 清除所有监控点
    void clear_watches();
    
    // ==================== 追踪控制 ====================
    
    // 开始追踪
    void* trace(uint64_t target_addr);
    
    // 记录指令执行 (内部调用)
    void record(const CPU_CONTEXT* ctx);
    
    // ==================== 数据溯源 ====================
    
    // 追溯寄存器值的来源
    // reg: 寄存器索引
    // value: 要追溯的值 (如果为0，则追溯当前值)
    // from_timestamp: 从哪个时间点开始回溯 (0=最新)
    DataSource trace_register(int reg, uint64_t value = 0, uint64_t from_timestamp = 0);
    
    // 追溯内存值的来源
    DataSource trace_memory(uint64_t addr, size_t size, uint64_t from_timestamp = 0);
    
    // 获取完整的数据流链
    std::vector<DataSource> get_full_trace(int reg, uint64_t value, int max_depth);
    
    // ==================== 查询 ====================
    
    // 查找产生特定值的所有指令
    std::vector<InstructionRecord> find_value_producers(uint64_t value, int reg = -1);
    
    // 查找特定寄存器的所有修改记录
    std::vector<InstructionRecord> find_reg_modifications(int reg);
    
    // 获取指定时间点的寄存器状态
    bool get_regs_at(uint64_t timestamp, uint64_t* regs_out);
    
    // 获取执行历史
    const std::vector<InstructionRecord>& get_history() const;
    
    // ==================== 输出 ====================
    
    // 打印数据来源
    void print_source(const DataSource& source, int indent = 0);
    
    // 打印完整追溯链
    void print_trace_chain(const std::vector<DataSource>& chain);
    
    // 导出追溯报告
    void export_trace_report(const char* filename, const DataSource& source);
    
    // ==================== 状态管理 ====================
    
    // 重置追踪器
    void reset();
    
    // 获取统计信息
    void get_stats(size_t* history_size, size_t* watch_count, uint64_t* timestamp);
};

// ==================== 辅助函数 ====================

// 数据来源类型转字符串
const char* source_type_name(DataSourceType type);

// 格式化数据来源信息
std::string format_data_source(const DataSource& source);

#endif //ARM64DBIDEMO_DATATRACER_H

