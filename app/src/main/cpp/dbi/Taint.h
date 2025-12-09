//
// Created for ARM64DBI Taint Analysis Extension
// 污点分析模块 - 头文件
//

#ifndef ARM64DBIDEMO_TAINT_H
#define ARM64DBIDEMO_TAINT_H

#include "../types/types.h"
#include "DBI.h"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <functional>

// ==================== 污点标签定义 ====================

// 污点标签类型（64位，支持多标签合并）
typedef uint64_t TaintTag;

// 预定义污点标签
#define TAINT_NONE      0x0000000000000000ULL  // 无污点
#define TAINT_INPUT     0x0000000000000001ULL  // 输入数据
#define TAINT_KEY       0x0000000000000002ULL  // 密钥数据
#define TAINT_IV        0x0000000000000004ULL  // 初始化向量
#define TAINT_OUTPUT    0x0000000000000008ULL  // 输出数据
#define TAINT_SENSITIVE 0x0000000000000010ULL  // 敏感数据
#define TAINT_USER1     0x0000000000000100ULL  // 用户自定义1
#define TAINT_USER2     0x0000000000000200ULL  // 用户自定义2
#define TAINT_USER3     0x0000000000000400ULL  // 用户自定义3
#define TAINT_USER4     0x0000000000000800ULL  // 用户自定义4

// ==================== 污点传播记录 ====================

// 污点传播事件类型
enum TaintEventType {
    TAINT_EVENT_SOURCE,      // 污点源标记
    TAINT_EVENT_PROPAGATE,   // 污点传播
    TAINT_EVENT_SINK,        // 污点汇聚
    TAINT_EVENT_CLEAR,       // 污点清除
    TAINT_EVENT_MERGE,       // 污点合并
};

// 污点传播记录
struct TaintEvent {
    uint64_t pc;                    // 指令地址
    TaintEventType type;            // 事件类型
    TaintTag old_taint;             // 旧污点值
    TaintTag new_taint;             // 新污点值
    std::string location;           // 位置描述 (如 "X0", "mem:0x12345678")
    std::string instruction;        // 指令文本
    std::string description;        // 事件描述
};

// 污点流记录（用于数据流分析）
struct TaintFlow {
    uint64_t source_pc;             // 源指令地址
    uint64_t dest_pc;               // 目标指令地址
    std::string source_loc;         // 源位置
    std::string dest_loc;           // 目标位置
    TaintTag taint;                 // 传播的污点
};

// ==================== 污点状态管理 ====================

class TaintState {
private:
    // 寄存器污点表 (X0-X30, SP)
    TaintTag reg_taint[32];
    
    // 内存污点表 (按字节粒度)
    std::unordered_map<uint64_t, TaintTag> mem_taint;
    
    // 污点事件记录
    std::vector<TaintEvent> events;
    
    // 污点流记录
    std::vector<TaintFlow> flows;
    
    // 是否启用详细记录
    bool verbose_mode;
    
    // 污点传播统计
    uint64_t propagate_count;
    uint64_t source_count;
    uint64_t sink_count;

public:
    TaintState();
    ~TaintState();
    
    // ========== 寄存器污点操作 ==========
    
    // 设置寄存器污点
    void set_reg_taint(int reg_idx, TaintTag taint);
    
    // 获取寄存器污点
    TaintTag get_reg_taint(int reg_idx);
    
    // 清除寄存器污点
    void clear_reg_taint(int reg_idx);
    
    // 合并寄存器污点 (用于多源操作数)
    TaintTag merge_reg_taint(int reg1, int reg2);
    TaintTag merge_reg_taint(int reg1, int reg2, int reg3);
    
    // ========== 内存污点操作 ==========
    
    // 设置内存区域污点
    void set_mem_taint(uint64_t addr, size_t size, TaintTag taint);
    
    // 获取内存地址污点
    TaintTag get_mem_taint(uint64_t addr);
    
    // 获取内存区域污点 (合并)
    TaintTag get_mem_taint_range(uint64_t addr, size_t size);
    
    // 清除内存区域污点
    void clear_mem_taint(uint64_t addr, size_t size);
    
    // ========== 污点源/汇标记 ==========
    
    // 标记污点源 (寄存器)
    void mark_source_reg(int reg_idx, TaintTag taint, uint64_t pc, const char* desc = nullptr);
    
    // 标记污点源 (内存)
    void mark_source_mem(uint64_t addr, size_t size, TaintTag taint, uint64_t pc, const char* desc = nullptr);
    
    // 标记污点汇 (检查点)
    bool check_sink_reg(int reg_idx, TaintTag expected, uint64_t pc, const char* desc = nullptr);
    bool check_sink_mem(uint64_t addr, size_t size, TaintTag expected, uint64_t pc, const char* desc = nullptr);
    
    // ========== 事件记录 ==========
    
    // 记录污点事件
    void record_event(const TaintEvent& event);
    
    // 记录污点流
    void record_flow(uint64_t src_pc, uint64_t dst_pc, 
                     const std::string& src_loc, const std::string& dst_loc, 
                     TaintTag taint);
    
    // 获取事件记录
    const std::vector<TaintEvent>& get_events() const;
    
    // 获取污点流记录
    const std::vector<TaintFlow>& get_flows() const;
    
    // ========== 状态管理 ==========
    
    // 重置所有状态
    void reset();
    
    // 设置详细模式
    void set_verbose(bool enable);
    
    // 获取统计信息
    void get_stats(uint64_t* propagate, uint64_t* source, uint64_t* sink);
    
    // 打印当前状态
    void dump_state();
    
    // 打印污点流图
    void dump_flow_graph();
};

// ==================== 污点分析引擎 ====================

// 污点分析回调类型
typedef void (*TaintCallback)(const CPU_CONTEXT* ctx, TaintState* state);

// 污点汇回调类型 (当检测到污点到达汇点时调用)
typedef void (*TaintSinkCallback)(uint64_t pc, const std::string& location, TaintTag taint, void* user_data);

class TaintAnalyzer {
private:
    static TaintAnalyzer* instance;
    
    TaintState state;
    
    // 用户自定义回调
    TaintCallback user_callback;
    TaintSinkCallback sink_callback;
    void* sink_user_data;
    
    // 监控的内存区域
    struct WatchRegion {
        uint64_t start;
        uint64_t end;
        TaintTag taint;
        std::string name;
    };
    std::vector<WatchRegion> watch_regions;
    
    // 污点汇点
    struct SinkPoint {
        uint64_t addr;          // 地址 (0 表示任意)
        int reg;                // 寄存器 (-1 表示任意)
        TaintTag expected;      // 期望的污点
        std::string name;
    };
    std::vector<SinkPoint> sink_points;
    
    // 配置选项
    bool track_arithmetic;      // 追踪算术运算
    bool track_logic;           // 追踪逻辑运算
    bool track_memory;          // 追踪内存操作
    bool track_control_flow;    // 追踪控制流
    bool auto_clear_on_const;   // 常量覆盖时自动清除污点
    
    TaintAnalyzer();

public:
    TaintAnalyzer(const TaintAnalyzer&) = delete;
    TaintAnalyzer& operator=(const TaintAnalyzer&) = delete;
    
    static TaintAnalyzer* getInstance();
    
    // ========== 配置接口 ==========
    
    // 设置追踪选项
    void set_track_arithmetic(bool enable);
    void set_track_logic(bool enable);
    void set_track_memory(bool enable);
    void set_track_control_flow(bool enable);
    void set_auto_clear_on_const(bool enable);
    
    // 设置用户回调
    void set_user_callback(TaintCallback callback);
    void set_sink_callback(TaintSinkCallback callback, void* user_data);
    
    // ========== 污点源配置 ==========
    
    // 添加监控内存区域 (自动标记为污点源)
    void add_watch_region(uint64_t start, size_t size, TaintTag taint, const char* name = nullptr);
    
    // 标记函数参数为污点
    void mark_arg_taint(int arg_idx, TaintTag taint);
    
    // 标记寄存器为污点源
    void mark_reg_source(int reg_idx, TaintTag taint);
    
    // 标记内存为污点源
    void mark_mem_source(uint64_t addr, size_t size, TaintTag taint);
    
    // ========== 污点汇配置 ==========
    
    // 添加污点汇点 (监控点)
    void add_sink_point(uint64_t addr, int reg, TaintTag expected, const char* name = nullptr);
    
    // 添加返回值汇点
    void add_return_sink(TaintTag expected, const char* name = nullptr);
    
    // ========== 分析接口 ==========
    
    // 开始污点追踪
    void* trace(uint64_t target_addr);
    
    // 污点传播处理 (内部调用)
    void propagate(const CPU_CONTEXT* ctx);
    
    // 获取污点状态
    TaintState* get_state();
    
    // ========== 结果分析 ==========
    
    // 导出分析报告
    void export_report(const char* filename);
    
    // 打印摘要
    void print_summary();
    
    // 重置分析器
    void reset();
};

// ==================== 辅助函数 ====================

// 获取污点标签名称
const char* taint_tag_name(TaintTag tag);

// 格式化污点标签
std::string format_taint_tag(TaintTag tag);

// 寄存器索引转名称
const char* reg_idx_to_name(int idx);

// 寄存器名称转索引
int reg_name_to_idx(const char* name);

// 从 Capstone 寄存器ID获取索引
int cs_reg_to_idx(unsigned int cs_reg);

#endif //ARM64DBIDEMO_TAINT_H

