//
// DataTracer.cpp - 数据溯源模块实现
//

#include "DataTracer.h"
#include "DBI.h"
#include "Taint.h"  // for reg_idx_to_name, cs_reg_to_idx
#include <cstring>
#include <algorithm>
#include <sstream>

// ==================== 辅助函数 ====================

const char* source_type_name(DataSourceType type) {
    switch (type) {
        case SOURCE_UNKNOWN: return "UNKNOWN";
        case SOURCE_IMMEDIATE: return "IMMEDIATE";
        case SOURCE_REGISTER: return "REGISTER";
        case SOURCE_MEMORY: return "MEMORY";
        case SOURCE_ARITHMETIC: return "ARITHMETIC";
        case SOURCE_LOGIC: return "LOGIC";
        case SOURCE_SHIFT: return "SHIFT";
        case SOURCE_FUNCTION_RETURN: return "FUNC_RET";
        case SOURCE_FUNCTION_ARG: return "FUNC_ARG";
        default: return "UNKNOWN";
    }
}

std::string format_data_source(const DataSource& source) {
    std::stringstream ss;
    ss << "[" << source_type_name(source.type) << "] ";
    ss << "PC=0x" << std::hex << source.pc << " ";
    ss << source.instruction;
    
    if (source.type == SOURCE_IMMEDIATE) {
        ss << " (imm=0x" << std::hex << source.immediate << ")";
    } else if (source.type == SOURCE_MEMORY) {
        ss << " (addr=0x" << std::hex << source.memory_addr << ")";
    }
    
    return ss.str();
}

// ==================== DataTracer 实现 ====================

DataTracer* DataTracer::instance = nullptr;

DataTracer::DataTracer() 
    : current_timestamp(0), has_last_regs(false),
      source_callback(nullptr), callback_user_data(nullptr),
      max_history_size(100000), max_trace_depth(50),
      auto_trace_on_watch(true) {
    memset(last_regs, 0, sizeof(last_regs));
}

DataTracer* DataTracer::getInstance() {
    if (!instance) {
        instance = new DataTracer();
    }
    return instance;
}

void DataTracer::set_max_history(size_t max_size) {
    max_history_size = max_size;
}

void DataTracer::set_max_trace_depth(int depth) {
    max_trace_depth = depth;
}

void DataTracer::set_source_callback(DataSourceCallback callback, void* user_data) {
    source_callback = callback;
    callback_user_data = user_data;
}

void DataTracer::add_watch(int reg, uint64_t value, uint64_t mask, const char* name) {
    ValueWatch watch;
    watch.reg = reg;
    watch.value = value;
    watch.mask = mask;
    watch.name = name ? name : "";
    watch.trigger_on_nth = 0;  // 每次都触发
    watch.current_count = 0;
    watch.pc_start = 0;
    watch.pc_end = 0;
    watch.triggered = false;
    watch.one_shot = false;
    watch.trigger_pc = 0;
    watch.trigger_timestamp = 0;
    watches.push_back(watch);
    
    LOGI("[DataTracer] Added watch: reg=%s, value=0x%llx, mask=0x%llx, name=%s",
         reg >= 0 ? reg_idx_to_name(reg) : "ANY",
         (unsigned long long)value,
         (unsigned long long)mask,
         name ? name : "(unnamed)");
}

void DataTracer::add_watch_advanced(const ValueWatch& watch) {
    watches.push_back(watch);
    LOGI("[DataTracer] Added advanced watch: %s", watch.name.c_str());
}

void DataTracer::add_watch_with_condition(int reg, uint64_t value,
                                          const std::vector<WatchCondition>& extra_conds,
                                          const char* name) {
    ValueWatch watch;
    watch.reg = reg;
    watch.value = value;
    watch.mask = 0xFFFFFFFFFFFFFFFF;
    watch.name = name ? name : "";
    watch.extra_conditions = extra_conds;
    watch.trigger_on_nth = 0;
    watch.current_count = 0;
    watches.push_back(watch);
    
    LOGI("[DataTracer] Added conditional watch: %s=%s with %zu extra conditions",
         reg >= 0 ? reg_idx_to_name(reg) : "ANY",
         name ? name : "(unnamed)",
         extra_conds.size());
}

void DataTracer::add_watch_nth(int reg, uint64_t value, int nth, const char* name) {
    ValueWatch watch;
    watch.reg = reg;
    watch.value = value;
    watch.mask = 0xFFFFFFFFFFFFFFFF;
    watch.name = name ? name : "";
    watch.trigger_on_nth = nth;
    watch.current_count = 0;
    watch.one_shot = true;  // 第N次触发后停止
    watches.push_back(watch);
    
    LOGI("[DataTracer] Added nth-trigger watch: %s=0x%llx on %d-th occurrence",
         reg >= 0 ? reg_idx_to_name(reg) : "ANY",
         (unsigned long long)value,
         nth);
}

void DataTracer::add_watch_in_range(int reg, uint64_t value,
                                     uint64_t pc_start, uint64_t pc_end,
                                     const char* name) {
    ValueWatch watch;
    watch.reg = reg;
    watch.value = value;
    watch.mask = 0xFFFFFFFFFFFFFFFF;
    watch.name = name ? name : "";
    watch.pc_start = pc_start;
    watch.pc_end = pc_end;
    watches.push_back(watch);
    
    LOGI("[DataTracer] Added range-limited watch: %s=0x%llx in [0x%llx-0x%llx]",
         reg >= 0 ? reg_idx_to_name(reg) : "ANY",
         (unsigned long long)value,
         (unsigned long long)pc_start,
         (unsigned long long)pc_end);
}

void DataTracer::add_watch_after_insn(int reg, uint64_t value,
                                       const char* mnemonic,
                                       const char* name) {
    ValueWatch watch;
    watch.reg = reg;
    watch.value = value;
    watch.mask = 0xFFFFFFFFFFFFFFFF;
    watch.name = name ? name : "";
    watch.mnemonic_filter = mnemonic;
    watches.push_back(watch);
    
    LOGI("[DataTracer] Added instruction-filtered watch: %s=0x%llx after '%s'",
         reg >= 0 ? reg_idx_to_name(reg) : "ANY",
         (unsigned long long)value,
         mnemonic);
}

void DataTracer::remove_watch(int reg, uint64_t value) {
    watches.erase(
        std::remove_if(watches.begin(), watches.end(),
            [reg, value](const ValueWatch& w) {
                return w.reg == reg && w.value == value;
            }),
        watches.end()
    );
}

void DataTracer::clear_watches() {
    watches.clear();
}

// 内部回调函数
static void data_tracer_callback(const CPU_CONTEXT* ctx) {
    DataTracer::getInstance()->record(ctx);
}

void* DataTracer::trace(uint64_t target_addr) {
    LOGI("[DataTracer] Starting trace at 0x%llx", (unsigned long long)target_addr);
    reset();
    return DBI::trace(target_addr, data_tracer_callback);
}

void DataTracer::update_regs_after(const CPU_CONTEXT* ctx) {
    if (has_last_regs && !history.empty()) {
        // 用当前的 before 作为上一条的 after
        auto& last = history.back();
        for (int i = 0; i < 29; i++) {
            last.regs_after[i] = ctx->x[i];
        }
        last.regs_after[29] = ctx->fp;
        last.regs_after[30] = ctx->lr;
        last.regs_after[31] = ctx->sp;
    }
}

DataSourceType DataTracer::classify_instruction(cs_insn* insn) {
    switch (insn->id) {
        // 立即数加载
        case AARCH64_INS_MOVZ:
        case AARCH64_INS_MOVN:
            return SOURCE_IMMEDIATE;
            
        // 寄存器移动
        case AARCH64_INS_MOV:
            // 需要检查是否是立即数
            if (insn->detail && insn->detail->aarch64.op_count >= 2) {
                if (insn->detail->aarch64.operands[1].type == AARCH64_OP_IMM) {
                    return SOURCE_IMMEDIATE;
                }
            }
            return SOURCE_REGISTER;
            
        // 内存加载
        case AARCH64_INS_LDR:
        case AARCH64_INS_LDRB:
        case AARCH64_INS_LDRH:
        case AARCH64_INS_LDRSB:
        case AARCH64_INS_LDRSH:
        case AARCH64_INS_LDRSW:
        case AARCH64_INS_LDUR:
        case AARCH64_INS_LDP:
            return SOURCE_MEMORY;
            
        // 算术运算
        case AARCH64_INS_ADD:
        case AARCH64_INS_SUB:
        case AARCH64_INS_MUL:
        case AARCH64_INS_SDIV:
        case AARCH64_INS_UDIV:
        case AARCH64_INS_MADD:
        case AARCH64_INS_MSUB:
            return SOURCE_ARITHMETIC;
            
        // 逻辑运算
        case AARCH64_INS_AND:
        case AARCH64_INS_ORR:
        case AARCH64_INS_EOR:
        case AARCH64_INS_BIC:
        case AARCH64_INS_ORN:
        case AARCH64_INS_EON:
            return SOURCE_LOGIC;
            
        // 移位运算
        case AARCH64_INS_LSL:
        case AARCH64_INS_LSR:
        case AARCH64_INS_ASR:
        case AARCH64_INS_ROR:
            return SOURCE_SHIFT;
            
        // 函数调用后的返回值
        case AARCH64_INS_BL:
        case AARCH64_INS_BLR:
            return SOURCE_FUNCTION_RETURN;
            
        default:
            return SOURCE_UNKNOWN;
    }
}

void DataTracer::extract_operands(cs_insn* insn, DataSource& source) {
    if (!insn->detail) return;
    
    cs_aarch64* aarch64 = &insn->detail->aarch64;
    
    for (int i = 0; i < aarch64->op_count; i++) {
        cs_aarch64_op* op = &aarch64->operands[i];
        
        if (i == 0 && op->type == AARCH64_OP_REG) {
            // 第一个寄存器通常是目标
            source.target_reg = cs_reg_to_idx(op->reg);
        } else if (op->type == AARCH64_OP_REG) {
            // 其他寄存器是源
            source.source_regs.push_back(cs_reg_to_idx(op->reg));
        } else if (op->type == AARCH64_OP_IMM) {
            source.immediate = op->imm;
        } else if (op->type == AARCH64_OP_MEM) {
            // 内存操作，需要从历史记录中获取实际地址
            source.memory_addr = 0;  // 后续填充
        }
    }
}

void DataTracer::record(const CPU_CONTEXT* ctx) {
    // 先更新上一条指令的 after 状态
    update_regs_after(ctx);
    
    // 反汇编当前指令
    auto insn = DBI::disassemble(ctx->pc);
    if (!insn) return;
    
    // 创建执行记录
    InstructionRecord record;
    record.pc = ctx->pc;
    record.timestamp = current_timestamp++;
    record.mnemonic = insn->mnemonic;
    record.op_str = insn->op_str;
    
    // 保存执行前的寄存器状态
    for (int i = 0; i < 29; i++) {
        record.regs_before[i] = ctx->x[i];
    }
    record.regs_before[29] = ctx->fp;
    record.regs_before[30] = ctx->lr;
    record.regs_before[31] = ctx->sp;
    
    // 内存访问检测
    record.is_memory_read = false;
    record.is_memory_write = false;
    record.memory_addr = 0;
    record.memory_value = 0;
    record.memory_size = 0;
    
    if (insn->detail) {
        cs_aarch64* aarch64 = &insn->detail->aarch64;
        for (int i = 0; i < aarch64->op_count; i++) {
            cs_aarch64_op* op = &aarch64->operands[i];
            if (op->type == AARCH64_OP_MEM) {
                // 计算内存地址
                int base_idx = cs_reg_to_idx(op->mem.base);
                if (base_idx >= 0) {
                    record.memory_addr = record.regs_before[base_idx] + op->mem.disp;
                    
                    // 判断是读还是写
                    if (insn->id >= AARCH64_INS_LDR && insn->id <= AARCH64_INS_LDURSW) {
                        record.is_memory_read = true;
                    } else if (insn->id >= AARCH64_INS_STR && insn->id <= AARCH64_INS_STURH) {
                        record.is_memory_write = true;
                    }
                }
            }
        }
    }
    
    // 保存到历史
    history.push_back(record);
    
    // 限制历史大小
    if (history.size() > max_history_size) {
        history.erase(history.begin(), history.begin() + (history.size() - max_history_size));
    }
    
    // 更新 last_regs
    memcpy(last_regs, record.regs_before, sizeof(last_regs));
    has_last_regs = true;
    
    // 检查值监控点
    std::vector<size_t> to_remove;  // 需要移除的一次性监控
    
    for (size_t wi = 0; wi < watches.size(); wi++) {
        auto& watch = watches[wi];
        if (watch.triggered && watch.one_shot) continue;
        
        // ===== 检查主条件 =====
        bool main_match = false;
        int matched_reg = -1;
        
        if (watch.reg >= 0) {
            uint64_t reg_val = record.regs_before[watch.reg];
            if ((reg_val & watch.mask) == (watch.value & watch.mask)) {
                main_match = true;
                matched_reg = watch.reg;
            }
        } else {
            for (int i = 0; i < 32; i++) {
                uint64_t reg_val = record.regs_before[i];
                if ((reg_val & watch.mask) == (watch.value & watch.mask)) {
                    main_match = true;
                    matched_reg = i;
                    break;
                }
            }
        }
        
        if (!main_match) continue;
        
        // ===== 检查额外条件 (AND 关系) =====
        bool extra_match = true;
        for (const auto& cond : watch.extra_conditions) {
            if (cond.reg >= 0 && cond.reg < 32) {
                uint64_t reg_val = record.regs_before[cond.reg];
                if ((reg_val & cond.mask) != (cond.value & cond.mask)) {
                    extra_match = false;
                    break;
                }
            }
        }
        if (!extra_match) continue;
        
        // ===== 检查地址范围 =====
        if (watch.pc_start > 0 || watch.pc_end > 0) {
            if (ctx->pc < watch.pc_start || ctx->pc >= watch.pc_end) {
                continue;
            }
        }
        
        // ===== 检查指令过滤 =====
        if (!watch.mnemonic_filter.empty()) {
            if (watch.mnemonic_filter != insn->mnemonic) {
                continue;
            }
        }
        
        // ===== 检查第N次触发 =====
        watch.current_count++;
        if (watch.trigger_on_nth > 0 && watch.current_count != watch.trigger_on_nth) {
            continue;  // 不是第N次，跳过
        }
        
        // ===== 所有条件满足，触发! =====
        watch.triggered = true;
        watch.trigger_pc = ctx->pc;
        watch.trigger_timestamp = record.timestamp;
        
        LOGI("========== VALUE WATCH TRIGGERED ==========");
        LOGI("Watch: %s", watch.name.c_str());
        LOGI("PC: 0x%llx", (unsigned long long)ctx->pc);
        LOGI("Occurrence: #%d", watch.current_count);
        LOGI("Register: %s = 0x%llx", 
             reg_idx_to_name(matched_reg),
             (unsigned long long)record.regs_before[matched_reg]);
        LOGI("Instruction: %s %s", insn->mnemonic, insn->op_str);
        
        // 打印上下文 (前后5条指令)
        LOGI("--- Context (nearby instructions) ---");
        size_t start_idx = history.size() > 5 ? history.size() - 5 : 0;
        for (size_t i = start_idx; i < history.size(); i++) {
            const auto& h = history[i];
            LOGI("  [%llu] 0x%llx: %s %s", 
                 (unsigned long long)h.timestamp,
                 (unsigned long long)h.pc,
                 h.mnemonic.c_str(),
                 h.op_str.c_str());
        }
        
        // 自动追溯
        if (auto_trace_on_watch) {
            LOGI("--- Tracing source ---");
            auto source = trace_register(matched_reg, watch.value, record.timestamp);
            print_source(source);
        }
        
        LOGI("===========================================");
        
        // 调用用户回调
        if (source_callback) {
            auto source = trace_register(matched_reg, watch.value, record.timestamp);
            source_callback(source, callback_user_data);
        }
        
        // 标记需要移除的一次性监控
        if (watch.one_shot) {
            to_remove.push_back(wi);
        }
    }
    
    // 移除已触发的一次性监控 (从后往前删除)
    for (auto it = to_remove.rbegin(); it != to_remove.rend(); ++it) {
        watches.erase(watches.begin() + *it);
    }
}

DataSource DataTracer::trace_register(int reg, uint64_t value, uint64_t from_timestamp) {
    DataSource result;
    result.type = SOURCE_UNKNOWN;
    result.pc = 0;
    result.timestamp = 0;
    result.target_reg = reg;
    result.value = value;
    result.immediate = 0;
    result.memory_addr = 0;
    
    if (history.empty()) return result;
    
    // 确定起始位置
    size_t start_idx = history.size() - 1;
    if (from_timestamp > 0) {
        for (size_t i = history.size(); i > 0; i--) {
            if (history[i-1].timestamp <= from_timestamp) {
                start_idx = i - 1;
                break;
            }
        }
    }
    
    // 如果 value 为 0，使用当前寄存器值
    if (value == 0 && start_idx < history.size()) {
        value = history[start_idx].regs_before[reg];
        result.value = value;
    }
    
    // 向后回溯，找到设置该寄存器的指令
    for (size_t i = start_idx + 1; i > 0; i--) {
        const auto& rec = history[i - 1];
        
        // 检查这条指令是否修改了目标寄存器
        bool modified = false;
        if (i < history.size()) {
            // 比较 before 和 after
            modified = (rec.regs_after[reg] != rec.regs_before[reg]);
        }
        
        if (!modified) continue;
        
        // 检查修改后的值是否匹配
        if (rec.regs_after[reg] != value) continue;
        
        // 找到了！分析这条指令
        result.pc = rec.pc;
        result.timestamp = rec.timestamp;
        result.instruction = std::string(rec.mnemonic) + " " + rec.op_str;
        
        // 反汇编获取详细信息
        auto insn = DBI::disassemble(rec.pc);
        if (insn) {
            result.type = classify_instruction(insn);
            extract_operands(insn, result);
            
            // 如果是内存加载，记录地址
            if (result.type == SOURCE_MEMORY && rec.is_memory_read) {
                result.memory_addr = rec.memory_addr;
            }
        }
        
        break;
    }
    
    return result;
}

DataSource DataTracer::trace_memory(uint64_t addr, size_t size, uint64_t from_timestamp) {
    DataSource result;
    result.type = SOURCE_UNKNOWN;
    result.pc = 0;
    result.timestamp = 0;
    result.memory_addr = addr;
    
    if (history.empty()) return result;
    
    // 向后回溯，找到写入该地址的指令
    size_t start_idx = history.size() - 1;
    if (from_timestamp > 0) {
        for (size_t i = history.size(); i > 0; i--) {
            if (history[i-1].timestamp <= from_timestamp) {
                start_idx = i - 1;
                break;
            }
        }
    }
    
    for (size_t i = start_idx + 1; i > 0; i--) {
        const auto& rec = history[i - 1];
        
        if (rec.is_memory_write && rec.memory_addr == addr) {
            result.pc = rec.pc;
            result.timestamp = rec.timestamp;
            result.instruction = std::string(rec.mnemonic) + " " + rec.op_str;
            result.type = SOURCE_MEMORY;
            
            // 获取写入的源寄存器
            auto insn = DBI::disassemble(rec.pc);
            if (insn) {
                extract_operands(insn, result);
            }
            
            break;
        }
    }
    
    return result;
}

std::vector<DataSource> DataTracer::get_full_trace(int reg, uint64_t value, int max_depth) {
    std::vector<DataSource> chain;
    
    if (max_depth < 0) max_depth = max_trace_depth;
    
    // 获取第一个来源
    auto source = trace_register(reg, value);
    if (source.type == SOURCE_UNKNOWN) return chain;
    
    chain.push_back(source);
    
    // 递归追溯每个源寄存器
    int depth = 1;
    std::vector<std::pair<int, uint64_t>> to_trace;  // (reg, timestamp)
    
    for (int src_reg : source.source_regs) {
        to_trace.push_back({src_reg, source.timestamp});
    }
    
    while (!to_trace.empty() && depth < max_depth) {
        auto [src_reg, ts] = to_trace.back();
        to_trace.pop_back();
        
        // 获取该寄存器在那个时间点的值
        uint64_t src_value = 0;
        for (const auto& rec : history) {
            if (rec.timestamp == ts) {
                src_value = rec.regs_before[src_reg];
                break;
            }
        }
        
        auto src_source = trace_register(src_reg, src_value, ts);
        if (src_source.type != SOURCE_UNKNOWN) {
            chain.push_back(src_source);
            
            // 继续追溯源寄存器
            for (int sub_reg : src_source.source_regs) {
                to_trace.push_back({sub_reg, src_source.timestamp});
            }
        }
        
        depth++;
    }
    
    return chain;
}

std::vector<InstructionRecord> DataTracer::find_value_producers(uint64_t value, int reg) {
    std::vector<InstructionRecord> results;
    
    for (size_t i = 0; i < history.size(); i++) {
        const auto& rec = history[i];
        
        if (reg >= 0) {
            // 检查特定寄存器
            if (i > 0 && rec.regs_before[reg] == value && 
                history[i-1].regs_before[reg] != value) {
                results.push_back(history[i-1]);
            }
        } else {
            // 检查所有寄存器
            for (int r = 0; r < 32; r++) {
                if (i > 0 && rec.regs_before[r] == value && 
                    history[i-1].regs_before[r] != value) {
                    results.push_back(history[i-1]);
                    break;
                }
            }
        }
    }
    
    return results;
}

std::vector<InstructionRecord> DataTracer::find_reg_modifications(int reg) {
    std::vector<InstructionRecord> results;
    
    for (size_t i = 1; i < history.size(); i++) {
        if (history[i].regs_before[reg] != history[i-1].regs_before[reg]) {
            results.push_back(history[i-1]);
        }
    }
    
    return results;
}

bool DataTracer::get_regs_at(uint64_t timestamp, uint64_t* regs_out) {
    for (const auto& rec : history) {
        if (rec.timestamp == timestamp) {
            memcpy(regs_out, rec.regs_before, sizeof(rec.regs_before));
            return true;
        }
    }
    return false;
}

const std::vector<InstructionRecord>& DataTracer::get_history() const {
    return history;
}

void DataTracer::print_source(const DataSource& source, int indent) {
    std::string prefix(indent * 2, ' ');
    
    LOGI("%s[%s] PC=0x%llx: %s",
         prefix.c_str(),
         source_type_name(source.type),
         (unsigned long long)source.pc,
         source.instruction.c_str());
    
    if (source.type == SOURCE_IMMEDIATE) {
        LOGI("%s  └─ Immediate value: 0x%llx", 
             prefix.c_str(), (unsigned long long)source.immediate);
    } else if (source.type == SOURCE_MEMORY) {
        LOGI("%s  └─ Memory address: 0x%llx", 
             prefix.c_str(), (unsigned long long)source.memory_addr);
    } else if (!source.source_regs.empty()) {
        LOGI("%s  └─ Source registers:", prefix.c_str());
        for (int r : source.source_regs) {
            LOGI("%s      - %s", prefix.c_str(), reg_idx_to_name(r));
        }
    }
    
    // 递归打印父节点
    for (const auto& parent : source.parents) {
        print_source(parent, indent + 1);
    }
}

void DataTracer::print_trace_chain(const std::vector<DataSource>& chain) {
    LOGI("========== DATA TRACE CHAIN ==========");
    for (size_t i = 0; i < chain.size(); i++) {
        LOGI("[%zu] %s", i, format_data_source(chain[i]).c_str());
    }
    LOGI("=======================================");
}

void DataTracer::export_trace_report(const char* filename, const DataSource& source) {
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        LOGE("Failed to open file: %s", filename);
        return;
    }
    
    fprintf(fp, "========== DATA SOURCE REPORT ==========\n\n");
    fprintf(fp, "Target Register: %s\n", reg_idx_to_name(source.target_reg));
    fprintf(fp, "Value: 0x%llx\n\n", (unsigned long long)source.value);
    fprintf(fp, "Source Type: %s\n", source_type_name(source.type));
    fprintf(fp, "PC: 0x%llx\n", (unsigned long long)source.pc);
    fprintf(fp, "Instruction: %s\n\n", source.instruction.c_str());
    
    if (source.type == SOURCE_IMMEDIATE) {
        fprintf(fp, "Immediate Value: 0x%llx\n", (unsigned long long)source.immediate);
    } else if (source.type == SOURCE_MEMORY) {
        fprintf(fp, "Memory Address: 0x%llx\n", (unsigned long long)source.memory_addr);
    }
    
    fprintf(fp, "\n========== END OF REPORT ==========\n");
    fclose(fp);
    
    LOGI("Report exported to: %s", filename);
}

void DataTracer::reset() {
    history.clear();
    current_timestamp = 0;
    has_last_regs = false;
    memset(last_regs, 0, sizeof(last_regs));
    
    for (auto& watch : watches) {
        watch.triggered = false;
        watch.trigger_pc = 0;
        watch.trigger_timestamp = 0;
    }
}

void DataTracer::get_stats(size_t* history_size, size_t* watch_count, uint64_t* timestamp) {
    if (history_size) *history_size = history.size();
    if (watch_count) *watch_count = watches.size();
    if (timestamp) *timestamp = current_timestamp;
}

