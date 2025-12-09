//
// Created for ARM64DBI Taint Analysis Extension
// 污点分析模块 - 实现文件
//

#include "Taint.h"
#include "DBI.h"
#include "Assembler.h"
#include <android/log.h>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <sstream>
#include <iomanip>

#define TAG "ARM64DBI-Taint"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// ==================== 辅助函数实现 ====================

const char* taint_tag_name(TaintTag tag) {
    if (tag == TAINT_NONE) return "NONE";
    if (tag == TAINT_INPUT) return "INPUT";
    if (tag == TAINT_KEY) return "KEY";
    if (tag == TAINT_IV) return "IV";
    if (tag == TAINT_OUTPUT) return "OUTPUT";
    if (tag == TAINT_SENSITIVE) return "SENSITIVE";
    if (tag == TAINT_USER1) return "USER1";
    if (tag == TAINT_USER2) return "USER2";
    if (tag == TAINT_USER3) return "USER3";
    if (tag == TAINT_USER4) return "USER4";
    return "MIXED";
}

std::string format_taint_tag(TaintTag tag) {
    if (tag == TAINT_NONE) return "NONE";
    
    std::string result;
    if (tag & TAINT_INPUT) result += "INPUT|";
    if (tag & TAINT_KEY) result += "KEY|";
    if (tag & TAINT_IV) result += "IV|";
    if (tag & TAINT_OUTPUT) result += "OUTPUT|";
    if (tag & TAINT_SENSITIVE) result += "SENSITIVE|";
    if (tag & TAINT_USER1) result += "USER1|";
    if (tag & TAINT_USER2) result += "USER2|";
    if (tag & TAINT_USER3) result += "USER3|";
    if (tag & TAINT_USER4) result += "USER4|";
    
    // 移除最后的 '|'
    if (!result.empty() && result.back() == '|') {
        result.pop_back();
    }
    
    return result.empty() ? "UNKNOWN" : result;
}

const char* reg_idx_to_name(int idx) {
    static const char* names[] = {
        "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7",
        "X8", "X9", "X10", "X11", "X12", "X13", "X14", "X15",
        "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23",
        "X24", "X25", "X26", "X27", "X28", "X29", "X30", "SP"
    };
    if (idx >= 0 && idx < 32) return names[idx];
    return "UNKNOWN";
}

int reg_name_to_idx(const char* name) {
    if (!name) return -1;
    
    // X0-X30
    if (name[0] == 'X' || name[0] == 'x') {
        int idx = atoi(name + 1);
        if (idx >= 0 && idx <= 30) return idx;
    }
    // W0-W30 (32位版本映射到相同索引)
    if (name[0] == 'W' || name[0] == 'w') {
        int idx = atoi(name + 1);
        if (idx >= 0 && idx <= 30) return idx;
    }
    // SP
    if (strcasecmp(name, "SP") == 0) return 31;
    // FP = X29
    if (strcasecmp(name, "FP") == 0) return 29;
    // LR = X30
    if (strcasecmp(name, "LR") == 0) return 30;
    
    return -1;
}

int cs_reg_to_idx(unsigned int cs_reg) {
    // Capstone ARM64 寄存器ID映射
    if (cs_reg >= AARCH64_REG_X0 && cs_reg <= AARCH64_REG_X28) {
        return cs_reg - AARCH64_REG_X0;
    }
    if (cs_reg >= AARCH64_REG_W0 && cs_reg <= AARCH64_REG_W30) {
        return cs_reg - AARCH64_REG_W0;
    }
    if (cs_reg == AARCH64_REG_X29 || cs_reg == AARCH64_REG_FP) return 29;
    if (cs_reg == AARCH64_REG_X30 || cs_reg == AARCH64_REG_LR) return 30;
    if (cs_reg == AARCH64_REG_SP) return 31;
    
    return -1;
}

// ==================== TaintState 实现 ====================

TaintState::TaintState() : verbose_mode(false), propagate_count(0), source_count(0), sink_count(0) {
    memset(reg_taint, 0, sizeof(reg_taint));
}

TaintState::~TaintState() {
    reset();
}

void TaintState::set_reg_taint(int reg_idx, TaintTag taint) {
    if (reg_idx >= 0 && reg_idx < 32) {
        reg_taint[reg_idx] = taint;
    }
}

TaintTag TaintState::get_reg_taint(int reg_idx) {
    if (reg_idx >= 0 && reg_idx < 32) {
        return reg_taint[reg_idx];
    }
    return TAINT_NONE;
}

void TaintState::clear_reg_taint(int reg_idx) {
    if (reg_idx >= 0 && reg_idx < 32) {
        reg_taint[reg_idx] = TAINT_NONE;
    }
}

TaintTag TaintState::merge_reg_taint(int reg1, int reg2) {
    return get_reg_taint(reg1) | get_reg_taint(reg2);
}

TaintTag TaintState::merge_reg_taint(int reg1, int reg2, int reg3) {
    return get_reg_taint(reg1) | get_reg_taint(reg2) | get_reg_taint(reg3);
}

void TaintState::set_mem_taint(uint64_t addr, size_t size, TaintTag taint) {
    for (size_t i = 0; i < size; i++) {
        if (taint == TAINT_NONE) {
            mem_taint.erase(addr + i);
        } else {
            mem_taint[addr + i] = taint;
        }
    }
}

TaintTag TaintState::get_mem_taint(uint64_t addr) {
    auto it = mem_taint.find(addr);
    if (it != mem_taint.end()) {
        return it->second;
    }
    return TAINT_NONE;
}

TaintTag TaintState::get_mem_taint_range(uint64_t addr, size_t size) {
    TaintTag result = TAINT_NONE;
    for (size_t i = 0; i < size; i++) {
        result |= get_mem_taint(addr + i);
    }
    return result;
}

void TaintState::clear_mem_taint(uint64_t addr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        mem_taint.erase(addr + i);
    }
}

void TaintState::mark_source_reg(int reg_idx, TaintTag taint, uint64_t pc, const char* desc) {
    TaintTag old = get_reg_taint(reg_idx);
    set_reg_taint(reg_idx, taint);
    source_count++;
    
    TaintEvent event;
    event.pc = pc;
    event.type = TAINT_EVENT_SOURCE;
    event.old_taint = old;
    event.new_taint = taint;
    event.location = reg_idx_to_name(reg_idx);
    event.description = desc ? desc : "Register taint source";
    record_event(event);
    
    if (verbose_mode) {
        LOGI("[TAINT SOURCE] PC=0x%llx %s <- %s %s", 
             (unsigned long long)pc, 
             reg_idx_to_name(reg_idx),
             format_taint_tag(taint).c_str(),
             desc ? desc : "");
    }
}

void TaintState::mark_source_mem(uint64_t addr, size_t size, TaintTag taint, uint64_t pc, const char* desc) {
    TaintTag old = get_mem_taint_range(addr, size);
    set_mem_taint(addr, size, taint);
    source_count++;
    
    TaintEvent event;
    event.pc = pc;
    event.type = TAINT_EVENT_SOURCE;
    event.old_taint = old;
    event.new_taint = taint;
    
    char loc_buf[64];
    snprintf(loc_buf, sizeof(loc_buf), "mem:0x%llx[%zu]", (unsigned long long)addr, size);
    event.location = loc_buf;
    event.description = desc ? desc : "Memory taint source";
    record_event(event);
    
    if (verbose_mode) {
        LOGI("[TAINT SOURCE] PC=0x%llx mem[0x%llx, %zu] <- %s %s",
             (unsigned long long)pc,
             (unsigned long long)addr,
             size,
             format_taint_tag(taint).c_str(),
             desc ? desc : "");
    }
}

bool TaintState::check_sink_reg(int reg_idx, TaintTag expected, uint64_t pc, const char* desc) {
    TaintTag actual = get_reg_taint(reg_idx);
    bool hit = (actual & expected) != 0;
    
    if (hit) {
        sink_count++;
        
        TaintEvent event;
        event.pc = pc;
        event.type = TAINT_EVENT_SINK;
        event.old_taint = TAINT_NONE;
        event.new_taint = actual;
        event.location = reg_idx_to_name(reg_idx);
        event.description = desc ? desc : "Taint sink detected";
        record_event(event);
        
        LOGI("[TAINT SINK] PC=0x%llx %s has taint %s (expected %s) %s",
             (unsigned long long)pc,
             reg_idx_to_name(reg_idx),
             format_taint_tag(actual).c_str(),
             format_taint_tag(expected).c_str(),
             desc ? desc : "");
    }
    
    return hit;
}

bool TaintState::check_sink_mem(uint64_t addr, size_t size, TaintTag expected, uint64_t pc, const char* desc) {
    TaintTag actual = get_mem_taint_range(addr, size);
    bool hit = (actual & expected) != 0;
    
    if (hit) {
        sink_count++;
        
        TaintEvent event;
        event.pc = pc;
        event.type = TAINT_EVENT_SINK;
        event.old_taint = TAINT_NONE;
        event.new_taint = actual;
        
        char loc_buf[64];
        snprintf(loc_buf, sizeof(loc_buf), "mem:0x%llx[%zu]", (unsigned long long)addr, size);
        event.location = loc_buf;
        event.description = desc ? desc : "Taint sink detected";
        record_event(event);
        
        LOGI("[TAINT SINK] PC=0x%llx mem[0x%llx, %zu] has taint %s (expected %s) %s",
             (unsigned long long)pc,
             (unsigned long long)addr,
             size,
             format_taint_tag(actual).c_str(),
             format_taint_tag(expected).c_str(),
             desc ? desc : "");
    }
    
    return hit;
}

void TaintState::record_event(const TaintEvent& event) {
    events.push_back(event);
}

void TaintState::record_flow(uint64_t src_pc, uint64_t dst_pc,
                              const std::string& src_loc, const std::string& dst_loc,
                              TaintTag taint) {
    TaintFlow flow;
    flow.source_pc = src_pc;
    flow.dest_pc = dst_pc;
    flow.source_loc = src_loc;
    flow.dest_loc = dst_loc;
    flow.taint = taint;
    flows.push_back(flow);
}

const std::vector<TaintEvent>& TaintState::get_events() const {
    return events;
}

const std::vector<TaintFlow>& TaintState::get_flows() const {
    return flows;
}

void TaintState::reset() {
    memset(reg_taint, 0, sizeof(reg_taint));
    mem_taint.clear();
    events.clear();
    flows.clear();
    propagate_count = 0;
    source_count = 0;
    sink_count = 0;
}

void TaintState::set_verbose(bool enable) {
    verbose_mode = enable;
}

void TaintState::get_stats(uint64_t* propagate, uint64_t* source, uint64_t* sink) {
    if (propagate) *propagate = propagate_count;
    if (source) *source = source_count;
    if (sink) *sink = sink_count;
}

void TaintState::dump_state() {
    LOGI("========== TAINT STATE ==========");
    
    // 打印寄存器污点
    LOGI("--- Register Taint ---");
    for (int i = 0; i < 32; i++) {
        if (reg_taint[i] != TAINT_NONE) {
            LOGI("  %s: %s", reg_idx_to_name(i), format_taint_tag(reg_taint[i]).c_str());
        }
    }
    
    // 打印内存污点 (合并相邻区域)
    LOGI("--- Memory Taint ---");
    if (!mem_taint.empty()) {
        std::vector<std::pair<uint64_t, TaintTag>> sorted_mem;
        for (const auto& p : mem_taint) {
            sorted_mem.push_back(p);
        }
        std::sort(sorted_mem.begin(), sorted_mem.end());
        
        uint64_t range_start = 0;
        TaintTag range_taint = TAINT_NONE;
        size_t range_size = 0;
        
        for (const auto& p : sorted_mem) {
            if (range_size == 0) {
                range_start = p.first;
                range_taint = p.second;
                range_size = 1;
            } else if (p.first == range_start + range_size && p.second == range_taint) {
                range_size++;
            } else {
                LOGI("  [0x%llx - 0x%llx] (%zu bytes): %s",
                     (unsigned long long)range_start,
                     (unsigned long long)(range_start + range_size - 1),
                     range_size,
                     format_taint_tag(range_taint).c_str());
                range_start = p.first;
                range_taint = p.second;
                range_size = 1;
            }
        }
        if (range_size > 0) {
            LOGI("  [0x%llx - 0x%llx] (%zu bytes): %s",
                 (unsigned long long)range_start,
                 (unsigned long long)(range_start + range_size - 1),
                 range_size,
                 format_taint_tag(range_taint).c_str());
        }
    }
    
    LOGI("--- Statistics ---");
    LOGI("  Sources: %llu", (unsigned long long)source_count);
    LOGI("  Propagations: %llu", (unsigned long long)propagate_count);
    LOGI("  Sinks: %llu", (unsigned long long)sink_count);
    LOGI("==================================");
}

void TaintState::dump_flow_graph() {
    LOGI("========== TAINT FLOW GRAPH ==========");
    for (const auto& flow : flows) {
        LOGI("  0x%llx [%s] --(%s)--> 0x%llx [%s]",
             (unsigned long long)flow.source_pc,
             flow.source_loc.c_str(),
             format_taint_tag(flow.taint).c_str(),
             (unsigned long long)flow.dest_pc,
             flow.dest_loc.c_str());
    }
    LOGI("=======================================");
}

// ==================== TaintAnalyzer 实现 ====================

TaintAnalyzer* TaintAnalyzer::instance = nullptr;

TaintAnalyzer::TaintAnalyzer() 
    : user_callback(nullptr), sink_callback(nullptr), sink_user_data(nullptr),
      track_arithmetic(true), track_logic(true), track_memory(true),
      track_control_flow(false), auto_clear_on_const(true) {
}

TaintAnalyzer* TaintAnalyzer::getInstance() {
    if (!instance) {
        instance = new TaintAnalyzer();
    }
    return instance;
}

void TaintAnalyzer::set_track_arithmetic(bool enable) { track_arithmetic = enable; }
void TaintAnalyzer::set_track_logic(bool enable) { track_logic = enable; }
void TaintAnalyzer::set_track_memory(bool enable) { track_memory = enable; }
void TaintAnalyzer::set_track_control_flow(bool enable) { track_control_flow = enable; }
void TaintAnalyzer::set_auto_clear_on_const(bool enable) { auto_clear_on_const = enable; }

void TaintAnalyzer::set_user_callback(TaintCallback callback) {
    user_callback = callback;
}

void TaintAnalyzer::set_sink_callback(TaintSinkCallback callback, void* user_data) {
    sink_callback = callback;
    sink_user_data = user_data;
}

void TaintAnalyzer::add_watch_region(uint64_t start, size_t size, TaintTag taint, const char* name) {
    WatchRegion region;
    region.start = start;
    region.end = start + size;
    region.taint = taint;
    region.name = name ? name : "";
    watch_regions.push_back(region);
    
    // 立即标记为污点源
    state.set_mem_taint(start, size, taint);
    
    LOGI("[TAINT] Added watch region: 0x%llx - 0x%llx, taint=%s, name=%s",
         (unsigned long long)start,
         (unsigned long long)(start + size),
         format_taint_tag(taint).c_str(),
         name ? name : "(unnamed)");
}

void TaintAnalyzer::mark_arg_taint(int arg_idx, TaintTag taint) {
    // ARM64 调用约定: X0-X7 用于前8个参数
    if (arg_idx >= 0 && arg_idx <= 7) {
        state.mark_source_reg(arg_idx, taint, 0, "Function argument");
    }
}

void TaintAnalyzer::mark_reg_source(int reg_idx, TaintTag taint) {
    state.mark_source_reg(reg_idx, taint, 0, "Manual register source");
}

void TaintAnalyzer::mark_mem_source(uint64_t addr, size_t size, TaintTag taint) {
    state.mark_source_mem(addr, size, taint, 0, "Manual memory source");
}

void TaintAnalyzer::add_sink_point(uint64_t addr, int reg, TaintTag expected, const char* name) {
    SinkPoint sink;
    sink.addr = addr;
    sink.reg = reg;
    sink.expected = expected;
    sink.name = name ? name : "";
    sink_points.push_back(sink);
}

void TaintAnalyzer::add_return_sink(TaintTag expected, const char* name) {
    // 监控 X0 (返回值)
    add_sink_point(0, 0, expected, name ? name : "Return value");
}

TaintState* TaintAnalyzer::get_state() {
    return &state;
}

// 内部污点传播回调
static void internal_taint_callback(const CPU_CONTEXT* ctx) {
    TaintAnalyzer::getInstance()->propagate(ctx);
}

void* TaintAnalyzer::trace(uint64_t target_addr) {
    LOGI("[TAINT] Starting taint trace at 0x%llx", (unsigned long long)target_addr);
    return DBI::trace(target_addr, internal_taint_callback);
}

void TaintAnalyzer::propagate(const CPU_CONTEXT* ctx) {
    auto insn = DBI::disassemble(ctx->pc);
    if (!insn) return;
    
    // 调用用户回调
    if (user_callback) {
        user_callback(ctx, &state);
    }
    
    // 获取指令详情
    cs_detail* detail = insn->detail;
    if (!detail) return;
    
    cs_aarch64* aarch64 = &detail->aarch64;
    
    // 根据指令类型处理污点传播
    switch (insn->id) {
        // ========== 数据移动指令 ==========
        case AARCH64_INS_MOV:
        case AARCH64_INS_MVN: {
            if (aarch64->op_count >= 2) {
                cs_aarch64_op* dst = &aarch64->operands[0];
                cs_aarch64_op* src = &aarch64->operands[1];
                
                if (dst->type == AARCH64_OP_REG) {
                    int dst_idx = cs_reg_to_idx(dst->reg);
                    TaintTag new_taint = TAINT_NONE;
                    
                    if (src->type == AARCH64_OP_REG) {
                        int src_idx = cs_reg_to_idx(src->reg);
                        new_taint = state.get_reg_taint(src_idx);
                    } else if (src->type == AARCH64_OP_IMM && auto_clear_on_const) {
                        new_taint = TAINT_NONE;  // 常量覆盖清除污点
                    }
                    
                    TaintTag old_taint = state.get_reg_taint(dst_idx);
                    if (new_taint != old_taint) {
                        state.set_reg_taint(dst_idx, new_taint);
                        state.propagate_count++;
                        
                        if (state.verbose_mode && new_taint != TAINT_NONE) {
                            LOGD("[PROPAGATE] 0x%llx: %s %s -> %s = %s",
                                 (unsigned long long)ctx->pc,
                                 insn->mnemonic,
                                 insn->op_str,
                                 reg_idx_to_name(dst_idx),
                                 format_taint_tag(new_taint).c_str());
                        }
                    }
                }
            }
            break;
        }
        
        // ========== 算术运算指令 ==========
        case AARCH64_INS_ADD:
        case AARCH64_INS_SUB:
        case AARCH64_INS_MUL:
        case AARCH64_INS_SDIV:
        case AARCH64_INS_UDIV:
        case AARCH64_INS_MADD:
        case AARCH64_INS_MSUB: {
            if (!track_arithmetic) break;
            
            if (aarch64->op_count >= 2) {
                cs_aarch64_op* dst = &aarch64->operands[0];
                
                if (dst->type == AARCH64_OP_REG) {
                    int dst_idx = cs_reg_to_idx(dst->reg);
                    TaintTag merged = TAINT_NONE;
                    
                    // 合并所有源操作数的污点
                    for (int i = 1; i < aarch64->op_count; i++) {
                        cs_aarch64_op* op = &aarch64->operands[i];
                        if (op->type == AARCH64_OP_REG) {
                            int src_idx = cs_reg_to_idx(op->reg);
                            merged |= state.get_reg_taint(src_idx);
                        }
                    }
                    
                    TaintTag old_taint = state.get_reg_taint(dst_idx);
                    if (merged != old_taint) {
                        state.set_reg_taint(dst_idx, merged);
                        state.propagate_count++;
                        
                        if (state.verbose_mode && merged != TAINT_NONE) {
                            LOGD("[PROPAGATE] 0x%llx: %s %s -> %s = %s",
                                 (unsigned long long)ctx->pc,
                                 insn->mnemonic,
                                 insn->op_str,
                                 reg_idx_to_name(dst_idx),
                                 format_taint_tag(merged).c_str());
                        }
                    }
                }
            }
            break;
        }
        
        // ========== 逻辑运算指令 (加密常用) ==========
        case AARCH64_INS_AND:
        case AARCH64_INS_ORR:
        case AARCH64_INS_EOR:  // XOR - 加密核心操作
        case AARCH64_INS_BIC:
        case AARCH64_INS_ORN:
        case AARCH64_INS_EON: {
            if (!track_logic) break;
            
            if (aarch64->op_count >= 2) {
                cs_aarch64_op* dst = &aarch64->operands[0];
                
                if (dst->type == AARCH64_OP_REG) {
                    int dst_idx = cs_reg_to_idx(dst->reg);
                    TaintTag merged = TAINT_NONE;
                    
                    for (int i = 1; i < aarch64->op_count; i++) {
                        cs_aarch64_op* op = &aarch64->operands[i];
                        if (op->type == AARCH64_OP_REG) {
                            int src_idx = cs_reg_to_idx(op->reg);
                            merged |= state.get_reg_taint(src_idx);
                        }
                    }
                    
                    state.set_reg_taint(dst_idx, merged);
                    state.propagate_count++;
                    
                    // XOR 操作特别标记 (加密中常用)
                    if (insn->id == AARCH64_INS_EOR && merged != TAINT_NONE && state.verbose_mode) {
                        LOGI("[CRYPTO] 0x%llx: XOR operation with tainted data: %s",
                             (unsigned long long)ctx->pc,
                             format_taint_tag(merged).c_str());
                    }
                }
            }
            break;
        }
        
        // ========== 移位运算指令 (加密常用) ==========
        case AARCH64_INS_LSL:
        case AARCH64_INS_LSR:
        case AARCH64_INS_ASR:
        case AARCH64_INS_ROR: {
            if (!track_logic) break;
            
            if (aarch64->op_count >= 2) {
                cs_aarch64_op* dst = &aarch64->operands[0];
                cs_aarch64_op* src = &aarch64->operands[1];
                
                if (dst->type == AARCH64_OP_REG && src->type == AARCH64_OP_REG) {
                    int dst_idx = cs_reg_to_idx(dst->reg);
                    int src_idx = cs_reg_to_idx(src->reg);
                    TaintTag src_taint = state.get_reg_taint(src_idx);
                    
                    state.set_reg_taint(dst_idx, src_taint);
                    state.propagate_count++;
                }
            }
            break;
        }
        
        // ========== 内存加载指令 ==========
        case AARCH64_INS_LDR:
        case AARCH64_INS_LDRB:
        case AARCH64_INS_LDRH:
        case AARCH64_INS_LDRSB:
        case AARCH64_INS_LDRSH:
        case AARCH64_INS_LDRSW:
        case AARCH64_INS_LDP: {
            if (!track_memory) break;
            
            if (aarch64->op_count >= 2) {
                cs_aarch64_op* dst = &aarch64->operands[0];
                cs_aarch64_op* mem = &aarch64->operands[aarch64->op_count - 1];
                
                if (dst->type == AARCH64_OP_REG && mem->type == AARCH64_OP_MEM) {
                    int dst_idx = cs_reg_to_idx(dst->reg);
                    
                    // 计算内存地址
                    uint64_t mem_addr = 0;
                    int base_idx = cs_reg_to_idx(mem->mem.base);
                    if (base_idx >= 0 && base_idx < 29) {
                        mem_addr = ctx->x[base_idx];
                    } else if (base_idx == 29) {
                        mem_addr = ctx->fp;
                    } else if (base_idx == 31) {
                        mem_addr = ctx->sp;
                    }
                    mem_addr += mem->mem.disp;
                    
                    // 确定加载大小
                    size_t load_size = 8;  // 默认64位
                    if (insn->id == AARCH64_INS_LDRB || insn->id == AARCH64_INS_LDRSB) load_size = 1;
                    else if (insn->id == AARCH64_INS_LDRH || insn->id == AARCH64_INS_LDRSH) load_size = 2;
                    else if (insn->id == AARCH64_INS_LDRSW) load_size = 4;
                    
                    // 从内存获取污点
                    TaintTag mem_taint = state.get_mem_taint_range(mem_addr, load_size);
                    
                    // 检查是否在监控区域
                    for (const auto& region : watch_regions) {
                        if (mem_addr >= region.start && mem_addr < region.end) {
                            mem_taint |= region.taint;
                        }
                    }
                    
                    state.set_reg_taint(dst_idx, mem_taint);
                    state.propagate_count++;
                    
                    if (state.verbose_mode && mem_taint != TAINT_NONE) {
                        LOGD("[LOAD] 0x%llx: %s <- mem[0x%llx] = %s",
                             (unsigned long long)ctx->pc,
                             reg_idx_to_name(dst_idx),
                             (unsigned long long)mem_addr,
                             format_taint_tag(mem_taint).c_str());
                    }
                }
            }
            break;
        }
        
        // ========== 内存存储指令 ==========
        case AARCH64_INS_STR:
        case AARCH64_INS_STRB:
        case AARCH64_INS_STRH:
        case AARCH64_INS_STP: {
            if (!track_memory) break;
            
            if (aarch64->op_count >= 2) {
                cs_aarch64_op* src = &aarch64->operands[0];
                cs_aarch64_op* mem = &aarch64->operands[aarch64->op_count - 1];
                
                if (src->type == AARCH64_OP_REG && mem->type == AARCH64_OP_MEM) {
                    int src_idx = cs_reg_to_idx(src->reg);
                    TaintTag src_taint = state.get_reg_taint(src_idx);
                    
                    // 计算内存地址
                    uint64_t mem_addr = 0;
                    int base_idx = cs_reg_to_idx(mem->mem.base);
                    if (base_idx >= 0 && base_idx < 29) {
                        mem_addr = ctx->x[base_idx];
                    } else if (base_idx == 29) {
                        mem_addr = ctx->fp;
                    } else if (base_idx == 31) {
                        mem_addr = ctx->sp;
                    }
                    mem_addr += mem->mem.disp;
                    
                    // 确定存储大小
                    size_t store_size = 8;
                    if (insn->id == AARCH64_INS_STRB) store_size = 1;
                    else if (insn->id == AARCH64_INS_STRH) store_size = 2;
                    
                    state.set_mem_taint(mem_addr, store_size, src_taint);
                    state.propagate_count++;
                    
                    if (state.verbose_mode && src_taint != TAINT_NONE) {
                        LOGD("[STORE] 0x%llx: mem[0x%llx] <- %s = %s",
                             (unsigned long long)ctx->pc,
                             (unsigned long long)mem_addr,
                             reg_idx_to_name(src_idx),
                             format_taint_tag(src_taint).c_str());
                    }
                }
            }
            break;
        }
        
        default:
            break;
    }
    
    // 检查污点汇点
    for (const auto& sink : sink_points) {
        if (sink.addr == 0 || sink.addr == ctx->pc) {
            if (sink.reg >= 0) {
                TaintTag actual = state.get_reg_taint(sink.reg);
                if ((actual & sink.expected) != 0) {
                    if (sink_callback) {
                        sink_callback(ctx->pc, reg_idx_to_name(sink.reg), actual, sink_user_data);
                    }
                    LOGI("[SINK HIT] 0x%llx: %s has taint %s (%s)",
                         (unsigned long long)ctx->pc,
                         reg_idx_to_name(sink.reg),
                         format_taint_tag(actual).c_str(),
                         sink.name.c_str());
                }
            }
        }
    }
}

void TaintAnalyzer::export_report(const char* filename) {
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        LOGE("Failed to open report file: %s", filename);
        return;
    }
    
    fprintf(fp, "========== ARM64DBI Taint Analysis Report ==========\n\n");
    
    // 统计信息
    uint64_t propagate, source, sink;
    state.get_stats(&propagate, &source, &sink);
    fprintf(fp, "=== Statistics ===\n");
    fprintf(fp, "Taint Sources: %llu\n", (unsigned long long)source);
    fprintf(fp, "Taint Propagations: %llu\n", (unsigned long long)propagate);
    fprintf(fp, "Taint Sinks: %llu\n\n", (unsigned long long)sink);
    
    // 事件记录
    const auto& events = state.get_events();
    fprintf(fp, "=== Taint Events (%zu total) ===\n", events.size());
    for (const auto& event : events) {
        const char* type_str = "UNKNOWN";
        switch (event.type) {
            case TAINT_EVENT_SOURCE: type_str = "SOURCE"; break;
            case TAINT_EVENT_PROPAGATE: type_str = "PROPAGATE"; break;
            case TAINT_EVENT_SINK: type_str = "SINK"; break;
            case TAINT_EVENT_CLEAR: type_str = "CLEAR"; break;
            case TAINT_EVENT_MERGE: type_str = "MERGE"; break;
        }
        fprintf(fp, "[%s] PC=0x%llx %s: %s -> %s | %s\n",
                type_str,
                (unsigned long long)event.pc,
                event.location.c_str(),
                format_taint_tag(event.old_taint).c_str(),
                format_taint_tag(event.new_taint).c_str(),
                event.description.c_str());
    }
    
    fprintf(fp, "\n=== End of Report ===\n");
    fclose(fp);
    
    LOGI("Report exported to: %s", filename);
}

void TaintAnalyzer::print_summary() {
    LOGI("========== TAINT ANALYSIS SUMMARY ==========");
    
    uint64_t propagate, source, sink;
    state.get_stats(&propagate, &source, &sink);
    
    LOGI("Taint Sources: %llu", (unsigned long long)source);
    LOGI("Taint Propagations: %llu", (unsigned long long)propagate);
    LOGI("Taint Sinks: %llu", (unsigned long long)sink);
    
    // 打印当前状态
    state.dump_state();
    
    LOGI("=============================================");
}

void TaintAnalyzer::reset() {
    state.reset();
    watch_regions.clear();
    sink_points.clear();
    user_callback = nullptr;
    sink_callback = nullptr;
    sink_user_data = nullptr;
}

