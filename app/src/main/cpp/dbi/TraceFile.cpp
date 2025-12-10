//
// TraceFile.cpp - Trace 文件生成模块实现
//

#include "TraceFile.h"
#include "DBI.h"
#include "Taint.h"
#include <cstring>
#include <ctime>
#include <dlfcn.h>
#include <link.h>
#include <sstream>
#include <iomanip>
#include <sys/time.h>

// ==================== 辅助函数 ====================

static uint64_t get_timestamp_ms() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// 用于遍历已加载模块的回调
struct ModuleScanContext {
    std::vector<ModuleInfo>* modules;
};

static int module_callback(struct dl_phdr_info* info, size_t size, void* data) {
    auto ctx = (ModuleScanContext*)data;
    
    if (info->dlpi_name && strlen(info->dlpi_name) > 0) {
        ModuleInfo mod;
        mod.path = info->dlpi_name;
        
        // 提取文件名
        const char* slash = strrchr(info->dlpi_name, '/');
        mod.name = slash ? (slash + 1) : info->dlpi_name;
        
        mod.base = info->dlpi_addr;
        
        // 计算模块大小
        mod.size = 0;
        for (int i = 0; i < info->dlpi_phnum; i++) {
            if (info->dlpi_phdr[i].p_type == PT_LOAD) {
                uint64_t end = info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz;
                if (end > mod.size) {
                    mod.size = end;
                }
            }
        }
        
        ctx->modules->push_back(mod);
    }
    
    return 0;
}

// ==================== TraceFile 实现 ====================

TraceFile* TraceFile::instance = nullptr;

TraceFile::TraceFile() : record_count(0), is_tracing(false), trace_start_time(0) {
}

TraceFile* TraceFile::getInstance() {
    if (!instance) {
        instance = new TraceFile();
    }
    return instance;
}

void TraceFile::scan_modules() {
    modules.clear();
    module_map.clear();
    
    ModuleScanContext ctx;
    ctx.modules = &modules;
    
    dl_iterate_phdr(module_callback, &ctx);
    
    // 建立名称映射
    for (auto& mod : modules) {
        module_map[mod.name] = &mod;
    }
    
    LOGI("[TraceFile] Scanned %zu modules", modules.size());
}

void TraceFile::add_module(const char* name, uint64_t base, uint64_t size, const char* path) {
    ModuleInfo mod;
    mod.name = name;
    mod.base = base;
    mod.size = size;
    mod.path = path ? path : "";
    
    modules.push_back(mod);
    module_map[mod.name] = &modules.back();
    
    LOGI("[TraceFile] Added module: %s @ 0x%llx (size: 0x%llx)",
         name, (unsigned long long)base, (unsigned long long)size);
}

ModuleInfo* TraceFile::get_module(const char* name) {
    auto it = module_map.find(name);
    if (it != module_map.end()) {
        return it->second;
    }
    return nullptr;
}

const std::vector<ModuleInfo>& TraceFile::get_modules() const {
    return modules;
}

void TraceFile::print_modules() {
    LOGI("========== Loaded Modules ==========");
    for (const auto& mod : modules) {
        LOGI("  %s: 0x%llx - 0x%llx (size: 0x%llx)",
             mod.name.c_str(),
             (unsigned long long)mod.base,
             (unsigned long long)(mod.base + mod.size),
             (unsigned long long)mod.size);
    }
    LOGI("=====================================");
}

ModuleInfo* TraceFile::find_module(uint64_t addr) {
    for (auto& mod : modules) {
        if (addr >= mod.base && addr < mod.base + mod.size) {
            return &mod;
        }
    }
    return nullptr;
}

void TraceFile::set_config(const TraceConfig& cfg) {
    config = cfg;
}

TraceConfig& TraceFile::get_config() {
    return config;
}

void TraceFile::set_target_module(const char* module_name) {
    config.target_module = module_name;
}

void TraceFile::set_address_range(uint64_t start, uint64_t end) {
    config.start_addr = start;
    config.end_addr = end;
}

void TraceFile::set_output_path(const char* path) {
    config.output_path = path;
}

// 内部 trace 回调
static void trace_file_callback(const CPU_CONTEXT* ctx) {
    TraceFile::getInstance()->record_instruction(ctx);
}

void* TraceFile::start_trace(uint64_t func_addr) {
    // 确保模块列表已扫描
    if (modules.empty()) {
        scan_modules();
    }
    
    reset();
    
    // 打开输出文件
    std::string base_path = config.output_path;
    if (base_path.empty()) {
        base_path = "/data/local/tmp/trace";
    }
    
    if (config.output_text) {
        text_file.open(base_path + ".txt");
        if (text_file.is_open()) {
            // 写入文件头
            text_file << "# ARM64DBI Trace File\n";
            text_file << "# Generated: " << time(nullptr) << "\n";
            text_file << "# Target Address: 0x" << std::hex << func_addr << "\n";
            
            // 查找所属模块
            auto mod = find_module(func_addr);
            if (mod) {
                text_file << "# Module: " << mod->name << " (base: 0x" << mod->base << ")\n";
                text_file << "# Offset: 0x" << (func_addr - mod->base) << "\n";
            }
            text_file << "#\n";
            text_file << "# Format: index | pc | offset | opcode | mnemonic operands | regs...\n";
            text_file << "#\n\n";
        }
    }
    
    if (config.output_json) {
        json_file.open(base_path + ".json");
        if (json_file.is_open()) {
            json_file << "{\n";
            json_file << "  \"target\": \"0x" << std::hex << func_addr << "\",\n";
            json_file << "  \"timestamp\": " << std::dec << time(nullptr) << ",\n";
            json_file << "  \"records\": [\n";
        }
    }
    
    is_tracing = true;
    trace_start_time = get_timestamp_ms();
    
    LOGI("[TraceFile] Starting trace at 0x%llx", (unsigned long long)func_addr);
    LOGI("[TraceFile] Output: %s", base_path.c_str());
    
    return DBI::trace(func_addr, trace_file_callback);
}

void* TraceFile::start_trace(const char* module_name, uint64_t offset) {
    // 确保模块列表已扫描
    if (modules.empty()) {
        scan_modules();
    }
    
    auto mod = get_module(module_name);
    if (!mod) {
        LOGE("[TraceFile] Module not found: %s", module_name);
        return nullptr;
    }
    
    uint64_t func_addr = mod->base + offset;
    LOGI("[TraceFile] Resolved %s+0x%llx = 0x%llx",
         module_name, (unsigned long long)offset, (unsigned long long)func_addr);
    
    return start_trace(func_addr);
}

void TraceFile::stop_trace() {
    if (!is_tracing) return;
    
    is_tracing = false;
    
    // 关闭文件
    if (text_file.is_open()) {
        text_file << "\n# Total records: " << record_count << "\n";
        text_file << "# Trace duration: " << (get_timestamp_ms() - trace_start_time) << " ms\n";
        text_file.close();
    }
    
    if (json_file.is_open()) {
        json_file << "\n  ],\n";
        json_file << "  \"total_records\": " << record_count << ",\n";
        json_file << "  \"duration_ms\": " << (get_timestamp_ms() - trace_start_time) << "\n";
        json_file << "}\n";
        json_file.close();
    }
    
    LOGI("[TraceFile] Trace stopped. Total records: %llu", (unsigned long long)record_count);
}

void TraceFile::record_instruction(const CPU_CONTEXT* ctx) {
    // 检查限制
    if (config.max_records > 0 && record_count >= config.max_records) {
        return;
    }
    
    // 检查地址范围
    if (config.end_addr > 0 && ctx->pc >= config.end_addr) {
        return;
    }
    
    // 检查模块过滤
    ModuleInfo* mod = nullptr;
    if (!config.target_module.empty()) {
        mod = find_module(ctx->pc);
        if (!mod || mod->name != config.target_module) {
            if (!config.trace_all_modules) {
                return;
            }
        }
    } else {
        mod = find_module(ctx->pc);
    }
    
    // 反汇编
    auto insn = DBI::disassemble(ctx->pc);
    if (!insn) return;
    
    // 创建记录
    TraceRecord rec;
    rec.index = record_count++;
    rec.pc = ctx->pc;
    rec.offset = mod ? (ctx->pc - mod->base) : ctx->pc;
    rec.mnemonic = insn->mnemonic;
    rec.operands = insn->op_str;
    
    if (config.record_opcodes) {
        rec.opcode = *(uint32_t*)ctx->pc;
    }
    
    if (config.record_regs) {
        for (int i = 0; i < 29; i++) {
            rec.regs[i] = ctx->x[i];
        }
        rec.regs[29] = ctx->fp;
        rec.regs[30] = ctx->lr;
        rec.regs[31] = ctx->sp;
    }
    
    // 内存访问检测
    rec.has_mem_access = false;
    rec.is_mem_read = false;
    rec.mem_addr = 0;
    rec.mem_value = 0;
    rec.mem_size = 0;
    
    if (config.record_memory && insn->detail) {
        cs_aarch64* aarch64 = &insn->detail->aarch64;
        for (int i = 0; i < aarch64->op_count; i++) {
            cs_aarch64_op* op = &aarch64->operands[i];
            if (op->type == AARCH64_OP_MEM) {
                rec.has_mem_access = true;
                
                // 计算地址
                int base_idx = cs_reg_to_idx(op->mem.base);
                if (base_idx >= 0) {
                    rec.mem_addr = rec.regs[base_idx] + op->mem.disp;
                }
                
                // 判断读写
                if (insn->id >= AARCH64_INS_LDR && insn->id <= AARCH64_INS_LDURSW) {
                    rec.is_mem_read = true;
                } else {
                    rec.is_mem_read = false;
                }
                
                break;
            }
        }
    }
    
    // 保存到内存
    records.push_back(rec);
    
    // 写入文件
    if (text_file.is_open()) {
        write_text_record(rec);
    }
    if (json_file.is_open()) {
        write_json_record(rec, false);
    }
}

void TraceFile::write_text_record(const TraceRecord& rec) {
    std::stringstream ss;
    
    // 格式: index | pc | offset | opcode | mnemonic operands
    ss << std::setw(8) << std::dec << rec.index << " | ";
    ss << "0x" << std::setw(12) << std::hex << std::setfill('0') << rec.pc << " | ";
    ss << "0x" << std::setw(8) << std::hex << std::setfill('0') << rec.offset << " | ";
    
    if (config.record_opcodes) {
        ss << std::setw(8) << std::hex << std::setfill('0') << rec.opcode << " | ";
    }
    
    ss << std::setfill(' ') << std::setw(8) << rec.mnemonic << " " << rec.operands;
    
    // 寄存器 (简化输出)
    if (config.record_regs) {
        ss << " ; ";
        // 只输出 X0-X7 (常用参数寄存器)
        for (int i = 0; i < 8; i++) {
            if (rec.regs[i] != 0) {
                ss << "X" << i << "=0x" << std::hex << rec.regs[i] << " ";
            }
        }
    }
    
    // 内存访问
    if (rec.has_mem_access) {
        ss << (rec.is_mem_read ? "[R]" : "[W]");
        ss << " @0x" << std::hex << rec.mem_addr;
    }
    
    text_file << ss.str() << "\n";
    text_file.flush();
}

void TraceFile::write_json_record(const TraceRecord& rec, bool is_last) {
    json_file << "    {\n";
    json_file << "      \"index\": " << std::dec << rec.index << ",\n";
    json_file << "      \"pc\": \"0x" << std::hex << rec.pc << "\",\n";
    json_file << "      \"offset\": \"0x" << std::hex << rec.offset << "\",\n";
    json_file << "      \"mnemonic\": \"" << rec.mnemonic << "\",\n";
    json_file << "      \"operands\": \"" << rec.operands << "\"";
    
    if (config.record_regs) {
        json_file << ",\n      \"regs\": {";
        for (int i = 0; i < 32; i++) {
            if (i > 0) json_file << ", ";
            json_file << "\"X" << i << "\": \"0x" << std::hex << rec.regs[i] << "\"";
        }
        json_file << "}";
    }
    
    if (rec.has_mem_access) {
        json_file << ",\n      \"mem_access\": {";
        json_file << "\"type\": \"" << (rec.is_mem_read ? "read" : "write") << "\", ";
        json_file << "\"addr\": \"0x" << std::hex << rec.mem_addr << "\"}";
    }
    
    json_file << "\n    }" << (is_last ? "" : ",") << "\n";
}

const std::vector<TraceRecord>& TraceFile::get_records() const {
    return records;
}

std::vector<TraceRecord> TraceFile::find_instructions(const char* mnemonic) {
    std::vector<TraceRecord> results;
    for (const auto& rec : records) {
        if (rec.mnemonic == mnemonic) {
            results.push_back(rec);
        }
    }
    return results;
}

std::vector<TraceRecord> TraceFile::find_memory_access(uint64_t addr, bool read, bool write) {
    std::vector<TraceRecord> results;
    for (const auto& rec : records) {
        if (rec.has_mem_access && rec.mem_addr == addr) {
            if ((read && rec.is_mem_read) || (write && !rec.is_mem_read)) {
                results.push_back(rec);
            }
        }
    }
    return results;
}

std::vector<TraceRecord> TraceFile::find_register_value(int reg, uint64_t value) {
    std::vector<TraceRecord> results;
    for (const auto& rec : records) {
        if (reg >= 0 && reg < 32 && rec.regs[reg] == value) {
            results.push_back(rec);
        }
    }
    return results;
}

void TraceFile::save() {
    stop_trace();
}

void TraceFile::export_unidbg_format(const char* filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        LOGE("[TraceFile] Failed to open file: %s", filename);
        return;
    }
    
    // unidbg trace 格式
    for (const auto& rec : records) {
        file << ">>> " << std::setw(8) << rec.mnemonic << " " << rec.operands;
        
        // 寄存器变化
        file << " ; ";
        for (int i = 0; i < 8; i++) {
            file << "x" << i << "=0x" << std::hex << rec.regs[i] << " ";
        }
        
        file << "\n";
    }
    
    file.close();
    LOGI("[TraceFile] Exported unidbg format to: %s", filename);
}

void TraceFile::export_ida_format(const char* filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        LOGE("[TraceFile] Failed to open file: %s", filename);
        return;
    }
    
    // IDA trace 格式
    file << "Thread ID: 0\n";
    file << "Trace records:\n";
    file << "----------------\n";
    
    for (const auto& rec : records) {
        file << std::hex << std::setw(12) << std::setfill('0') << rec.pc;
        file << ": " << rec.mnemonic << " " << rec.operands << "\n";
    }
    
    file.close();
    LOGI("[TraceFile] Exported IDA format to: %s", filename);
}

void TraceFile::export_summary(const char* filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        LOGE("[TraceFile] Failed to open file: %s", filename);
        return;
    }
    
    file << "========== TRACE SUMMARY ==========\n\n";
    file << "Total instructions: " << records.size() << "\n\n";
    
    // 指令频率统计
    std::unordered_map<std::string, size_t> mnemonic_count;
    for (const auto& rec : records) {
        mnemonic_count[rec.mnemonic]++;
    }
    
    file << "Instruction frequency:\n";
    for (const auto& p : mnemonic_count) {
        file << "  " << p.first << ": " << p.second << "\n";
    }
    
    // 内存访问统计
    size_t read_count = 0, write_count = 0;
    for (const auto& rec : records) {
        if (rec.has_mem_access) {
            if (rec.is_mem_read) read_count++;
            else write_count++;
        }
    }
    
    file << "\nMemory access:\n";
    file << "  Reads: " << read_count << "\n";
    file << "  Writes: " << write_count << "\n";
    
    file << "\n========== END SUMMARY ==========\n";
    file.close();
    
    LOGI("[TraceFile] Exported summary to: %s", filename);
}

void TraceFile::get_stats(size_t* total_records, size_t* module_count) {
    if (total_records) *total_records = records.size();
    if (module_count) *module_count = modules.size();
}

void TraceFile::reset() {
    records.clear();
    record_count = 0;
    is_tracing = false;
    
    if (text_file.is_open()) text_file.close();
    if (json_file.is_open()) json_file.close();
    if (bin_file.is_open()) bin_file.close();
}

// ==================== 便捷函数 ====================

void* quick_trace(uint64_t func_addr, const char* output_file) {
    auto tf = TraceFile::getInstance();
    tf->set_output_path(output_file);
    return tf->start_trace(func_addr);
}

void* quick_trace_module(const char* module_name, uint64_t offset, const char* output_file) {
    auto tf = TraceFile::getInstance();
    tf->set_output_path(output_file);
    return tf->start_trace(module_name, offset);
}

uint64_t find_module_base(const char* module_name) {
    auto tf = TraceFile::getInstance();
    if (tf->get_modules().empty()) {
        tf->scan_modules();
    }
    
    auto mod = tf->get_module(module_name);
    return mod ? mod->base : 0;
}

uint64_t get_module_offset(const char* module_name, uint64_t addr) {
    uint64_t base = find_module_base(module_name);
    if (base && addr >= base) {
        return addr - base;
    }
    return 0;
}

