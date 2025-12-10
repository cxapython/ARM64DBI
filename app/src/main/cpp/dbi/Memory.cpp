//
// Created by lidongyooo on 2025/12/7.
//

#include "Memory.h"

Memory* Memory::instance = nullptr;

BlockMeta* Memory::new_block_meta() {
    auto self = getInstance();
    
    // 检查是否初始化成功
    if (self->first_block_meta == nullptr || self->first_block_meta == MAP_FAILED) {
        LOGE("Memory pool not initialized!");
        return nullptr;
    }
    
    // 检查块数量是否已满
    if (self->curr_block_index >= BLOCK_NUMBER) {
        LOGE("Block pool exhausted! Maximum %d blocks reached.", BLOCK_NUMBER);
        return nullptr;
    }
    
    auto block_meta = self->first_block_meta + self->curr_block_index;
    block_meta->index = self->curr_block_index;
    
    // 初始化块元数据
    block_meta->code_start = nullptr;
    block_meta->code_size = 0;
    block_meta->block_start = nullptr;
    block_meta->block_size = 0;
    block_meta->slice_block_meta = nullptr;
    memset(block_meta->code, 0, sizeof(block_meta->code));
    
    self->block_meta_arr[self->curr_block_index++] = block_meta;

    return block_meta;
}

BlockMeta* Memory::get_or_new_block_meta(int index) {
    if (index >= BLOCK_NUMBER) {
        return new_block_meta();
    }

    auto self = getInstance();
    if (self->block_meta_arr[index] == nullptr) {
        return new_block_meta();
    }

    return self->block_meta_arr[index];
}


bool Memory::set_cache_block_meta(uint64_t key, int value) {
    auto self = getInstance();
    if (value < 0 || value >= BLOCK_NUMBER) {
        LOGE("Invalid block index: %d", value);
        return false;
    }
    self->cache_block_meta[key] = value;
    return true;
}

BlockMeta* Memory::get_cache_block_meta(uint64_t key) {
    auto self = getInstance();
    if (self->cache_block_meta.count(key) == 0) {
        return nullptr;
    }

    int index = self->cache_block_meta[key];
    if (index < 0 || index >= BLOCK_NUMBER) {
        LOGE("Invalid cached block index: %d", index);
        return nullptr;
    }
    return get_or_new_block_meta(index);
}

// 获取当前已使用的块数量
int Memory::get_used_block_count() {
    return getInstance()->curr_block_index;
}

// 获取剩余可用块数量
int Memory::get_available_block_count() {
    return BLOCK_NUMBER - getInstance()->curr_block_index;
}

// 检查内存池是否已初始化
bool Memory::is_initialized() {
    auto self = getInstance();
    return self->first_block_meta != nullptr && self->first_block_meta != MAP_FAILED;
}