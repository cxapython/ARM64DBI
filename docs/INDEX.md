# ARM64DBI 文档索引

> 快速导航到各个文档模块

## 📚 文档目录

### 核心文档

| 文档 | 描述 | 适合人群 |
|------|------|----------|
| [README.md](../README.md) | 项目概述、系统架构、API参考 | 所有用户 |
| [LEARNING_GUIDE.md](../LEARNING_GUIDE.md) | 从零开始的学习指南 | 初学者 |
| [TAINT_ANALYSIS.md](../TAINT_ANALYSIS.md) | 污点分析模块使用指南 | 安全研究员 |

### 技术文档 (docs/)

| 文档 | 描述 | 适合人群 |
|------|------|----------|
| [CONDITIONAL_BRANCH_FIX.md](./CONDITIONAL_BRANCH_FIX.md) | 条件分支翻译修复详解 | 框架开发者 |
| [AES_TRACE_DEBUG_REPORT.md](./AES_TRACE_DEBUG_REPORT.md) | AES追踪问题排查报告 | 框架开发者 |
| [CHANGELOG.md](./CHANGELOG.md) | 版本更新日志 | 所有用户 |

---

## 🔍 按功能查找

### DBI 基础使用

- 如何开始使用 DBI？→ [LEARNING_GUIDE.md - 快速入门](../LEARNING_GUIDE.md#4-快速入门)
- DBI::trace() 怎么用？→ [README.md - API参考](../README.md#api-参考)
- 回调函数怎么写？→ [README.md - 使用示例](../README.md#使用示例)

### 污点分析

- 什么是污点分析？→ [TAINT_ANALYSIS.md - 原理](../TAINT_ANALYSIS.md#污点分析原理)
- 如何追踪加密算法？→ [TAINT_ANALYSIS.md - AES白盒DFA](../TAINT_ANALYSIS.md#实战案例aes白盒dfa攻击定位)
- 污点传播规则？→ [TAINT_ANALYSIS.md - 传播规则](../TAINT_ANALYSIS.md#污点传播规则)

### 问题排查

- 追踪时密文不正确？→ [AES_TRACE_DEBUG_REPORT.md](./AES_TRACE_DEBUG_REPORT.md)
- 条件分支崩溃？→ [CONDITIONAL_BRANCH_FIX.md](./CONDITIONAL_BRANCH_FIX.md)
- 常见问题FAQ？→ [LEARNING_GUIDE.md - 常见问题](../LEARNING_GUIDE.md#8-常见问题)

### 框架开发

- 核心组件架构？→ [README.md - 系统架构](../README.md#系统架构)
- 指令翻译原理？→ [README.md - 工作原理](../README.md#工作原理)
- 如何添加新指令支持？→ [LEARNING_GUIDE.md - 实战练习](../LEARNING_GUIDE.md#7-实战练习)

---

## 📖 推荐阅读顺序

### 新手入门

```
1. README.md (项目简介)
       ↓
2. LEARNING_GUIDE.md (前置知识 → 快速入门)
       ↓
3. README.md (使用示例)
       ↓
4. TAINT_ANALYSIS.md (高级功能)
```

### 安全研究员

```
1. README.md (了解框架)
       ↓
2. TAINT_ANALYSIS.md (污点分析原理 → 使用示例)
       ↓
3. AES白盒DFA攻击定位案例
       ↓
4. 实战应用
```

### 框架开发者

```
1. README.md (系统架构 → 核心组件详解)
       ↓
2. LEARNING_GUIDE.md (深入理解)
       ↓
3. CONDITIONAL_BRANCH_FIX.md (理解翻译器修复)
       ↓
4. AES_TRACE_DEBUG_REPORT.md (理解回调函数限制)
       ↓
5. 阅读源码
```

---

## 📁 项目源码结构

```
app/src/main/cpp/
├── main.cpp                 # 测试入口和示例代码
├── types/
│   └── types.h              # 基础类型定义
└── dbi/
    ├── DBI.h/cpp            # ★ 核心控制器入口
    ├── Translator.h/cpp     # ★ 指令翻译器（核心）
    ├── Assembler.h/cpp/S    # ARM64 汇编生成
    ├── Router.h/cpp/S       # 控制流路由
    ├── Memory.h/cpp         # 内存管理
    ├── Utils.h/cpp          # 工具函数
    ├── Taint.h/cpp          # 污点分析模块
    ├── DataTracer.h/cpp     # 数据溯源模块
    ├── AESWhitebox.h/cpp    # AES白盒实现（演示用）
    └── AES_DFA_Demo.h/cpp   # DFA攻击演示
```

---

## 🏷️ 版本信息

| 版本 | 日期 | 主要更新 |
|------|------|----------|
| v1.2.0 | 2024-12-10 | 修复追踪问题、完善文档 |
| v1.1.0 | 2024-12-09 | 新增DFA攻击定位、数据溯源 |
| v1.0.0 | 初始版本 | 基础DBI框架、污点分析 |

详细更新日志请查看 [CHANGELOG.md](./CHANGELOG.md)

---

## 🔗 外部资源

- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest)
- [Capstone Disassembly Framework](https://www.capstone-engine.org/)
- [项目 GitHub](https://github.com/lidongyooo/ARM64DBI)

---

*最后更新: 2024-12-10*

