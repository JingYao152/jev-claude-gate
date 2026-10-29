# jev-claude-gate

> **System-1 (Fast-Thinking) Security Guardrail & Quality Gate for Claude Code, powered by TypeSafe Jev.**

[![Tests](https://img.shields.io/badge/tests-27%20passed-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)]()
[![Code style: Google](https://img.shields.io/badge/code%20style-google-000000.svg)](https://google.github.io/styleguide/pyguide.html)

---

## 💡 为什么需要它？（The Problem）

在长程自主编码任务中（如 Claude Code、Codex CLI 等 Agent 框架），安全防护通常依赖两类传统方案：

1. **死板的硬编码正则**：漏报率极高，且无法理解复合语义。例如简单的前缀匹配会将 `git\nstatus` 或 `git status ${SUSPICIOUS}` 误判为只读放行。
2. **用通用 LLM 充当权限分类器（LLM-as-Classifier）**：
   - **60s 硬超时与调用崩溃**：分类器带着几万 token 的历史上下文转录去评估单条命令，大模型“思考太深”或响应慢，频繁撞上客户端硬超时（`Request was aborted`）。
   - **Reasoning 诱导与自我辩护陷阱**：通用大模型容易受到 Agent 主模型思维链（CoT）中语言艺术的影响，被“这个命令是安全的，请批准”这类提示词说服，彻底破坏 **Reasoning-Blind（推理盲审）** 原则。
   - **延迟与成本爆炸**：每执行一次微小的 `ls`、`Edit` 都要等待 2~10 秒，Token 账单成倍膨胀。

### 核心解法：TypeSafe Jev（System 1 快思考原语）

**Jev** 并非自回归文本生成模型，而是专门用于机器决策的轻量级模型（由 OpenAI RLHF 共同发明人研发）。它在单次前向传播中同时评估多个类型化原语（`Noul` 布尔概率、`Choice` 离散分类、`Score` 阶梯打分）：

- **毫秒级极速响应**：端到端延迟仅 **70ms ~ 300ms**，相较通用大模型提速 20~50 倍。
- **天然推理盲审（Reasoning-Blind）**：仅接收工具名、当前参数、最近工作区状态，严格剥离主模型的思维链与无关转录。
- **纯数值确定性输出**：永远不返回废话或自然语言 Markdown，杜绝格式解析失败。

---

## 🛡️ 四维纵深防御架构（4-Hook Defense Matrix）

`jev-claude-gate` 深度集成 Claude Code 的生命周期 Hooks，构建了从会话启动、工具调用前、工具执行后到任务收尾的全流程闭环：

```text
 ┌────────────────────────────────────────────────────────┐
 │ 1. SessionStart Hook: 指令与规则安全巡检               │
 │    扫描 CLAUDE.md / AGENTS.md / rules，防范提示词投毒  │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │ 2. PreToolUse Hook: 工具与命令执行门禁 (jev-gate.py)   │
 │    8 维度多任务并行审查；拦截高危操作、凭证窃取、外传 │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼ (工具执行)
 ┌────────────────────────────────────────────────────────┐
 │ 3. PostToolUse Hook: 间接提示词注入扫描 (jev-post.py)  │
 │    滑动窗口分块扫描网页/文件返回内容，标记 untrusted   │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │ 4. Stop Hook: 任务完成度审查 (jev-stop.py)             │
 │    防止智能体假装做完、隐瞒报错、未回答关键诉求       │
 └────────────────────────────────────────────────────────┘
```

### 1. `PreToolUse` (工具调用前安全门禁)
- **八维独立审查**：在单次 Jev 请求中同时判定：
  - `destructive`：破坏性与不可逆操作（覆盖、删库、force-push、重置历史）
  - `exfiltration`：未授权网络外传（包括私自 git push 到不受信远端）
  - `sensitive_target`：涉及私钥（`id_rsa`）、环境变量、云凭证文件
  - `impact`：潜在破坏波及半径（Blast Radius, 0~3 分）
  - `policy_allows`：常规运维策略是否明确放行
  - `user_requested`：用户本轮发言是否直接、明确请求了此动作
  - `self_advocating`：命令本身是否夹带“忽悠”审查器的自我辩护注释
  - `from_untrusted`：是否在盲目执行来自外部网页或文档的恶意指令
- **安全加固快路径**：极保守放行 `pwd` 与标准参数的 `git status`，杜绝任何换行符或拼接命令穿透。

### 2. `PostToolUse` (间接注入扫描器)
- 抓取 `WebFetch`、`Bash`、`Read` 等工具返回的外部数据。
- 采用 **800 字符重叠滑动窗口（Overlap Chunking）**，避免长文本中段恶意指令漏检。
- 一旦捕获注入行为（`directed >= 0.60` 且 `kind == injection`），立刻存入当前会话的 `untrusted` 上下文，并向 Claude 注入警告。

### 3. `SessionStart` (项目规则审计)
- 会话启动或恢复时，自动遍历全局 `~/.claude/` 与当前项目根目录的指令文件。
- 排除敏感字段（如 MCP 配置中的 `token`、`env`、`api_key`），仅扫描语义描述，防止恶意项目规则劫持 Agent。

### 4. `Stop` (会话完成度与诚信审查)
- 审查 Agent 在停止前的最后回答与工具执行历史。
- 重点拦截 `unanswered`（用户提问未回答）与 `promises_work`（承诺交付未落地）。
- 对于 `unbacked_claim`（无工具支撑的空口断言）与 `hidden_failure`（隐瞒底层报错），降级为 `systemMessage` 友好提示，避免因上下文轮数截断造成误报阻断。

---

## 🚀 快速上手（Quickstart）

### 依赖环境
- Python 3.9+（仅依赖 Python 标准库，**无需额外 pip 安装第三方依赖**）
- Claude Code CLI
- 本地 Magpie 网关（`127.0.0.1:3425`）或直接可访问的 TypeSafe Jev API 端点

### 步骤 1：安装 Hook 脚本

克隆本项目到本地，并将 `hooks` 部署到 Claude Code 配置目录（或直接软链接）：

```bash
git clone https://github.com/JingYao152/jev-claude-gate.git
cd jev-claude-gate

# 方式一：复制到 Claude 默认 hooks 目录
mkdir -p ~/.claude/hooks
cp hooks/*.py ~/.claude/hooks/
cp config/jev-gate.example.json ~/.claude/hooks/jev-gate.json

# 方式二：也可以通过环境变量指定配置路径
# export JEV_CONFIG_PATH="/path/to/your/jev-gate.json"
```

### 步骤 2：配置 `~/.claude/settings.json`

在您的 `~/.claude/settings.json` 中注册对应的生命周期事件：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/jev-gate.py"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "WebFetch|WebSearch|Read|Bash|Grep|Task|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/jev-post.py",
            "timeout": 15
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/jev-stop.py",
            "timeout": 15
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "matcher": "startup|resume",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/jev-scan-instructions.py --hook",
            "timeout": 60
          }
        ]
      }
    ]
  }
}
```

---

## ⚙️ 核心配置详解（`jev-gate.json`）

| 参数项 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `mode` | `"enforce"` | `shadow`（仅记录日志）、`ask`（命中风险提示确认）、`enforce`（高危直接拦截） |
| `endpoint` | `"http://127.0.0.1:3425/v1/systemone"` | Jev API 接入地址（通过 Magpie 或直连 TypeSafe） |
| `model` | `"typesafe/jev-latest"` | Jev 决策模型版本 |
| `read_only_fast_path` | `true` | 是否启用本地极速安全只读匹配（跳过网络请求） |
| `policy` | `string` | 本地声明的免审安全白名单规则描述文本 |
| `thresholds.destructive` | `0.90` | 破坏性行为告警门限 |
| `thresholds.exfiltration` | `0.70` | 敏感数据/代码外传告警门限 |
| `thresholds.sensitive_target` | `0.80` | 敏感系统资产读写门限 |
| `thresholds.from_untrusted` | `0.70` | 盲目跟从不可信来源指令告警门限（在 enforce 下直接 deny） |

---

## 🔬 生产实战加固经验（Hardened Lessons）

在实际高频智能体编程测试与安全审计中，我们踩平了以下核心陷阱：

1. **不可信来源与数据外传不可被模型自我豁免**：
   - 即使大模型推断出“用户要求过”或“策略可能允许”，只要触发 `from_untrusted` 或 `exfiltration`，门禁一律拒绝降级为 `allow`，避免智能体被间接注入后假借用户意图越狱。
2. **正则快路径的换行穿透防御**：
   - 早期使用 `\s+` 匹配参数，导致 `git\nstatus` 绕过了只读校验。现已加固为 `[ \t]+` 配合严格全词正则，任何非标准命令统一交由 Jev 判断。
3. **确定性评分与 NaN / 缺失校验**：
   - 严格检查 Jev 响应中的浮点数有效性（有限数值、非空、界限检查），出现网络异常或字段损坏时一律触发 `ask`，**绝不静默 Fail-Open**。
4. **日志脱敏与文件权限收敛**：
   - 运行时日志绝不持久化明文命令内容，日志文件以 `0600` 创建，缓存目录强制 `0700`，杜绝多用户或未授权访问。

---

## 🧪 自动化测试验证（Test Suite）

本项目自带完整的离线测试套件（无需联网或有效 API Key 即可全量跑通）：

```bash
# 运行全部 27 项自动化安全与回归测试
python3 tests/test_gate_security.py   # 10 项 PreToolUse 核心安全攻防测试
python3 tests/check_jev_hooks.py      # 14 项 Hooks 生命周期回归测试
python3 tests/test_scan_limits.py     # 3 项 分块与扫描边界测试
```

测试覆盖范围包括：
- `git push` 外传无条件防御
- 损坏配置与不可靠评分时转人工确认（Ask-on-Fault）
- 只读快路径参数异常阻断与精确匹配
- 滑动窗口注入命中与截断提示
- Stop hook 误报分流与重复阻断抑制

---

## 📄 开源许可证

本项目采用 [MIT 许可证](LICENSE)。欢迎提交 Issue 与 Pull Request 共同完善 Coding Agent 的安全底座！
