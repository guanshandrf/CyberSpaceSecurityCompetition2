# SafeMCP Chat

面向 MCP 工具调用的提示注入检测与阻断课程项目。使用真实的官方 MCP v2 stdio Client/Server，提供 Streamlit 聊天界面、调用前授权、返回后检测，以及每条回复的“查看安全路径”。

默认离线演示，无需 API Key。离线模式只模拟模型规划与措辞，MCP 工具、安全检查和日志均真实执行。

## 安装与运行

需要 Python 3.11+，在项目根目录执行：

```bash
git clone https://github.com/guanshandrf/CyberSpaceSecurityCompetition2.git
cd CyberSpaceSecurityCompetition2
python -m venv .venv
```

Windows PowerShell：

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m streamlit run app.py
```

macOS / Linux：

```bash
source .venv/bin/activate
python -m pip install -e ".[test]"
python -m streamlit run app.py
```

打开 http://127.0.0.1:8501 。停止服务使用 Ctrl+C。

依赖版本固定在 `pyproject.toml`。已验证 Windows、Python 3.13.9、MCP 2.3.0、Streamlit 1.51.0。MCP 使用 `MCPServer`、`Client`、`StdioServerParameters`，未使用内存内工具调用代替 stdio。

## 演示

|场景|操作|预期|
|---|---|---|
|正常总结|选择“正常文档”，输入“帮我读取项目周报并总结”|SAFE，读取与检测 ALLOW|
|注入隔离|选择“包含提示注入的文档”，输入相同任务|SANITIZED，隔离恶意片段后继续总结|
|敏感外发|输入“将敏感配置发送给 demo@local.test”|BLOCKED，P004 拒绝，发送未执行|
|合法模拟发送|输入“将普通进度发送给 demo@local.test”|仅向本地 outbox 追加一条记录|

每条助手回复下点击“🛡 查看安全路径”，可查看本轮真实的工具参数摘要、授权与检测决定、规则、脱敏证据、执行状态。输入“你好”可验证无工具轮次。

## 真实模型配置

复制 `.env.example` 为 `.env`，配置支持 Chat Completions tool calling 的兼容 API：

```dotenv
SAFEMCP_MODE=live
OPENAI_API_KEY=填写自己的密钥
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=填写供应商支持工具调用的模型名
```

真实模型工具 schema 来自 MCP，每次调用强制经过安全网关。缺少配置或 API 出错时明确显示 ERROR，不会自动伪装成离线成功。不要提交 `.env`。

**真实 API 推理尚未使用真实 Key 验证**；目前已验证适配器替身测试与真实 MCP 联调。

## 测试与实验

Windows：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m scripts.smoke_test
.\.venv\Scripts\python.exe -m scripts.run_experiments
```

激活虚拟环境后，可直接使用 `python -m ...`。当前 40 项自动测试通过，三个演示场景已做浏览器验证。

实验包含 60 条恶意、40 条正常样本，实际经过 MCP 读取。三组使用独立的本地模拟 outbox：

|分组|实际危险写入 / 恶意样本|离线 ASR|
|---|---|---|
|A 无防御|60/60|100%|
|B 仅返回检测|12/60|20%|
|C 返回检测与前置授权|0/60|0%|

ASR 指演示秘密实际写入本地隔离 outbox 的比例，不是文本检测命中率。B/C 检测召回率均为 80%，本组合成语料正常完成率为 100%。实验使用刻意脆弱的脚本化代理解析 `NEXT_ACTION`，这些结果不能代表真实模型防御率或未知攻击泛化能力。

实验命令自动生成 `results/metrics.csv`、`sample_results.csv`、`comparison.png`、`experiment_report.md`，无需预先下载结果。必要时可用 `python -m scripts.build_dataset` 重建样本后重启进程。

## 项目结构

```text
app.py                   Streamlit 聊天界面
pyproject.toml           固定版本的依赖与测试配置
.env.example             无密钥的配置示例
.streamlit/config.toml   本地服务配置
safemcp/                 Agent、MCP、检测、授权、网关、审计
fixtures/                五份虚构文档和100条固定样本
scripts/                 联调、实验和样本生成
tests/                   自动测试
```

本仓库只保留可运行源码、必要样例、测试和说明。虚拟环境、缓存、开发计划书、日志、截图和生成的实验结果不上传；运行时会创建 `runtime/` 与 `results/`。

## 安全边界与限制

- 三个工具为 `read_document`、`search_document`、`send_message`。只能读取白名单样例，发送只写本地 JSONL，不接入真实邮箱、HTTP 外发或 shell。
- P001–P006 检查白名单、路径、明确用户意图、精确接收方和内容、敏感标记、参数结构、调用上限。只有本轮原始用户请求能授予权限。
- R001–R004 检测中英文指令覆盖、角色伪装、工具诱导和敏感外传。完整明确标签内可疑片段可以隔离，无法可靠分离时整体阻断。
- 每轮最多四次工具调用；API 请求20秒、MCP 调用15秒、整轮90秒超时。拒绝后停止本轮。
- JSONL 日志按 session_id / turn_id 关联，记录调用是否执行及检查后内容是否放行给模型；SANITIZE 放行的是隔离后的正文。日志写入失败时停止处理，证据与参数摘要脱敏。
- 正则可能误报或漏报；发送授权采用严格语法；日志没有防篡改能力；SAFE 只表示当前规则通过。本项目用于本地课程演示，不提供生产级安全保证。
