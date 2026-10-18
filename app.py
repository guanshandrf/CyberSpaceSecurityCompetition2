import json
from dataclasses import asdict

import streamlit as st

from safemcp.agent import chat
from safemcp.config import Settings
from safemcp.models import uid

st.set_page_config(page_title="SafeMCP Chat", page_icon="🛡", layout="centered")
st.markdown("""<style>
.block-container {max-width: 860px; padding-top: 2rem;}
[data-testid="stChatMessage"] {border-radius:16px; margin-bottom:1rem;}
footer {visibility:hidden;}
</style>""", unsafe_allow_html=True)

if "session_id" not in st.session_state:
    st.session_state.session_id = uid("session")
    st.session_state.messages = []

settings = Settings.from_env()
with st.sidebar:
    st.header("SafeMCP Chat")
    st.caption("MCP 工具调用安全 · 课程工程")
    mode = st.radio("运行模式", ["演示模式（离线）", "真实 LLM"], index=1 if settings.mode == "live" else 0)
    scene = st.selectbox("演示场景", ["正常文档", "包含提示注入的文档"])
    st.caption("演示模式仅模拟模型规划；工具仍通过官方 MCP v2 stdio 运行。")
    st.markdown("**试试这些任务**\n\n帮我读取项目周报并总结\n\n将敏感配置发送给 demo@local.test\n\n将普通进度发送给 demo@local.test")
    if st.button("新对话"):
        st.session_state.session_id = uid("session")
        st.session_state.messages = []
        st.rerun()

st.title("SafeMCP Chat")
st.caption("你的本地项目助手 · 每次工具调用都有可追溯的安全路径")
if mode.startswith("演示"):
    st.info("演示模式：确定性脚本规划与回复，使用真实 MCP 工具和安全检查。")
else:
    st.caption("真实 LLM 模式：使用 .env 配置的兼容 API；调用仍强制经过安全网关。")


def render_assistant(result):
    st.markdown(result["answer"])
    labels = {"SAFE": "安全检查通过（限当前规则）", "SANITIZED": "已隔离不可信工具片段", "BLOCKED": "本次风险操作或返回内容已被阻断", "ERROR": "处理异常，请查看安全路径"}
    st.caption(f"🛡 {labels[result['status']]} · {result['elapsed_ms'] / 1000:.2f}s")
    with st.popover("🛡 查看安全路径", use_container_width=True):
        st.caption(f"会话 {result['session_id']}\n\n轮次 {result['turn_id']}")
        events = [e for e in result["events"] if e["session_id"] == result["session_id"] and e["turn_id"] == result["turn_id"]]
        if not any(e["phase"] == "pre_tool_call" for e in events):
            st.write("本轮未调用 MCP 工具。")
        for event in events:
            st.markdown(f"**{event['decision']} · {event['phase']}**")
            st.caption(event["timestamp"])
            if event["tool_name"]:
                st.write("工具：", event["tool_name"])
                st.code(event["arguments_preview"], language="json")
            st.write(event["reason"])
            if event["rule_ids"]:
                st.write("命中规则：", ", ".join(event["rule_ids"]))
            if event["evidence_preview"]:
                st.code(event["evidence_preview"], language=None)
            if event["tool_name"]:
                st.caption(f"来源：{event['source_type']} · 调用已执行：{event['tool_call_executed']} · 检查后内容放行给模型：{event['result_exposed_to_llm']}")
            st.divider()
        st.download_button("下载本轮审计", json.dumps(events, ensure_ascii=False, indent=2),
                           file_name=result["turn_id"] + ".json", key="download_" + result["turn_id"])


for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        if msg["role"] == "assistant":
            render_assistant(msg["result"])
        else:
            st.markdown(msg["content"])

if prompt := st.chat_input("发送消息给 SafeMCP Chat…", max_chars=8000):
    history = [{"role": m["role"], "content": m["content"]} for m in st.session_state.messages]
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)
    selected = Settings("demo" if mode.startswith("演示") else "live", settings.api_key, settings.base_url, settings.model)
    with st.chat_message("assistant"):
        with st.spinner("正在处理并记录安全路径…"):
            result = asdict(chat(prompt, st.session_state.session_id, history=history,
                                 scene="injected" if scene.startswith("包含") else "normal", settings=selected))
        render_assistant(result)
    st.session_state.messages.append({"role": "assistant", "content": result["answer"], "result": result})
