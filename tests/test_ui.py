from streamlit.testing.v1 import AppTest
from safemcp.config import ROOT


def test_chat_and_message_trace(monkeypatch):
    monkeypatch.setenv("SAFEMCP_MODE", "demo")
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=20).run()
    assert not app.exception
    app.chat_input[0].set_value("你好").run()
    assert not app.exception
    assert len(app.chat_message) == 2
    assert "本轮未调用 MCP 工具" in str(app)
    assert len(app.session_state["messages"]) == 2
