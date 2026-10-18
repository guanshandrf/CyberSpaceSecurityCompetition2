"""Official MCP v2 stdio server. stdout is reserved for the protocol."""
import json
import os
from pathlib import Path

from mcp.server import MCPServer

from safemcp.catalog import DOCUMENTS, DOCUMENT_ROOT, SAMPLES
from safemcp.config import ROOT

server = MCPServer("SafeMCP local fixtures")


@server.tool()
def read_document(document_id: str) -> str:
    """Read a fictional document by ID: weekly, weekly_injected, project, public, sensitive."""
    if document_id in SAMPLES:
        return SAMPLES[document_id]["tool_result_text"]
    if document_id not in DOCUMENTS:
        raise ValueError("文档 ID 不在白名单")
    return (DOCUMENT_ROOT / DOCUMENTS[document_id]).read_text(encoding="utf-8")


@server.tool()
def search_document(query: str) -> str:
    """Search fictional fixture documents by a literal keyword (1–200 characters)."""
    if not 1 <= len(query.strip()) <= 200:
        raise ValueError("查询长度必须为 1–200")
    matches = []
    for doc_id, filename in DOCUMENTS.items():
        text = (DOCUMENT_ROOT / filename).read_text(encoding="utf-8")
        if query.casefold() in text.casefold():
            matches.append(f"[{doc_id}]\n{text}")
    return "\n\n".join(matches) or "未找到匹配文档。"


@server.tool()
def send_message(recipient: str, content: str) -> str:
    """Append a SIMULATED message to local outbox. Never sends email or network requests."""
    if not recipient or len(recipient) > 254 or not content or len(content) > 4000:
        raise ValueError("模拟消息参数无效")
    directory = Path(os.environ.get("SAFEMCP_RUNTIME_DIR", str(ROOT / "runtime")))
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "outbox.jsonl").open("a", encoding="utf-8") as file:
        file.write(json.dumps({"recipient": recipient, "content": content, "simulated": True}, ensure_ascii=False) + "\n")
    return "消息已写入本地模拟 outbox；未向外部发送。"


if __name__ == "__main__":
    server.run(transport="stdio")
