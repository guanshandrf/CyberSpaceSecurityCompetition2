import re

from safemcp.catalog import DEMO_SECRET, DOCUMENT_IDS, SAFE_RECIPIENTS
from safemcp.models import SecurityDecision


def explicit_send(request: str):
    """Narrow deterministic grammar from ORIGINAL user input only; never accepts model flags."""
    patterns = [
        r"(?:请)?(?:将|把)(?P<content>[^\n]+?)(?:发送给|发给)\s*(?P<recipient>[\w.+-]+@[\w.-]+)\s*[。.!！]?",
        r"(?:please\s+)?send\s+(?P<content>[^\n]+?)\s+to\s+(?P<recipient>[\w.+-]+@[\w.-]+)\s*[.!]?",
    ]
    for pattern in patterns:
        match = re.fullmatch(pattern, request.strip(), re.I)
        if match:
            return {"recipient": match["recipient"].rstrip("."), "content": match["content"].strip()}
    return None


def contains_sensitive(text):
    return bool(re.search(r"SENSITIVE_CONFIG|DEMO_SECRET|api[_-]?key|密钥|敏感配置|凭据|sk-[\w-]+", text, re.I)
                or DEMO_SECRET in text)


class PreToolPolicy:
    def check(self, name: str, args: dict, trusted_request: str):
        def deny(rule, reason):
            return SecurityDecision("pre_tool_call", "DENY", "high", [rule], reason, tool_name=name)

        schemas = {"read_document": {"document_id"}, "search_document": {"query"}, "send_message": {"recipient", "content"}}
        if name not in schemas:
            return deny("P001", "工具不在白名单中，未执行。")
        if not isinstance(args, dict) or set(args) != schemas[name] or not all(isinstance(v, str) for v in args.values()):
            return deny("P005", "参数结构无效或包含未允许字段，未执行。")
        if name == "read_document" and args["document_id"] not in DOCUMENT_IDS:
            return deny("P002", "文档 ID 不在白名单中，禁止路径穿越或任意文件读取。")
        if name == "search_document" and not 1 <= len(args["query"].strip()) <= 200:
            return deny("P005", "检索关键词长度必须为 1–200。")
        if name == "send_message":
            if contains_sensitive(args["content"]):
                return deny("P004", "内容包含演示敏感配置或密钥标记，禁止外发。")
            intent = explicit_send(trusted_request)
            if (not intent or intent != args or args["recipient"] not in SAFE_RECIPIENTS
                    or not 1 <= len(args["content"]) <= 4000):
                return deny("P003", "需要原始用户明确发送指令，且接收方与内容必须精确匹配安全白名单授权。")
        return SecurityDecision("pre_tool_call", "ALLOW", tool_name=name)
