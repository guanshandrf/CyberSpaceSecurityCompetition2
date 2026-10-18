"""Heuristic evidence, never proof of compromise. Unlabeled hits block the whole result."""
import re
import unicodedata
from dataclasses import dataclass

from safemcp.audit import redact
from safemcp.models import SecurityDecision


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    reason: str
    pattern: str


RULES = [
    Rule("R001", "指令覆盖", "high", "工具文本要求覆盖原有指令",
         r"(?:忽略|无视|忘记|丢弃).{0,16}(?:之前|前面|原有|用户|所有).{0,12}(?:指令|要求|任务)|(?:ignore|disregard|forget).{0,24}(?:previous|prior|user|all).{0,16}(?:instructions?|requests?|tasks?)"),
    Rule("R002", "角色伪装", "high", "工具文本伪装高权限角色或授权来源",
         r"你(?:现在)?是.{0,10}(?:系统管理员|系统|开发者)|system\s*override|(?:you are|act as).{0,16}(?:system|administrator|developer)|(?:用户已授权|user has authorized).{0,40}(?:发送|工具|send|tool)"),
    Rule("R003", "工具诱导", "high", "工具文本诱导 Agent 执行额外工具调用",
         r"(?:请|立即|必须|现在|然后|应当).{0,24}(?:调用|执行).{0,40}(?:send_message|read_document|search_document)|(?:call|invoke|execute|run).{0,20}(?:send_message|read_document|search_document)"),
    Rule("R004", "敏感外传", "high", "工具文本要求复制或外发配置、凭据等敏感数据",
         r"(?:复制|发送|外传|上传|传出).{0,30}(?:配置|密钥|凭据|秘密)|(?:把|将).{0,20}(?:配置|密钥|凭据|秘密).{0,20}(?:发|传)|(?:send|copy|upload|exfiltrate).{0,40}(?:config|secret|credential|api.?key)"),
]
BEGIN = "<!-- BEGIN_UNTRUSTED_INJECTION -->"
END = "<!-- END_UNTRUSTED_INJECTION -->"
BLOCK = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)


class PostToolDetector:
    def _hits(self, text):
        # Exempt only complete quoted teaching lines with an explicit non-execution disclaimer.
        # Imperatives outside the quotation are still checked.
        hits = []
        for line in unicodedata.normalize("NFKC", text).splitlines():
            quoted = re.fullmatch(r'.*(?:教材|安全分析|文献|Teaching|Security analysis).*?[「“\"].+?[」”\"][。. ]*(?:这是|仅用于|This is).*(?:分析|讨论|不是|not an instruction|do not execute).*', line, re.I)
            if quoted:
                # A teaching prefix never suppresses text outside its single quoted span.
                line = re.sub(r'[「“\"].*?[」”\"]', '', line, count=1)
            for rule in RULES:
                match = re.search(rule.pattern, line, re.I)
                if match:
                    hits.append((rule, match.group()))
        return hits

    def inspect(self, text: str, tool_name: str):
        hits = self._hits(text)
        if not hits:
            return SecurityDecision("post_tool_result", "ALLOW", tool_name=tool_name), text
        remaining = BLOCK.sub("", text)
        valid_blocks = (text.count(BEGIN) == text.count(END) == len(BLOCK.findall(text))
                        and len(BLOCK.findall(text)) > 0)
        sanitized = valid_blocks and not self._hits(remaining)
        decision = SecurityDecision(
            "post_tool_result", "SANITIZE" if sanitized else "BLOCK_RESULT", "high",
            sorted({r.id for r, _ in hits}),
            "；".join(dict.fromkeys(r.reason for r, _ in hits)) +
            ("；已隔离明确标签内的内容。" if sanitized else "；无法可靠分离，已阻断整个返回结果。"),
            redact(" | ".join(e for _, e in hits)), tool_name,
        )
        return decision, remaining.strip() if sanitized else "工具返回内容被安全模块隔离，无法安全使用。"
