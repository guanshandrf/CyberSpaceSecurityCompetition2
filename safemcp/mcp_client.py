import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from mcp import Client
from mcp.client.stdio import StdioServerParameters

from safemcp.config import ROOT


class MCPClient:
    """Each connection launches a separate official stdio server process."""

    def __init__(self, runtime_dir: Path | None = None):
        self.runtime_dir = runtime_dir or ROOT / "runtime"
        self.client = None

    @asynccontextmanager
    async def connect(self):
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "safemcp.mcp_server"], cwd=ROOT,
            env={**os.environ, "PYTHONUTF8": "1", "SAFEMCP_RUNTIME_DIR": str(self.runtime_dir.resolve())},
        )
        async with Client(params, read_timeout_seconds=15) as client:
            self.client = client
            try:
                yield self
            finally:
                self.client = None

    async def list_tools(self):
        if self.client is None:
            raise RuntimeError("MCP 未连接")
        return (await self.client.list_tools()).tools

    async def call_tool(self, name, arguments):
        if self.client is None:
            raise RuntimeError("MCP 未连接")
        result = await self.client.call_tool(name, arguments, read_timeout_seconds=15)
        if result.is_error:
            raise RuntimeError("MCP 工具执行失败；参数可能不符合工具约束。")
        return "\n".join(block.text for block in result.content if block.type == "text")
