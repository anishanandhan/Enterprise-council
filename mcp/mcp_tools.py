"""
mcp_tools.py — MCP Tool Registry and Execution Framework

Defines the Model Context Protocol tool interface that agents
use to request data from external systems (Splunk, Digital Twin).

    Agent
        ↓
    MCP Tool Call
        ↓
    Tool Registry
        ↓
    Execution
        ↓
    Result

This is the protocol layer. Actual tool implementations live
in splunk_tools.py and context_provider.py.
"""

import time


class MCPTool:
    """Definition of a single MCP-compatible tool."""

    def __init__(self, name, description, parameters, handler):
        self.name = name
        self.description = description
        self.parameters = parameters
        self.handler = handler

    def to_schema(self):
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": self.parameters
            }
        }


class MCPResult:
    """Result of an MCP tool execution."""

    def __init__(self, tool_name, content, is_error=False):
        self.tool_name = tool_name
        self.content = content
        self.is_error = is_error
        self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def to_dict(self):
        return {
            "toolName": self.tool_name,
            "content": self.content,
            "isError": self.is_error,
            "timestamp": self.timestamp
        }


class MCPToolRegistry:
    """
    Central registry for all MCP tools.

    Implements the MCP server-side protocol:
        - tools/list  → list_tools()
        - tools/call  → call_tool(name, args)
    """

    def __init__(self):
        self._tools = {}
        self._call_log = []

    def register(self, tool):
        """Register an MCPTool instance."""
        self._tools[tool.name] = tool

    def list_tools(self):
        """MCP tools/list — return all tool schemas."""
        return {
            "tools": [t.to_schema() for t in self._tools.values()]
        }

    def call_tool(self, name, arguments=None):
        """
        MCP tools/call — execute a tool by name.

        Returns MCPResult.
        """
        arguments = arguments or {}

        if name not in self._tools:
            return MCPResult(
                tool_name=name,
                content={"error": f"Unknown tool: {name}"},
                is_error=True
            )

        tool = self._tools[name]

        try:
            result = tool.handler(arguments)

            self._call_log.append({
                "tool": name,
                "arguments": arguments,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "success": True
            })

            return MCPResult(tool_name=name, content=result)

        except Exception as e:
            self._call_log.append({
                "tool": name,
                "arguments": arguments,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "success": False,
                "error": str(e)
            })

            return MCPResult(
                tool_name=name,
                content={"error": str(e)},
                is_error=True
            )

    def get_call_log(self):
        """Return the history of all MCP tool calls."""
        return self._call_log


class MCPResource:
    """Definition of an MCP-compatible resource."""

    def __init__(self, uri, name, description, mime_type, handler):
        self.uri = uri
        self.name = name
        self.description = description
        self.mime_type = mime_type
        self.handler = handler

    def to_schema(self):
        return {
            "uri": self.uri,
            "name": self.name,
            "description": self.description,
            "mimeType": self.mime_type
        }


class MCPPrompt:
    """Definition of an MCP-compatible prompt template."""

    def __init__(self, name, description, arguments, template):
        self.name = name
        self.description = description
        self.arguments = arguments  # list of dicts: {"name": str, "description": str, "required": bool}
        self.template = template

    def to_schema(self):
        return {
            "name": self.name,
            "description": self.description,
            "arguments": self.arguments
        }

