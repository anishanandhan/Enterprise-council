"""
mcp_client.py — Splunk MCP (Model Context Protocol) Client

Implements MCP-compatible tool interfaces for AI agents to query
Splunk data through the Model Context Protocol.

    Agent
        ↓
    MCP Tool Call
        ↓
    Splunk Data
        ↓
    Agent Context

MCP Tools exposed:
    - query_splunk_index: Run SPL queries against a Splunk index
    - get_user_activity: Fetch all activity for a specific user
    - get_security_alerts: Fetch security alerts
    - get_infrastructure_status: Fetch infrastructure events
    - get_compliance_events: Fetch compliance audit events

When SPLUNK_PASSWORD is set, connects via REST API.
Otherwise falls back to CSV data for development.
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from splunk.splunk_client import get_client
from splunk.queries import SECURITY_EVENTS, INFRA_EVENTS, BUSINESS_EVENTS, COMPLIANCE_EVENTS


# ── MCP Protocol Structures ─────────────────────────────────────

class MCPToolDefinition:
    """Describes a tool available through MCP."""

    def __init__(self, name, description, parameters):
        self.name = name
        self.description = description
        self.parameters = parameters

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": self.parameters
            }
        }


class MCPToolResult:
    """Result of an MCP tool invocation."""

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


# ── MCP Server Implementation ───────────────────────────────────

class SplunkMCPServer:
    """
    MCP-compatible server that exposes Splunk data as tools.

    This follows the Model Context Protocol specification for
    connecting AI agents to external data sources.
    """

    def __init__(self):
        from mcp.mcp_tools import MCPToolRegistry
        from mcp.splunk_tools import register_splunk_tools, register_ai_tools
        self.client = get_client()
        self.registry = MCPToolRegistry()
        register_splunk_tools(self.registry)
        register_ai_tools(self.registry)
        self._register_compatibility_aliases()

    def _register_compatibility_aliases(self):
        from mcp.mcp_tools import MCPTool

        # query_splunk_index
        def query_splunk_index_handler(args):
            index = args.get("index", "security")
            spl_filter = args.get("spl_filter", "")
            max_results = args.get("max_results", 50)

            query_map = {
                "security": SECURITY_EVENTS,
                "infrastructure": INFRA_EVENTS,
                "business": BUSINESS_EVENTS,
                "compliance": COMPLIANCE_EVENTS,
            }
            spl = query_map.get(index, SECURITY_EVENTS)
            if spl_filter:
                spl = f"{spl} | search {spl_filter}"

            results = self.client.search(spl, max_results=max_results)
            return {
                "index": index,
                "result_count": len(results),
                "results": results
            }

        self.registry.register(MCPTool(
            name="query_splunk_index",
            description="Execute an SPL query against a Splunk index and return results",
            parameters={
                "index": {
                    "type": "string",
                    "description": "The Splunk index to query (security, infrastructure, business, compliance)",
                    "enum": ["security", "infrastructure", "business", "compliance"]
                },
                "spl_filter": {
                    "type": "string",
                    "description": "Additional SPL filter to apply (optional)"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default: 50)"
                }
            },
            handler=query_splunk_index_handler
        ))

        # get_security_alerts
        def get_security_alerts_handler(args):
            severity = args.get("severity", "")
            res = self.registry.call_tool("query_security_events", {"severity": severity})
            return {
                "alert_count": res.content.get("result_count", 0),
                "severity_filter": severity or "all",
                "alerts": res.content.get("results", [])
            }

        self.registry.register(MCPTool(
            name="get_security_alerts",
            description="Fetch recent security alerts and threat events",
            parameters={
                "severity": {
                    "type": "string",
                    "description": "Filter by severity level (optional)",
                    "enum": ["Critical", "High", "Medium", "Low"]
                }
            },
            handler=get_security_alerts_handler
        ))

        # get_infrastructure_status
        def get_infrastructure_status_handler(args):
            service = args.get("service", "")
            res = self.registry.call_tool("query_infrastructure_events", {"service": service})
            return {
                "event_count": res.content.get("result_count", 0),
                "service_filter": service or "all",
                "events": res.content.get("results", [])
            }

        self.registry.register(MCPTool(
            name="get_infrastructure_status",
            description="Fetch infrastructure health events and service status",
            parameters={
                "service": {
                    "type": "string",
                    "description": "Filter by service name (optional)"
                }
            },
            handler=get_infrastructure_status_handler
        ))

        # get_compliance_events
        def get_compliance_events_handler(args):
            risk_level = args.get("risk_level", "")
            res = self.registry.call_tool("query_compliance_events", {"risk_level": risk_level})
            return {
                "event_count": res.content.get("result_count", 0),
                "risk_filter": risk_level or "all",
                "events": res.content.get("results", [])
            }

        self.registry.register(MCPTool(
            name="get_compliance_events",
            description="Fetch compliance and audit events with policy mappings",
            parameters={
                "risk_level": {
                    "type": "string",
                    "description": "Filter by risk level (optional)",
                    "enum": ["Critical", "High", "Medium", "Low"]
                }
            },
            handler=get_compliance_events_handler
        ))

    def list_tools(self):
        """Return all available tools (MCP tools/list response)."""
        return self.registry.list_tools()

    def call_tool(self, tool_name, arguments=None):
        """
        Execute an MCP tool call (MCP tools/call handler).

        Returns MCPToolResult.
        """
        arguments = arguments or {}
        res = self.registry.call_tool(tool_name, arguments)
        return MCPToolResult(
            tool_name=tool_name,
            content=res.content,
            is_error=res.is_error
        )



# ── Convenience Function ─────────────────────────────────────────

_mcp_server = None


def get_mcp_server():
    """Get or create the singleton MCP server instance."""
    global _mcp_server
    if _mcp_server is None:
        _mcp_server = SplunkMCPServer()
    return _mcp_server


# ── Test ─────────────────────────────────────────────────────────

def run_stdio_server():
    """Run a standard-compliant stdio JSON-RPC MCP server loop with LSP-style framing support."""
    sys.stderr.write("Splunk MCP Stdio Server Started\n")
    sys.stderr.flush()

    server = get_mcp_server()

    # Expose Splunk indexes as MCP resources
    resources = [
        {
            "uri": "splunk://index/security",
            "name": "Splunk Security Index",
            "description": "Exposes recent events in the security index",
            "mimeType": "application/json"
        },
        {
            "uri": "splunk://index/infrastructure",
            "name": "Splunk Infrastructure Index",
            "description": "Exposes infrastructure telemetry and health logs",
            "mimeType": "application/json"
        }
    ]

    # Expose Agent prompts as MCP prompts
    prompts = [
        {
            "name": "security_analysis",
            "description": "Analyze a security event using Digital Twin and Splunk context",
            "arguments": [
                {"name": "user", "description": "The user involved in the event", "required": True},
                {"name": "event", "description": "The specific security event", "required": True}
            ]
        },
        {
            "name": "infrastructure_forecast",
            "description": "Analyze system impact of proposed actions using Deep Time Series predictions",
            "arguments": [
                {"name": "service", "description": "The service to analyze impact for", "required": True}
            ]
        }
    ]

    def _send_response(resp):
        payload = json.dumps(resp)
        # Handle both raw JSON newline and standard LSP framing for maximum client compatibility
        sys.stdout.write(f"Content-Length: {len(payload)}\r\n\r\n{payload}\n")
        sys.stdout.flush()

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break

            line = line.strip()
            if not line:
                continue

            # Read Content-Length if present
            if line.startswith("Content-Length:"):
                try:
                    content_length = int(line.split(":")[1].strip())
                    # Skip the subsequent empty line (\r\n)
                    sys.stdin.readline()
                    # Read body
                    body = sys.stdin.read(content_length)
                except Exception as ex:
                    sys.stderr.write(f"Error reading LSP framed header/body: {ex}\n")
                    sys.stderr.flush()
                    continue
            else:
                body = line

            if not body.strip():
                continue

            request = json.loads(body)
            method = request.get("method")
            req_id = request.get("id")

            if method == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {},
                            "resources": {},
                            "prompts": {}
                        },
                        "serverInfo": {
                            "name": "splunk-mcp-server",
                            "version": "1.0.0"
                        }
                    }
                }
                _send_response(response)

            elif method == "notifications/initialized":
                pass

            elif method == "ping":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {}
                }
                _send_response(response)

            elif method == "tools/list":
                tools_data = server.list_tools()
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": tools_data["tools"]
                    }
                }
                _send_response(response)

            elif method == "tools/call":
                params = request.get("params", {})
                tool_name = params.get("name")
                arguments = params.get("arguments", {})

                result = server.call_tool(tool_name, arguments)
                response_content = [{
                    "type": "text",
                    "text": json.dumps(result.content, indent=2)
                }]

                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": response_content,
                        "isError": result.is_error
                    }
                }
                _send_response(response)

            elif method == "resources/list":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "resources": resources
                    }
                }
                _send_response(response)

            elif method == "resources/read":
                params = request.get("params", {})
                uri = params.get("uri", "")

                index = "security"
                if "infrastructure" in uri:
                    index = "infrastructure"

                search_res = server.call_tool("query_splunk_index", {"index": index})
                content_text = json.dumps(search_res.content, indent=2)

                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "contents": [{
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": content_text
                        }]
                    }
                }
                _send_response(response)

            elif method == "prompts/list":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "prompts": prompts
                    }
                }
                _send_response(response)

            else:
                if req_id is not None:
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method not found: {method}"
                        }
                    }
                    _send_response(response)

        except Exception as e:
            sys.stderr.write(f"Error handling request: {e}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    if "--stdio" in sys.argv:
        run_stdio_server()
    else:
        print("\n  Splunk MCP Server Test")
        print("  " + "-" * 50)

        server = get_mcp_server()

        # List tools
        tools = server.list_tools()
        print(f"\n  Available MCP Tools: {len(tools['tools'])}")
        for tool in tools["tools"]:
            print(f"    • {tool['name']}: {tool['description'][:60]}...")

        # Test tool calls
        print("\n  Testing MCP Tool Calls:")
        print("  " + "-" * 50)

        # 1. Query security index
        result = server.call_tool("query_splunk_index", {"index": "security"})
        print(f"\n  query_splunk_index(security):")
        print(f"    Results: {result.content['result_count']} events")

        # 2. Get user activity
        result = server.call_tool("get_user_activity", {"username": "John"})
        print(f"\n  get_user_activity(John):")
        print(f"    Total events: {result.content['total_events']}")

        # 3. Get security alerts (Critical)
        result = server.call_tool("get_security_alerts", {"severity": "Critical"})
        print(f"\n  get_security_alerts(Critical):")
        print(f"    Alerts: {result.content['alert_count']}")

        # 4. Get infrastructure status
        result = server.call_tool("get_infrastructure_status", {"service": "CustomerDB"})
        print(f"\n  get_infrastructure_status(CustomerDB):")
        print(f"    Events: {result.content['event_count']}")

        # 5. Get compliance events
        result = server.call_tool("get_compliance_events", {"risk_level": "High"})
        print(f"\n  get_compliance_events(High):")
        print(f"    Events: {result.content['event_count']}")

        print("\n  ✓ All MCP tools operational")

