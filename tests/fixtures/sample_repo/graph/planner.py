"""A LangGraph agent wired to two MCP servers through langchain-mcp-adapters (fixture)."""

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent


async def build(model):
    client = MultiServerMCPClient(
        {
            "papers": {"command": "python3", "args": ["servers/papers_server.py"], "transport": "stdio"},
            "weather": {
                "url": "https://mcp.weather.example.test/mcp",
                "transport": "streamable_http",
                "headers": {"Authorization": "Bearer FIXTURE_CODE_HEADER_VALUE_must_never_upload"},
            },
        }
    )
    tools = await client.get_tools()
    planner = create_react_agent(model, tools)
    return planner
