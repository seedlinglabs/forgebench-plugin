"""A CrewAI crew whose researcher uses a packaged stdio MCP server (fixture)."""

from crewai import Agent, Crew, Task
from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters

params = StdioServerParameters(
    command="npx",
    args=["-y", "@acme/papers-mcp@1.4.2"],
    env={"PAPERS_API_KEY": "FIXTURE_CODE_ENV_VALUE_must_never_upload"},
)

with MCPServerAdapter(params) as tools:
    researcher = Agent(
        role="Researcher",
        goal="Find relevant papers",
        backstory="Reads a lot.",
        tools=tools,
    )
    crew = Crew(agents=[researcher], tasks=[Task(description="research", agent=researcher)])
