"""A test double that declares an agent; the scanner must skip tests/ by default (fixture)."""
from crewai import Agent

fake = Agent(role="TestOnlyAgent", goal="x", backstory="y", tools=[])
