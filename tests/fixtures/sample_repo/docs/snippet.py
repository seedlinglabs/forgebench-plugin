"""A documentation snippet; the scanner must skip docs/ by default (fixture)."""
from crewai import Agent

example = Agent(role="DocsOnlyAgent", goal="x", backstory="y", tools=[])
