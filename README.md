# forgebench for Claude Code

Govern your AI agents, their MCP servers and their budgets with [forgebench](https://forgebench.ai), directly from Claude Code.

## Install

```bash
claude plugin marketplace add seedlinglabs/forgebench-plugin
claude plugin install forgebench@forgebench
```

Restart Claude Code, run `/mcp`, select **forgebench** and choose **Authenticate** to sign in.

## Usage

```
onboard this repo to forgebench
set Researcher's monthly budget to 40 dollars
give me a key for Researcher
```

## What's included

- **MCP server**: the hosted forgebench server, with OAuth sign-in. No API keys to configure.
- **Onboarding skill**: guides Claude through scan, review, plan and apply.
- **Repository scanner**: finds agents and MCP servers locally and uploads only a minimal summary. Requires Python 3.10+.

## Security

- Agent keys are revealed only in your browser, never in chat.
- The scanner uploads no environment values, headers or file contents, and never contacts an MCP server without your approval.
- Every change is shown as a plan and applied only after you confirm.

## Configuration

The plugin connects to `https://api.forgebench.ai/mcp`. To use another deployment, set `FORGEBENCH_MCP_URL` before starting Claude Code.

## Uninstall

```bash
claude plugin uninstall forgebench@forgebench
claude plugin marketplace remove forgebench
```
