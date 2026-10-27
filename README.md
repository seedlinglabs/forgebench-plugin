# forgebench plugin for Claude Code

Connects Claude Code to the **hosted forgebench MCP server** and adds what the
server cannot ship by itself:

| Part | Path | What it does |
|---|---|---|
| MCP server entry | `.mcp.json` | An HTTP server named `forgebench` at `${FORGEBENCH_MCP_URL:-https://api.forgebench.ai/mcp}`. Sign-in is OAuth in the browser; no API key is configured anywhere. |
| Onboarding skill | `skills/forgebench-onboarding/SKILL.md` | The scan, review, plan and apply flow, budgets and limits, and browser-only agent keys. Loaded when you ask Claude to onboard a repo, change a budget or get an agent key. |
| Integration skill | `skills/forgebench-integrate/SKILL.md` | Integrating forgebench into a developer's own app: the gateway base URL, env vars, request parameters, metadata, sessions, streaming, error handling, agent keys and tool gating, using the `forgebench_integrate recipe` tool and checking the result with `forgebench_integrate verify`. |
| Local scanner | `scripts/forgebench_scan.py` | Finds agents and MCP servers in a repository and uploads a minimal `forgebench.scan/v1` payload straight to forgebench with a single-use ticket. Prints only counts and a sha256. Needs Python 3.10+. |
| Manifests | `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` | The plugin, and a one-plugin marketplace so this directory can be added as a marketplace. |

The server-side design, threat model and an end-to-end test runbook are in
[`docs/HOSTED-MCP.md`](../../docs/HOSTED-MCP.md).

## Install for local testing

You need a running control plane (the local stack serves it at
`http://localhost:8000`) and Claude Code. The plugin connects to dev by
default, so point it at the local stack first. From the repository root:

```bash
export FORGEBENCH_MCP_URL=http://localhost:8000/mcp
claude plugin marketplace add ./packages/forgebench-plugin
claude plugin install forgebench@forgebench
```

The same works inside a session with `/plugin marketplace add ./packages/forgebench-plugin`
and `/plugin install forgebench@forgebench`. A marketplace added from a local
directory loads the plugin in place, so edits to the skill take effect after
`/reload-plugins`.

Then sign in once:

1. Start `claude` and run `/mcp`.
2. Select the forgebench server (listed as coming from the plugin) and choose
   **Authenticate**.
3. In the browser: sign in (locally `demo@acme.test` / `ForgeDemo!2026`), pick a
   workspace if you belong to more than one, and approve access on the consent
   page. The browser hands control back to Claude Code; the token lives in your
   OS keychain.

Try it: *"onboard this repo to forgebench"*, *"set Researcher's monthly budget
to 40 dollars"*, *"give me a key for Researcher"*. The server's prompts
`onboard_repo`, `set_up_budgets` and `org_rollout_status` also appear in the
`/` menu, marked (MCP).

### Server only (no skill, no scanner)

```bash
claude mcp add --transport http forgebench https://api.forgebench.ai/mcp
```

Every tool works, but there is no onboarding skill and no local scanner (the
model can only fall back to `forgebench_onboarding` with action `submit_inline`). If you add both,
Claude Code treats the plugin's server and yours as one server as long as they
point at the same URL.

### Point the plugin at another deployment

The URL in `.mcp.json` is `${FORGEBENCH_MCP_URL:-https://api.forgebench.ai/mcp}`:
Claude Code expands environment variables, with a `:-` default, in an MCP
server's `url`. Set the variable before starting Claude Code:

```bash
export FORGEBENCH_MCP_URL=http://localhost:8000/mcp
claude
```

If your Claude Code version shows the literal `${FORGEBENCH_MCP_URL...}` text
for the server in `/mcp`, it does not expand the variable: disable the plugin's
server there and use the server-only command above with the URL instead.

Organizations do not need either step: an admin gets managed settings that
deliver the server and this plugin to every developer from
`forgebench_rollout_kit` (see [`docs/HOSTED-MCP.md`](../../docs/HOSTED-MCP.md)).

## Tool names and permissions

Plugin-provided tools are named `mcp__plugin_forgebench_forgebench__<tool>`
(for example `mcp__plugin_forgebench_forgebench__forgebench_whoami`); a server
added with `claude mcp add` uses `mcp__forgebench__<tool>`. Use those names in
permission rules. `forgebench_apply_plan` always asks for confirmation, even
with permissive settings: the server marks it as requiring user interaction.

## What the plugin never does

- It never asks for, stores or prints an API key. Agent keys are revealed once
  on a forgebench page in your browser.
- The scanner uploads only with the single-use ticket `forgebench_onboarding`
  (action `begin_scan`) returns (write-only, one scan, 30 minutes). It sends no environment or header
  values, no library inventory and no OS details.
- The scanner does not start or contact any MCP server unless you name that
  server for its dial option.
- Nothing is approved from chat: console confirmations and approval requests
  are decided by people in the forgebench console.

## Check, update, remove

```bash
claude plugin validate ./packages/forgebench-plugin       # manifest and skill checks
claude plugin uninstall forgebench@forgebench
claude plugin marketplace remove forgebench
```
