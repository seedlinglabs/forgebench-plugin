# forgebench plugin for Claude Code

Connects Claude Code to the **hosted forgebench MCP server** and adds what the
server cannot ship by itself:

| Part | Path | What it does |
|---|---|---|
| MCP server entry | `.mcp.json` | An HTTP server named `forgebench` at the fixed URL `https://api.forgebench.ai/mcp` (hard-coded, not configurable). Sign-in is OAuth in the browser; no API key is configured anywhere. |
| Onboarding skill | `skills/forgebench-onboarding/SKILL.md` | The scan, review, plan and apply flow, budgets and limits, and browser-only agent keys. Loaded when you ask Claude to onboard a repo, change a budget or get an agent key. |
| Integration skill | `skills/forgebench-integrate/SKILL.md` | Integrating forgebench into a developer's own app: the gateway base URL, env vars, request parameters, metadata, sessions, streaming, error handling, agent keys and tool gating, using the `forgebench_integrate recipe` tool and checking the result with `forgebench_integrate verify`. |
| Local scanner | `scripts/forgebench_scan.py` | Finds agents and MCP servers in a repository and uploads a minimal `forgebench.scan/v1` payload straight to forgebench with a single-use ticket. Prints only counts and a sha256. Needs Python 3.10+. |
| Sync hooks | `hooks/hooks.json`, `scripts/forgebench_sync_launcher.py` | Three exec-form hooks (SessionStart, SessionEnd, and PostToolUse for the `Skill` matcher) run the launcher, which starts `forgebench sync --quiet --url <url>` fully detached (double fork) and returns at once, inside the fixed 1.5 s SessionEnd budget. With the `sync` option off it exits before reading anything. POSIX only (#1060); without `fork`/`setsid` the launcher exits without syncing, and the Windows detach is #1146. Needs the `forgebench` CLI (see the `forgebench_cli_path` option). |
| Options | `userConfig` in `.claude-plugin/plugin.json` | `forgebench_url` (default `https://api.forgebench.ai`, where sync uploads), `forgebench_cli_path` (default `forgebench`, found on `PATH` or in `~/.local/bin`), `sync` (Boolean, default on) and `mcp_url` (no longer used: the MCP URL is fixed; kept so existing managed settings stay valid). None is sensitive. |
| Manifests | `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` | The plugin, and a one-plugin marketplace so this directory can be added as a marketplace. |

The server-side design, threat model and an end-to-end test runbook are in
[`docs/HOSTED-MCP.md`](../../docs/HOSTED-MCP.md).

## Install for local testing

You need a running control plane (the local stack serves it at
`http://localhost:8000`) and Claude Code. The plugin connects to production
(`https://api.forgebench.ai`) by default. Session sync can be pointed at the local stack
with `forgebench_url`; the bundled MCP server is fixed to `https://api.forgebench.ai/mcp`
and cannot be redirected. From the repository root:

```bash
claude plugin marketplace add ./packages/forgebench-plugin
claude plugin install forgebench@forgebench \
  --config forgebench_url=http://localhost:8000
```

Claude Code also prompts for the options when you install from `/plugin`.

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

The sync hooks read the `forgebench_url` option (no trailing slash). The MCP
server URL is **hard-coded** to `https://api.forgebench.ai/mcp` in `.mcp.json`:
the Claude desktop app does not apply `userConfig` defaults, so a
`${user_config.*}` reference there resolved to an empty URL and the connector
never connected. The `mcp_url` option is therefore ignored (it is kept only so
existing managed settings that set it stay valid). Dev and staging editions
published from `develop` and `staging` get their own `/mcp` URL written into the
staged `.mcp.json` at release time.

To sync to a custom or on-premises deployment:

```bash
claude plugin marketplace add seedlinglabs/forgebench-plugin
claude plugin install forgebench@forgebench \
  --config forgebench_url=https://forgebench.example.com
```

For an existing installation:

```bash
echo '{"forgebench_url":"https://forgebench.example.com"}' | claude plugin configure forgebench@forgebench --values-stdin
```

This redirects sync only. A self-hosted deployment that needs the MCP server
must register it directly (for example `claude mcp add --transport http
forgebench https://forgebench.example.com/mcp`) or use its own plugin build with
that URL in `.mcp.json`. Then choose **forgebench → Authenticate** in `/mcp`.
Claude Code discovers OAuth from the deployment; it needs no API key, client
secret, or separate client registration. The deployment administrator must
configure the externally reachable HTTPS API origin (`NEXT_PUBLIC_API_URL`, or
Helm `config.publicApiUrl`), the identity provider, and a stable `STUDIO_KEK`
shared across replicas. Both `/.well-known/oauth-protected-resource/mcp` and
`/.well-known/oauth-authorization-server` should return metadata at that origin.

Organizations can deliver this plugin through managed settings from
`forgebench_rollout_kit` (see [`docs/HOSTED-MCP.md`](../../docs/HOSTED-MCP.md)).
The kit sets `pluginConfigs["forgebench@forgebench"].options.forgebench_url` to the
deployment's own URL; Claude Code reads plugin options from user settings,
`--settings` and managed settings, and managed settings win over a developer's own
value. **The plugin's MCP server no longer follows these settings:** `.mcp.json` is
fixed to the edition's own URL, so `options.mcp_url` does not collapse the plugin's
server into a managed one. An organization on a non-prod or self-hosted deployment
that installs the prod edition therefore gets MCP pointed at production
(`https://api.forgebench.ai/mcp`) while sync follows `forgebench_url` (or
`FORGEBENCH_MCP_URL`) to their own deployment. Such organizations must deliver their
MCP server directly through managed settings and should not rely on this plugin's.
Without a managed value, sync defaults to the edition's URL (production for the prod
edition).

Hook options are read by the launcher from the `CLAUDE_PLUGIN_OPTION_SYNC`,
`CLAUDE_PLUGIN_OPTION_FORGEBENCH_URL` and `CLAUDE_PLUGIN_OPTION_FORGEBENCH_CLI_PATH`
environment variables (the hooks pass only `sync --quiet`). Each value loses
surrounding whitespace and one layer of quotes. If a variable is empty or
unsubstituted (the desktop app does not apply defaults), the staged manifest's
default is used; if the manifest is missing or corrupt, sync is skipped silently
(a broken dev edition never syncs to production).

The launcher validates the URL: a trailing slash is removed, and it must be
`https://` with no user info or whitespace. Plain `http://` is accepted only for
`localhost`, `127.0.0.1` and `::1`; any other URL uploads nothing. If the option is
still the production default and the managed settings set `env.FORGEBENCH_MCP_URL`
(the rollout kit does), the launcher uploads to that deployment instead (validated
the same way), a fallback in case Claude Code does not honour the managed
`pluginConfigs` entry. `forgebench_cli_path` must be a bare command name (looked up
on `PATH` and `~/.local/bin`) or an absolute path; a relative path with a separator
is refused.

### Turn sync off

The `sync` option (default on) controls session sync. It is ON for `true`, `1`,
`yes`, `y`, `on`, `t` or `enabled` (case-insensitive, whitespace and one layer of
quotes ignored). Empty or unsubstituted means "not set" and takes the manifest
default (on). Anything else, whether an explicit `false`, `0`, `no`, `n`, `off`, `f`,
`disabled` or an unrecognised value, is off: sync uploads coding sessions, so
ambiguity stays off. Off, the hooks still fire but the launcher exits before it
reads the transcript, starts the CLI or uploads. The MCP server is unaffected; to
stop using it, disable the plugin or the `forgebench` connector.

```bash
echo '{"sync": "false"}' | claude plugin configure forgebench@forgebench --values-stdin
```

Check the saved `pluginConfigs` in `~/.claude/settings.json`, not just the exit code.

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
