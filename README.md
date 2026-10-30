# forgebench plugin for Claude Code

Connects Claude Code to the **hosted forgebench MCP server** and adds what the
server cannot ship by itself:

| Part | Path | What it does |
|---|---|---|
| MCP server entry | `.mcp.json` | An HTTP server named `forgebench` at the `mcp_url` option (no default: unset means the server is skipped). Sign-in is OAuth in the browser; no API key is configured anywhere. |
| Onboarding skill | `skills/forgebench-onboarding/SKILL.md` | The scan, review, plan and apply flow, budgets and limits, and browser-only agent keys. Loaded when you ask Claude to onboard a repo, change a budget or get an agent key. |
| Integration skill | `skills/forgebench-integrate/SKILL.md` | Integrating forgebench into a developer's own app: the gateway base URL, env vars, request parameters, metadata, sessions, streaming, error handling, agent keys and tool gating, using the `forgebench_integrate recipe` tool and checking the result with `forgebench_integrate verify`. |
| Local scanner | `scripts/forgebench_scan.py` | Finds agents and MCP servers in a repository and uploads a minimal `forgebench.scan/v1` payload straight to forgebench with a single-use ticket. Prints only counts and a sha256. Needs Python 3.10+. |
| Setup skill | `skills/setup/SKILL.md` | `/forgebench:setup`: browser sign-in, gateway routing, native OpenTelemetry, status, task selection and disconnect, all without the forgebench CLI. Runs the helper below. |
| Helper | `scripts/forgebench-run`, `scripts/forgebench_helper.py`, `scripts/fbplugin/` | Standard-library Python 3.10+ (macOS and Linux). Signs in with PKCE in the browser; writes only its own keys in user-scope `settings.json` (`ANTHROPIC_BASE_URL`, `apiKeyHelper`, `ANTHROPIC_CUSTOM_HEADERS`, the OTel exporter and `otelHeadersHelper`) with an ownership receipt, and restores them on disconnect; serves the `apiKeyHelper` and `otelHeadersHelper` credentials; posts session context to `/v1/sessions/meta` from the SessionStart and SessionEnd hooks. Never needs, finds or runs the CLI. |
| Sync hooks | `hooks/hooks.json`, `scripts/forgebench_sync_launcher.py` | Optional, for machines that also have the CLI: three exec-form hooks (SessionStart, SessionEnd, and PostToolUse for the `Skill` matcher) run the launcher, which starts `forgebench sync --quiet --url <url>` fully detached (double fork) and returns at once, inside the fixed 1.5 s SessionEnd budget. With the `sync` option off it exits before reading anything. POSIX only (#1060); without `fork`/`setsid` the launcher exits without syncing, and the Windows detach is #1146. Uses the `forgebench` CLI when it is installed (see the `forgebench_cli_path` option) and does nothing without it. |
| Options | `userConfig` in `.claude-plugin/plugin.json` | `forgebench_url` (default `https://api.forgebench.ai`, where sync uploads), `forgebench_cli_path` (default `forgebench`, found on `PATH` or in `~/.local/bin`), `sync` (Boolean, default on) and `mcp_url` (no default). None is sensitive. |
| Manifests | `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` | The plugin, and a one-plugin marketplace so this directory can be added as a marketplace. |

The server-side design, threat model and an end-to-end test runbook are in
[`docs/HOSTED-MCP.md`](../../docs/HOSTED-MCP.md).

## Install for local testing

You need a running control plane (the local stack serves it at
`http://localhost:8000`) and Claude Code. The plugin connects to production
(`https://api.forgebench.ai`) by default and registers no MCP server until
`mcp_url` is set, so point both at the local stack when you install. From the
repository root:

```bash
claude plugin marketplace add ./packages/forgebench-plugin
claude plugin install forgebench@forgebench \
  --config forgebench_url=http://localhost:8000 --config mcp_url=http://localhost:8000/mcp
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

### Connect Claude Code itself (no CLI)

The MCP sign-in above is for the forgebench tools. To route Claude Code's own
model calls through the gateway and report sessions, run
`/forgebench:setup connect` (or ask *"connect Claude Code to forgebench"*). The
skill signs you in through the browser, asks before turning on gateway
routing (routed calls use a forgebench credential instead of your claude.ai
login) and telemetry, and writes the configuration. Restart Claude Code
afterwards. `/forgebench:setup status` shows what is connected, and
`/forgebench:setup disconnect` restores your settings.

Known gaps, all on the server side: until the control plane hands a model
credential to the plugin at sign-in (the `plugin_contract` marker), connect is
reporting-only and gateway routing is reported as unsupported. The
session-context confirmation (`capture_contract`) and the telemetry delivery
endpoint are not implemented yet either, so `status` shows context as sent but
unconfirmed. Per-session usage from transcripts still comes from the optional
CLI sync.

### Server only (no skill, no scanner)

```bash
claude mcp add --transport http forgebench https://api.forgebench.ai/mcp
```

Every tool works, but there is no onboarding skill and no local scanner (the
model can only fall back to `forgebench_onboarding` with action `submit_inline`). If you add both,
Claude Code treats the plugin's server and yours as one server as long as they
point at the same URL.

### Point the plugin at another deployment

The sync hooks read the `forgebench_url` option (no trailing slash) and the MCP
server reads the `mcp_url` option (`.mcp.json`: `${user_config.mcp_url}`, the
full URL including `/mcp`). Set them at install time with `--config` or change
them from the plugin's configuration in `/plugin`.

Organizations do not need either step: an admin gets managed settings that
deliver the server and this plugin to every developer from
`forgebench_rollout_kit` (see [`docs/HOSTED-MCP.md`](../../docs/HOSTED-MCP.md)).
The kit sets `pluginConfigs["forgebench@forgebench"].options.forgebench_url` to
the deployment's own URL and `options.mcp_url` to its `/mcp` URL, so the plugin's MCP server collapses into the managed
one and the sync hooks upload to the same deployment, on staging, dev or
self-hosted as much as on production. Claude Code reads plugin options from
user settings, `--settings` and managed settings, and managed settings win over
a developer's own value. Without a managed value the sync default stays
production and MCP stays off.

The launcher also checks the `forgebench_url` it is given: a trailing slash is
removed, and plain `http://` is accepted only for `localhost`, `127.0.0.1` and
`::1` (session content is not sent over cleartext to anything else); any other
URL uploads nothing. If the option is still the production default and the
managed settings set `env.FORGEBENCH_MCP_URL` (the rollout kit does), the
launcher uploads to that deployment instead, a fallback in case Claude Code
does not honour the managed `pluginConfigs` entry.

### Turn sync or MCP on and off separately

The two features are independent options of one plugin; neither needs the
plugin disabled or uninstalled, and neither uses `disableAllHooks`.

- **Sync**: the `sync` option (default on). Off, the hooks still fire but the
  launcher exits before it reads the transcript, starts the CLI or uploads.
- **MCP**: the `mcp_url` option. Pass `--config mcp_url=<url>` on install to
  enable it; to skip it, leave the flag out. **Never pass an empty
  `--config mcp_url=`**: Claude Code 2.1.311 rejects the empty value while the
  install can still exit 0.

To change either on an installed plugin, write the options as a JSON object of
strings on stdin (`--values-stdin` refuses a bare `false`), then check the saved
`pluginConfigs` in `~/.claude/settings.json`, not just the exit code:

```bash
echo '{"mcp_url": ""}' | claude plugin configure forgebench@forgebench --values-stdin   # MCP off, sync kept
echo '{"mcp_url": "https://api.forgebench.ai/mcp"}' | claude plugin configure forgebench@forgebench --values-stdin
echo '{"sync": "false"}' | claude plugin configure forgebench@forgebench --values-stdin  # sync off, MCP kept
```

With `mcp_url` unset or empty, Claude Code makes no connection, but `/mcp` and
`claude mcp get plugin:forgebench:forgebench` show **Failed to connect** with
"URL is unset or invalid" (verified on 2.1.306 and 2.1.311), not "Not configured". That is the expected
display for skipped MCP; set `mcp_url` to turn it back on.

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
