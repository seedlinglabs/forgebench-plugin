---
name: setup
description: >-
  Connect this Claude Code install to forgebench without the forgebench CLI:
  sign in through the browser, route Claude Code's model calls through the
  forgebench gateway, turn on native OpenTelemetry reporting, check the
  connection, pick the task a session works on, and disconnect. Use when the
  user asks to connect, set up, sign in to or log out of forgebench, to
  "route Claude Code through forgebench" or "use the forgebench gateway", to
  turn gateway routing or telemetry on or off, to check forgebench status
  ("is forgebench connected?", "why isn't my session showing up?"), or to
  link this session to a task. Not for onboarding a repo's agents or MCP
  servers (use forgebench-onboarding) or wiring forgebench into an app the
  user is building (use forgebench-integrate).
argument-hint: "[connect | status | gateway on | gateway off | task | disconnect]"
---

# forgebench setup (no CLI)

Every step runs the plugin's own helper. It needs Python 3.10+ and never
needs, finds or runs the forgebench CLI. Run it exactly like this, through
the Bash tool, with `--json` so you can read the result:

```
"${CLAUDE_PLUGIN_ROOT}/scripts/forgebench-run" --json <command> --url "${user_config.forgebench_url}" [options]
```

Below, `fb <command>` is short for that line. Run it as written: always pass
`--url` with the configured value, never a URL you made up or the user typed
into chat. To change the deployment, the user changes the plugin's
`forgebench_url` option in `/plugin` (or `/config`).

## Ground rules

- **No secrets in chat.** The helper never prints keys. Never ask the user for
  an API key, token or password, never read files under the helper's data
  directory, and never run the `api-key` or `otel-headers` modes yourself:
  Claude Code runs those itself.
- **Report what the helper says.** Relay `problems`, `skipped`, `conflicts`
  and `next_step` in plain words. Don't claim something is routed or
  reporting unless `status` says so.
- **Settings are the user's.** The helper writes only the user-scope
  `settings.json`, only keys it owns, and reports any conflict instead of
  overwriting. Never edit `settings.json` yourself to "fix" a conflict. Tell
  the user which key and which layer conflict, and let them decide.
- **Gateway routing changes billing.** While routing is on, Claude Code's
  model calls use a forgebench credential instead of the user's claude.ai
  login. Usage counts against the workspace's forgebench budgets, not the
  user's subscription, and Remote Control and voice dictation stop working.
  Say this once before turning routing on, and confirm the user wants it.

## connect

1. `fb preflight`. If `ok` is false, show `problems` and stop.
2. `fb auth begin`. It opens the browser and returns an `op` and a
   `login_url`. Tell the user to finish signing in there (and to open the
   `login_url` themselves if no browser opened). Never paste the URL's
   query parameters anywhere else.
3. Poll `fb auth wait --op <op> --seconds 20` (no `--url`) until `status` is
   `complete`, `failed`, `cancelled` or `expired`. Between polls, say once
   that you are still waiting. If the user wants to stop, run
   `fb auth cancel --op <op>`.
4. On `complete`, show who they signed in as (`result.identity`) and whether
   model access was granted (`result.inference_state`).
5. Ask whether to turn on gateway routing (see the billing rule above) and
   telemetry, then run `fb apply` with `--no-gateway` and/or
   `--no-telemetry` for anything they declined.
6. Report `written`, `unchanged`, `skipped` and `conflicts`. If
   `pending_restart` is true, tell them to restart Claude Code. The new
   configuration only applies to sessions started after that.

If model access shows as unsupported, the deployment doesn't hand out a model
credential to the plugin yet: reporting still works, routing doesn't. Say so
plainly. Don't retry the sign-in.

## status

Run `fb status`. Summarise:

- signed in and as whom, and whether the credential still authenticates
- `configuration.gateway` and `configuration.telemetry` (`applied`,
  `absent`, or a conflict), and `restart_required`
- session context delivery: `context.last_status`, `last_success_at`,
  `pending`, and `stale`
- the capture policy, if present

The forgebench MCP server is a separate OAuth connection. If the user asks
about forgebench tools, point them to `/mcp`.

## gateway on / gateway off

- **On:** must be signed in (run *connect* if not). Run `fb apply` with
  `--no-telemetry` only if the user wants routing alone. Restart required.
- **Off:** the helper restores only the values it wrote and are still
  unchanged. Run `fb logout`, which also removes the local credentials, then
  offer to reconnect with routing declined (`fb apply --no-gateway`) if the
  user still wants reporting. Restart required.

## task

To link the current session to a task:

1. `fb task options --origin <deployment origin from status> [--query <text>]`.
   Show the options and let the user pick one. Never guess a task.
2. `fb task validate --origin <origin> --connection <id> --task <id>`.
3. `fb task declare --origin <origin> --connection <id> --task <id>
   --session-id ${CLAUDE_SESSION_ID} --mechanism ui`.

If the helper says task selection isn't available for this credential, say so
and stop.

## disconnect

`fb logout` restores the settings it wrote, removes local credentials, and
drops undelivered session context. Add `--revoke` only if the user asks to
revoke the grants on the server too. Relay `server_revocation` exactly: if it
says the server doesn't support revoking, the grants stay active until
someone revokes them in the console. Tell the user to restart Claude Code and,
if they also want to disconnect the MCP server, to do that from `/mcp`.
