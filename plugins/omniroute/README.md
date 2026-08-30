# OmniRoute plugin for Claude Code

Connects Claude Code to a running [OmniRoute](https://github.com/diegosouzapw/OmniRoute)
instance — a local-first AI API proxy router that load-balances and fails over across multiple
upstream AI providers — through OmniRoute's built-in MCP server.

## Install

From within Claude Code:

```
/plugin marketplace add usamariax0349-cmd/bos-security-app-v3
/plugin install omniroute@bos-security-app-v3
```

(Or add the marketplace from a local checkout with `/plugin marketplace add /path/to/bos-security-app-v3`.)

## Configure

Set these environment variables before starting Claude Code (or edit `.mcp.json` in this plugin
directly):

| Variable            | Default                   | Notes                                                                                                   |
| -------------------- | -------------------------- | --------------------------------------------------------------------------------------------------------- |
| `OMNIROUTE_URL`      | `http://localhost:20128`  | Base URL of your OmniRoute instance                                                                     |
| `OMNIROUTE_API_KEY`  | _(none)_                   | An OmniRoute API key. A local instance accepts any valid key; a non-loopback instance requires a key with the `manage` scope — OmniRoute's `LOCAL_ONLY` route guard only allows remote MCP access for `manage`-scoped keys. |

## What you get

- An `omniroute` MCP server (streamable-HTTP transport, `/api/mcp/stream`) exposing OmniRoute's
  100+ management tools — routing, providers, cache, compression, memory, budget, admin.
- A bundled `omniroute` skill describing the tool catalog and setup.
- Slash commands:
  - `/omniroute:status` — health, uptime, circuit breakers
  - `/omniroute:combos` — list routing combos
  - `/omniroute:switch-combo <name> [on|off]` — activate/deactivate a combo
  - `/omniroute:providers` — provider latency & circuit breaker state
  - `/omniroute:usage [session|day|week|month]` — cost report + session snapshot
  - `/omniroute:cache` — semantic/prompt cache stats

## Reference

Full MCP server docs:
https://github.com/diegosouzapw/OmniRoute/blob/main/docs/frameworks/MCP-SERVER.md
