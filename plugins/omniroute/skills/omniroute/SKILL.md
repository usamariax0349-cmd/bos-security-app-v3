---
name: omniroute
description: Use when the user wants to inspect or manage an OmniRoute AI proxy router instance — health, routing combos, provider metrics, cache, cost/usage, budgets, or compression — through OmniRoute's MCP server.
---

# OmniRoute

[OmniRoute](https://github.com/diegosouzapw/OmniRoute) is a local-first AI API proxy router: an
OpenAI/Anthropic-compatible endpoint that load-balances and fails over across multiple upstream
AI providers, with usage tracking, semantic caching, and prompt compression built in.

This plugin registers an `omniroute` MCP server that talks to a running OmniRoute instance's
built-in MCP server (100+ tools across routing, providers, cache, compression, memory, skills,
budget, and admin scopes).

## Setup

- `OMNIROUTE_URL` — base URL of the OmniRoute instance (default `http://localhost:20128`)
- `OMNIROUTE_API_KEY` — an OmniRoute API key. A local instance accepts any valid key; a
  non-loopback instance requires a key with the `manage` scope (OmniRoute's `LOCAL_ONLY` route
  guard only allows remote MCP access for `manage`-scoped keys).

Set both as environment variables before starting Claude Code, or edit `.mcp.json` in this
plugin directly.

## Common tools

| Task                                     | Tool                              |
| ----------------------------------------- | ---------------------------------- |
| Health / uptime / circuit breakers       | `omniroute_get_health`            |
| List routing combos                      | `omniroute_list_combos`           |
| Activate/deactivate a combo              | `omniroute_switch_combo`          |
| Provider latency & circuit breaker state | `omniroute_get_provider_metrics`  |
| Cost report                              | `omniroute_cost_report`           |
| Session snapshot                         | `omniroute_get_session_snapshot`  |
| Cache stats / flush                      | `omniroute_cache_stats` / `omniroute_cache_flush` |
| Simulate a routing decision              | `omniroute_simulate_route`        |
| Explain a past route                     | `omniroute_explain_route`         |
| Live-test every provider in a combo      | `omniroute_test_combo`            |

The connected instance's live catalog is authoritative — call `omniroute_tool_search`, or
`GET $OMNIROUTE_URL/api/mcp/tools`, to enumerate everything actually available.

## Slash commands

This plugin also ships shortcuts: `/omniroute:status`, `/omniroute:combos`,
`/omniroute:switch-combo`, `/omniroute:providers`, `/omniroute:usage`, `/omniroute:cache`.

## Reference

Full MCP server docs:
https://github.com/diegosouzapw/OmniRoute/blob/main/docs/frameworks/MCP-SERVER.md
