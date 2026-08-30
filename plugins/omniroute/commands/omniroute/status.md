---
description: Check OmniRoute health, uptime, and circuit breaker status
---

Call the `omniroute_get_health` MCP tool on the `omniroute` MCP server and present a concise
summary: uptime, memory, circuit breaker states, rate limit headroom, and cache stats.

If the call fails because the server is unreachable or unauthorized, tell the user to verify:

- OmniRoute is running and reachable at `OMNIROUTE_URL` (default `http://localhost:20128`)
- `OMNIROUTE_API_KEY` is set to a valid key (needs the `manage` scope for a non-local instance)
