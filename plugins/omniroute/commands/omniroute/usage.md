---
description: Show OmniRoute cost/usage report and current session snapshot
argument-hint: "[session|day|week|month]"
---

Arguments: $ARGUMENTS

Call `omniroute_cost_report` on the `omniroute` MCP server with the period taken from the
arguments (default to `day` when empty), and also call `omniroute_get_session_snapshot`.
Summarize total cost, token counts, top models/providers, error rate, and budget guard status.
