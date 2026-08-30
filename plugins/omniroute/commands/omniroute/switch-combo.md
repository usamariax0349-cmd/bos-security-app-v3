---
description: Activate or deactivate an OmniRoute routing combo
argument-hint: <combo-name> [on|off]
---

Arguments: $ARGUMENTS

Parse the arguments as `<combo-name> [on|off]`. If no `on`/`off` is given, default to activating
the combo. Call `omniroute_switch_combo` on the `omniroute` MCP server with the parsed combo name
and desired state, then confirm the result (or surface the error, e.g. unknown combo name).
