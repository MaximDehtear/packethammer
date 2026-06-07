# AGENTS.md

Top-level routing rules for agents working in `/workspace`.

Use the mode-specific rule file for the active task:

- Server-side protocol inference: read `SERVER_AGENTS.md` and use `server-orchestrator` plus server subagents.
- Client-side closed-source protocol reversing: read `CLIENT_AGENTS.md` and use `client-orchestrator` plus client subagents.

Shared invariant: all analysis output for both modes stays under `/workspace/netproto/<target>/...`. Do not rename or split that storage path.

MCP infrastructure is managed by opencode in both modes. Do not kill, restart, inspect, or replace MCP server processes manually.
