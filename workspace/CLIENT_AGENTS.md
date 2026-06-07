# CLIENT_AGENTS.md

Strict runtime rules for client-side closed-source protocol reversing agents working in `/workspace`.

## MCP Lifecycle Is Off Limits

- Do not restart, kill, replace, reconfigure, or inspect MCP server processes manually.
- Do not run `pkill`, `kill`, `killall`, `pgrep`, `ps`, `docker restart`, `docker stop`, `supervisorctl`, or equivalent process-management commands against MCP servers.
- Do not restart `frida-mcp-server.py`, `ghidra_headless_analyze.py`, `mcp-gdb`, `searxng`, or any opencode-managed MCP process.
- Treat MCP servers as managed by opencode. If a tool call fails, retry according to the active client agent prompt.

## Client MCP Tool Discipline

- Use exact MCP tool names and explicit JSON-style arguments from the current task contract.
- For `frida-live_attach`, `target` must be the executable client binary path from `state.json` (`target`) or the user request. Never pass `target_dir`, `/workspace/netproto/<name>`, or any output directory as the executable target.
- Attach with `desock=false`; client-mode uses real socket APIs so Frida can observe and rewrite `connect`/`WSAConnect` sockaddr data.
- Do not approximate Frida or Ghidra calls with shell commands. If a prompt says `frida-live_get_connect_attempts`, call that MCP tool.
- Do not invent tool names. Use only names listed in the active client agent prompt.
- Preserve ordering when the prompt requires ordering.

Allowed client Frida call shapes:

```text
frida-live_attach(target="/workspace/client", desock=false)
frida-live_get_pid()
frida-live_get_base(module="client")
frida-live_hook_branches(addrs=["0x...rebased live addr..."])
frida-live_reset_connect_attempts()
frida-live_get_connect_attempts()
frida-live_set_connect_redirects(redirects=[{"original_ip":"1.2.3.4","original_port":443,"local_host":"127.0.0.1","local_port":31337}])
frida-live_reset_io_events()
frida-live_get_io_events()
frida-live_reset_hits()
frida-live_get_branch_hits()
frida-live_get_last_recv()
frida-live_restart()
```

## Required Client Flow

```text
DISCOVER:
1. ghidra-headless_analyze/list_branches/list_imports
2. frida-live_attach exactly once with desock=false
3. compute image_base/live_base/rebase_offset and hook rebased branch addrs
4. frida-live_reset_connect_attempts + frida-live_reset_io_events
5. observe startup/timer/event connection attempts
6. frida-live_get_connect_attempts
7. record runtime connect_targets and static hints separately

REDIRECT:
1. client-peer-emulator starts a LONG-LIVED local fake peer (survives the turn), writes scripts/peer_<seq_id>.py + .pid, and returns pid + ready=true only after a readiness probe
2. frida-live_set_connect_redirects maps original_host/original_ip/original_port to fake peer local_host/local_port; check returned errors[] and frida-live_get_redirect_errors before trusting the redirect
3. every redirect evidence record must preserve original_dst and redirect_dst

OBSERVE:
1. trigger or wait for the client connect path
2. frida-live_get_io_events for outbound send/sendto/SSL_write/WSASend payloads
3. frida-live_get_connect_attempts for endpoint/redirect evidence
4. frida-live_get_branch_hits and frida-live_get_last_recv when relevant
5. client-orchestrator (sole writer) appends Frida-observed io_events to client_sends.log and io_events.log
```

## Tool Boundaries By Client Agent

- `client-orchestrator`: only `read`, `edit`, and `task` for `/workspace/netproto/<target>/...`. It must not call Frida, Ghidra, bash, gdb, web, grep, glob, or list tools directly.
- `client-instrumenter-linux`: owns Linux/ELF client Frida/Ghidra interaction and connect redirection.
- `client-instrumenter-windows`: owns Windows/PE client Frida/Ghidra interaction through Wine-backed runtime and connect/WSAConnect redirection.
- `client-peer-emulator`: starts only long-lived local fake peers (with pid file + readiness probe) and writes reproducible peer scripts. Its only log is `peer_events.log` (peer-side observations). It must NOT write `client_sends.log` or `io_events.log`, and must not call Frida or Ghidra.
- `client-code-analyzer`: decompiles client-side connect/send/SSL_write/config/crypto/timer paths, extracts static hints and raw seeds, and installs Tier 2 hooks.
- `client-protocol-mapper`: consolidates state, packet graph, client_sends.log, io_events.log, and peer scripts into `protocol_model.json`.
- `client-analysis-supervisor`: read-only progress/staleness review.

## Evidence Discipline

- Runtime endpoint truth comes from `frida-live_get_connect_attempts`.
- Runtime outbound payload truth comes from `frida-live_get_io_events`, including SSL_write plaintext when available.
- Static endpoint strings are hints until they match runtime evidence.
- Never call the fake peer the real server. Keep `original_dst` and `redirect_dst` separate everywhere.
- DNS/hosts fallback is allowed only when Frida connect rewrite is unavailable or hostname resolution happened before attach. It does not help hardcoded IP clients.
- Unknown fields stay unknown. Do not invent credentials, protocol semantics, encryption keys, packet fields, or vulnerability reachability.

## Failure Handling

- If redirect cannot be installed, set `connect_redirect_blocked=true` or `tool_blocker="connect_redirect_blocked"`; do not claim fake-server coverage.
- If Wine/runtime is unavailable for PE clients, report `windows_runtime_unavailable`; do not fake dynamic coverage.
- On target death, use `frida-live_restart` only according to the client instrumenter prompt. Never restart MCP infrastructure.
