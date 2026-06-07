# SERVER_AGENTS.md

Strict runtime rules for server-side protocol inference agents working in `/workspace`.

## MCP Lifecycle Is Off Limits

- Do not restart, kill, replace, reconfigure, or inspect MCP server processes manually.
- Do not run `pkill`, `kill`, `killall`, `pgrep`, `ps`, `docker restart`, `docker stop`, `supervisorctl`, or equivalent process-management commands against MCP servers.
- Do not restart `frida-mcp-server.py`, `ghidra_headless_analyze.py`, `mcp-gdb`, `searxng`, or any opencode-managed MCP process.
- Do not edit MCP server files, generated MCP logs, or opencode MCP configuration during an active analysis run unless the user explicitly asks for configuration work.
- Treat MCP servers as managed by opencode. If a tool call fails, retry the tool according to the agent prompt. Do not manage the server process yourself.

## MCP Tool Call Format

- MCP tools must be called by exact tool name, with explicit JSON-style arguments from the current task contract.
- For `frida-live_attach`, `target` must be the executable path from `state.json` (`target`) or the user request, normally `/workspace/server`. Never pass `target_dir`, `/workspace/netproto/<name>`, or any output directory as the executable target.
- Do not approximate MCP calls with shell commands. If a prompt says to use `frida-live_get_branch_hits`, call that MCP tool; do not inspect processes, logs, or files as a substitute.
- Do not invent tool names. Use only names listed in the active agent prompt.
- Do not call multiple MCP tools when the prompt requires a specific order. Preserve the order exactly.
- Do not wrap MCP tool calls in explanatory text. Call the tool first, then return the required JSON contract if the prompt asks for one.

Allowed MCP call shapes:

```text
ghidra-headless_analyze(binary_path="/workspace/server")
ghidra-headless_list_branches(binary_path="/workspace/server")
ghidra-headless_list_imports(binary_path="/workspace/server")
ghidra-headless_list_functions(binary_path="/workspace/server")
ghidra-headless_decompile(binary_path="/workspace/server", address="0x...")

frida-live_attach(target="/workspace/server", desock=false)
frida-live_get_pid()
frida-live_get_base(module="server")
frida-live_hook_branches(addrs=["0x...rebased live addr...", "0x..."])
frida-live_reset_hits()
frida-live_get_branch_hits()
frida-live_get_last_recv()
frida-live_restart()
frida-live_reset_comparisons()
frida-live_get_last_comparisons()
frida-live_reset_file_reads()
frida-live_get_file_reads()
frida-live_hook_address(addr="0x...", label="observed_context@0x...")
frida-live_reset_address_hits()
frida-live_get_address_hits()
```

Required MCP sequences:

```text
INIT:
1. ghidra-headless_analyze
2. ghidra-headless_list_branches
3. ghidra-headless_list_imports
4. frida-live_attach exactly once with desock=false
5. frida-live_get_pid; if it returns a PID, do not call frida-live_attach again
6. discover target listening port according to the agent prompt
7. frida-live_get_base before any branch hooks
8. compute rebase_offset = live_base - image_base
9. rebase all Ghidra branch addresses to live addresses
10. frida-live_hook_branches with only rebased live addresses
11. choose protocol frontier, excluding _init/PLT/import/runtime wrapper branches
12. decompile the protocol frontier function for the seed scan
13. write state.json with live_base, rebase_offset, phase=probe_loop, branches_covered=0

PROBE CYCLE:
1. frida-live_reset_hits
2. server-packet-crafter sends exactly one goal packet after replay steps
3. frida-live_get_branch_hits
4. frida-live_get_last_recv
5. append one branches.log JSON object

SEED HARVEST:
1. frida-live_reset_comparisons
2. frida-live_reset_address_hits
3. frida-live_reset_file_reads
4. frida-live_reset_hits
5. server-packet-crafter sends one intentionally wrong probe at the current gate
6. frida-live_get_last_comparisons
7. if needed, frida-live_get_address_hits
8. frida-live_get_file_reads for runtime-observed config/credential file contents
9. append only evidence-backed seeds
```

MCP failure handling:

- If a call fails, retry the same MCP tool only when the agent prompt allows retry.
- If retry fails, report the failure in the required return contract.
- Never resolve MCP failures by killing, restarting, or replacing MCP servers.

## Frida And Target Restart Rules

- `frida-live_restart` is allowed only to restart the spawned target binary and restore branch hooks.
- `frida-live_restart` is not permission to restart the Frida MCP server process.
- If the target binary dies, report `binary_alive=false` or use the prescribed `frida-live_restart` path from the agent prompt.
- Do not use stale `detach_reason` as a re-attach trigger. Re-attach only when the active tool result shows `session_active=false`; otherwise use the existing PID/session.
- Never kill or respawn the target with shell commands during protocol inference. Use the Frida MCP tools.

## Ghidra Rules

- Use `ghidra-headless_analyze`, `ghidra-headless_list_branches`, `ghidra-headless_list_imports`, `ghidra-headless_list_functions`, and `ghidra-headless_decompile` through MCP only.
- Do not launch Ghidra manually from shell during an agent run.
- If Ghidra analysis fails, use the retry/fallback path from the agent prompt. Do not restart the Ghidra MCP server.

## Tool Boundaries By Agent

- `server-orchestrator`: only `read`, `edit`, and `task` for its allowed state files and subagents. It must not call Frida, Ghidra, bash, gdb, web, grep, glob, or list tools directly. It chooses `server-instrumenter-linux` for ELF/Linux and `server-instrumenter-windows` for PE/Windows.
- `server-instrumenter-linux`: owns Linux/ELF Frida/Ghidra MCP interaction. It may use the exact tool paths described in its prompt, but it must not manually manage MCP processes.
- `server-instrumenter-windows`: owns Windows/PE Frida/Ghidra MCP interaction through the Windows compatibility runtime. It must not use Linux ELF assumptions for PE targets and must mark static-only findings as unconfirmed until runtime hits exist.
- `server-instrumenter`: legacy Linux-compatible alias; prefer the platform-specific agents above.
- `server-packet-crafter`: sends packets only. It must not read files, list directories, inspect logs, or interpret branch hits.
- `server-protocol-mapper`: consolidates observed files into `protocol_model.json`. It must not send packets or delegate tasks.
- `server-code-analyzer`: decompiles covered/frontier code plus protocol-relevant callees to depth 10, extracts seeds, scans vulnerabilities, and installs Tier 2 hooks. It must not run bash or manage MCP processes.
- `server-analysis-supervisor`: read-only coverage strategy. It must not write files, delegate tasks, use Frida tools, or manage MCP processes.

## Evidence Discipline

- Every protocol claim must be backed by observed packet bytes, branch hits, decompile output, runtime comparison data, or a specific line from the shared state/log files.
- Unknown fields stay unknown. Do not invent protocol semantics, credentials, encryption keys, packet fields, or vulnerability reachability.
- Seeds are opaque byte values until evidence proves their role. Semantic names are allowed only when they are derived from observed runtime/decompile evidence; otherwise preserve mechanically discovered names or derive names from comparison/function/address context. Do not include hardcoded example seed names in these rules.
- File-backed credentials/seeds must come from evidence: either decompile showing an explicit config/credential file loader or Frida runtime `get_file_reads` output from a target-opened file. Do not read arbitrary files with shell/read tools to guess secrets.

## Encrypted Or Obfuscated Protocol Handling

- Treat encryption or obfuscation as a hypothesis to verify, not as an assumption.
- Prefer oracle evidence: `strcmp`, `memcmp`, custom comparison hooks, Tier 2 argument captures, branch blockers, and decompiled parser/crypto functions.
- Look for XOR, rolling-key, checksum, length-prefix, transform, compression, or encryption-like logic only when decompile/runtime evidence supports it.
- When coverage plateaus, use the prescribed seed-harvest path instead of restarting MCP servers.

## Failure Handling

- On MCP tool errors, retry the specific tool if the prompt allows it.
- On target death or missing receive data, report the failure through the expected JSON contract.
- On stale frontier or plateau, delegate to `server-analysis-supervisor` or use seed harvesting according to the orchestrator prompt.
- Initial and replacement frontiers must be protocol-relevant branches. Do not select `_init`, PLT/import trampolines, stdlib/C++ runtime wrappers, startup/destructor glue, or the first raw branch solely because it appears first in Ghidra output. Prefer protocol/server/parser/SSL/read/write/auth/crypto functions; for `/workspace/server`, start in `handle_client`, not `0x104013`.
- Never "fix" failures by restarting MCP infrastructure.

