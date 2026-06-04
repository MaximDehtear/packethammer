# PacketHammer Wiki

> Autonomous network protocol reverse-engineering via cooperative LLM agents.  
> Binary in → protocol model, vulnerabilities, and fuzzing seeds out.

---

## Table of Contents

| Section | Description |
|---|---|
| [Overview](#overview) | What PacketHammer is and the problem it solves |
| [Core Concepts](#core-concepts) | Active-learning loop, oracle tiers, PIE rebasing |
| [System Architecture](#system-architecture) | Container layout, component relationships |
| [The 6-Agent System](#the-6-agent-system) | Each agent's role, tools, and strict boundaries |
| [Probe Loop Internals](#probe-loop-internals) | Step-by-step mechanics of each cycle |
| [Oracle System](#oracle-system) | Tier 1, Tier 2, and planned Tier 3 seed harvesting |
| [MCP Servers](#mcp-servers) | `ghidra-headless` and `frida-live` tool references |
| [Data Formats](#data-formats) | Schemas for every file the pipeline reads and writes |
| [Installation & Configuration](#installation--configuration) | Build, model backends, agent config |
| [Running the Pipeline](#running-the-pipeline) | Prompts, monitoring, output |
| [HTML Report Generation](#html-report-generation) | The `/generate-protocol-report` skill |
| [Invariants & Safety Rules](#invariants--safety-rules) | Rules that must never be broken |
| [Troubleshooting](#troubleshooting) | Diagnosed failure modes and fixes |
| [Design Decisions](#design-decisions) | Why things are built the way they are |
| [Roadmap](#roadmap) | Completed and planned work |

---

## Overview

Protocol reverse-engineering is an active-learning problem. To understand what a server accepts, you must send bytes. But to know what bytes to send, you must already understand the protocol. PacketHammer resolves this loop by running an instrumentation-backed probe cycle — each iteration reveals which code path your packet reached, and the coverage delta guides the shape of the next packet.

The entire process runs without human involvement after the initial prompt. A single `phammer` invocation:

1. Runs Ghidra headless analysis on the binary to map every branch address
2. Spawns the binary under Frida to instrument it live
3. Discovers the real listening port via `lsof`/`ss` (never guesses)
4. Enters the probe loop — RESET → SEND → OBSERVE → UPDATE → repeat
5. Decompiles every newly-hit function in real time and scans for vulnerabilities
6. Extracts seeds (tokens, passwords, magic values) from Frida comparison hooks
7. Builds `protocol_model.json` and an animated HTML report

**What you get at the end:**

- A structured JSON specification of the protocol — every command, response code, session flow, and field annotation
- A machine-readable vulnerability report — buffer overflows, format strings, integer overflows, UAF — each with a decompile snippet and PoC trigger
- Reproducible Python send scripts for every discovered sequence step
- A self-contained HTML report you can open in any browser

---

## Core Concepts

### The Three-Layer Stack

PacketHammer combines three independent layers into a single feedback loop. Each layer sees what the others cannot.

```
┌──────────────────────────────────────────────────────┐
│  Layer 3 — LLM Reasoning                             │
│  Six agents decide what to probe next, interpret     │
│  coverage deltas, decompile functions, and build     │
│  the protocol model. No human decisions at any step. │
├──────────────────────────────────────────────────────┤
│  Layer 2 — Dynamic Instrumentation (Frida)           │
│  Branch hit counters installed at every address from │
│  Ghidra. Comparison oracle hooks capture the exact   │
│  expected values at every strcmp/memcmp call.        │
├──────────────────────────────────────────────────────┤
│  Layer 1 — Static Analysis (Ghidra)                  │
│  Complete branch map before a single byte is sent.   │
│  Decompiled pseudo-C for every covered function.     │
│  Provides the address space for Frida to instrument. │
└──────────────────────────────────────────────────────┘
```

Static analysis alone cannot tell you what input reaches a branch — there are too many paths and the data is unknown. Dynamic instrumentation alone cannot tell you what code to instrument — you don't know which functions matter. LLM reasoning alone cannot navigate byte-level parsing without ground-truth coverage feedback. Together, each layer provides what the others lack.

### Coverage as Feedback

Each packet send produces a binary signal per branch address: hit or not hit. The set of newly-hit branches (branches covered this step that were never covered before) is the primary signal driving the next probe. When the set is empty for three consecutive cycles, the system has reached a plateau — all reachable branches from the current seed pool have been covered — and triggers a HARVEST cycle to extract new seeds from the oracle.

### The Blackboard Pattern

All agents communicate through shared files rather than direct calls. The orchestrator owns `state.json` (the blackboard) and `packet_graph.json` (the decision graph). Agents read their input contracts, perform exactly their assigned work, and return structured output. No agent ever calls another agent directly.

```
                 ┌─────────────┐
         writes  │  state.json │  reads
   ┌────────────►│ packet_graph│◄────────────┐
   │             └─────────────┘             │
   │                                         │
orchestrator                            sub-agents
(UPDATE step)                        (input contracts)
```

### PIE Address Rebasing

Position-independent executables load at a kernel-randomised base address each run. Ghidra analyses the binary at its static load address (e.g. `0x100000`); Frida sees it at a live address (e.g. `0x5695c9bf4000`). Every hook address computed from Ghidra output must be rebased:

```
rebase_offset = live_base − image_base
live_addr     = ghidra_addr − image_base + live_base
```

`image_base` is always read from `ghidra_analysis.json`. It is never hardcoded, never assumed to be `0x400000`, and never guessed.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Docker Container                           │
│                                                                 │
│  phammer (wrapper) → opencode TUI                               │
│       │                                                         │
│       ▼                                                         │
│  netproto-orchestrator  (primary agent)                         │
│       │  task tool  ── permission.task grants delegation        │
│       │                                                         │
│       ├─► @net-instrumenter                                     │
│       │        ├── ghidra-headless MCP (stdio)                  │
│       │        │     ghidra_headless_analyze.py                 │
│       │        │     PyGhidra 3.1.0 → Ghidra 12.1 JVM          │
│       │        └── frida-live MCP (stdio)                       │
│       │              frida-mcp-server.py                        │
│       │              Frida 17.10.1 → spawned target process     │
│       │                                                         │
│       ├─► @packet-crafter                                       │
│       │        └── python3 / scapy / socket                     │
│       │                                                         │
│       ├─► @protocol-mapper                                      │
│       │        └── reads logs → writes protocol_model.json      │
│       │                                                         │
│       ├─► @code-analyzer        (triggered: new branch covered) │
│       │        ├── ghidra-headless_decompile (per function)     │
│       │        └── frida-live_hook_address (Tier 2 oracle)      │
│       │              writes vulnerabilities.jsonl               │
│       │                                                         │
│       └─► @analysis-supervisor  (triggered: every 5 steps)     │
│                └── ghidra-headless_list_branches (gap analysis) │
│                      returns recommendations only               │
│                                                                 │
│  Bind mount: ./workspace ↔ /workspace                           │
│  Network: --network host  (container shares host ports)         │
└─────────────────────────────────────────────────────────────────┘
```

### Key Architectural Constraints

| Constraint | Reason |
|---|---|
| Orchestrator has no Frida/Ghidra tools | Enforces delegation — all instrumentation goes through net-instrumenter |
| Packet-crafter has no file-read tools | Prevents context pollution; all input arrives in the task contract |
| Analysis-supervisor is read-only | Prevents accidental state mutation from a recommendation agent |
| MCP servers run as stdio processes | opencode-ai launches them as child processes; no separate daemon needed |
| `desock=false` always | `desock.so` intercepts socket syscalls; binary never binds to a real port if enabled |
| `frida.spawn()` always | `frida.attach()` requires `CAP_SYS_PTRACE` which the container does not have |

---

## The 6-Agent System

### Agent Summary

| Agent | Mode | Trigger | Writes | Forbidden |
|---|---|---|---|---|
| `netproto-orchestrator` | primary | user prompt | `state.json`, `packet_graph.json` | Frida tools, Ghidra tools, bash |
| `net-instrumenter` | subagent | INIT / RESET / OBSERVE / HARVEST | `branches.log`, `state.json` (INIT only) | `state.json` in RESET/OBSERVE, bash (except port discovery) |
| `packet-crafter` | subagent | SEND step | `scripts/send_*.py` | All file reads, all file lists |
| `protocol-mapper` | subagent | every 5 steps + exit | `protocol_model.json`, `knowledge.jsonl` | Task delegation, file writes other than its two outputs |
| `code-analyzer` | subagent | each new branch covered | `vulnerabilities.jsonl` | bash, task delegation, `frida-live_attach`, `frida-live_hook_branches`, `ghidra-headless_analyze` |
| `analysis-supervisor` | subagent | every 5 steps or plateau ≥ 2 | — (read-only) | All writes, all task delegation, all frida-live tools |

### netproto-orchestrator

The orchestrator is the only agent that runs for the full duration of a pipeline. It owns the two shared state files and drives the probe loop. It never calls Frida or Ghidra tools directly — all instrumentation is delegated to net-instrumenter.

**INIT sequence (one-time):**
1. `task(net-instrumenter, "INIT MODE — target_path=... target_dir=...")` — runs the full init protocol (Ghidra analysis, branch hook installation, port discovery, PIE rebase computation). The prompt passes only the target path and output directory; the net-instrumenter owns all INIT steps internally.
2. `read(state.json)` — retrieve channel, rebase_offset, frontier
3. `edit(packet_graph.json)` — write initial graph with ROOT node

**Probe loop (each cycle — exactly 3 task calls):**
```
task(net-instrumenter, "RESET MODE")
task(packet-crafter,   <input contract JSON>)
task(net-instrumenter, "OBSERVE MODE")
→ edit(state.json)
→ edit(packet_graph.json)
→ [CODE-ANALYZE if new_branch_seen]
→ [SUPERVISOR if step % 5 == 0 or plateau_counter >= 2]
→ repeat
```

**Exit conditions:**
- `plateau_counter >= 3` AND `branches_covered >= 2` — natural plateau exit
- `steps_total >= 30` — hard cap
- `restart_count > 5` — too many binary deaths

**Restart protocol (on `binary_alive=false` or `replay_failed`):**
1. `task(net-instrumenter, "restart the binary")` → calls `frida-live_restart()`
2. Replay all confirmed sequences as a health check
3. On success: continue from frontier
4. On failure: mark sequence `flaky=true`, skip it

### net-instrumenter

The net-instrumenter holds the persistent Frida session for the entire run. It is called in four distinct modes; each mode has its own strict tool access list.

**INIT MODE — full setup protocol:**

| Step | Action |
|---|---|
| A | `ghidra-headless_analyze(binary_path)` — ~60–120 s first run; cached |
| B | `ghidra-headless_list_branches(binary_path)` — collect all branch addresses |
| C | `ghidra-headless_list_imports(binary_path)` — find recv/read symbol addresses |
| D | `frida-live_attach(target, desock=false)` — spawn binary as child process |
| D.5 | Port discovery: `frida-live_get_pid()` → `lsof -Pan -i tcp -p <PID>` → parse real port |
| E | `frida-live_hook_branches(addrs=[...])` — install hit counters on all branch addresses |
| F | `frida-live_get_base()` → read `image_base` from `ghidra_analysis.json` → compute `rebase_offset` |
| G | Write `state.json` with channel, rebase_offset, image_base, live_base, frontier, phase |

**RESET MODE** — allowed tools: `frida-live_reset_hits`, `read` (branches.log only). Must NOT touch `state.json`.

**OBSERVE MODE** — allowed tools: `frida-live_get_branch_hits`, `frida-live_get_last_recv`, `edit` (branches.log only). Must NOT touch `state.json`.

**SEED HARVEST RESET MODE** — `frida-live_reset_comparisons()`, `frida-live_reset_address_hits()`, `frida-live_reset_hits()`.

**SEED HARVEST OBSERVE MODE** — reads Tier 1 comparisons, falls back to Tier 2 address hits, appends seeds to `state.json`.

### packet-crafter

Spawned fresh for exactly one goal per cycle. Has no memory of prior calls. All context it needs arrives in the input contract JSON.

**Contract fields received:**
```json
{
  "channel": "socket:127.0.0.1:2121",
  "target_dir": "/workspace/netproto/server",
  "seq_id": "seq_003",
  "step": 4,
  "goal": "send PASS command with seed value from gate 0x103c11",
  "replay_steps": ["555345520d0a", "504153530d0a"],
  "seeds": [
    {"name": "strcmp_a1@0", "value": "secret", "gate": "0x103c11"}
  ]
}
```

**Execution rules:**
- Step 1 is always opening a TCP connection — nothing else first
- Replay all `replay_steps` bytes in order before attempting the goal
- On replay failure at any step: return `{"ok": false, "error": "replay_failed", "failed_at_step": N}` and stop
- For the first ever probe (empty `replay_steps`): send a minimal ASCII line (e.g. `HELP\r\n`) — do not invent binary framing
- Seeds are opaque values; apply the seed matching the blocking `gate` address when the server rejects at that gate
- Save a reproducible script at `<target_dir>/scripts/send_<seq_id>_s<step>.py`
- Return value: print contract JSON as the last line of output

### protocol-mapper

Reads the full accumulated log set and writes `protocol_model.json`. Called every 5 steps and at final exit. On runs with good coverage, also appends a protocol signature to `/workspace/netproto/knowledge.jsonl`.

**Input files read:**
- `branches.log` — all per-packet observations
- `packet_graph.json` — the decision graph built by orchestrator
- `state.json` — final seeds, sequences, coverage
- `vulnerabilities.jsonl` — real-time findings from code-analyzer (if present)

**Output:** `protocol_model.json` covering `packet_structure`, `value_to_branch`, `sequences`, `gates`, `field_influence_map`, `risk_hints`, `seeds`, and `graph_summary` with ASCII decision tree.

Every field, gate, and risk must cite the observation that supports it. No guessing or inference without evidence.

### code-analyzer

Triggered immediately after any new branch is covered. Decompiles every function that was newly hit and performs three tasks:

1. **Seed extraction** — scans decompile output for string literals, integer constants, and magic bytes in comparison expressions. Creates `decompile_str_<N>` entries.
2. **Tier 2 oracle setup** — identifies non-stdlib comparison logic (custom `verify_*` functions, inline byte comparisons). Calls `frida-live_hook_address(live_addr, label)` to install argument-capture hooks.
3. **Vulnerability scan** — checks every decompiled function for: `buffer_overflow`, `format_string`, `integer_overflow`, `out_of_bounds_write`, `use_after_free`, `stack_overflow`. Appends confirmed findings with decompile evidence to `vulnerabilities.jsonl`.

Returns `{seeds, vulnerabilities_found, tier2_hooks, functions_analyzed}` — the orchestrator appends seeds to `state.json`.

### analysis-supervisor

A strategic advisor with no write access. Reads the current coverage gap and the last 30 lines of `branches.log` to detect trajectory patterns, then returns a structured recommendation.

**Returns:**
```json
{
  "coverage_gap_pct": 34,
  "unreached_functions": ["parse_extra_cmd", "handle_admin"],
  "recommendation": "try HI command with oversized argument",
  "suggested_probe_strategy": "send 'HI ' + 'A'*40 + '\r\n'",
  "stale_frontier_detected": true,
  "stale_reason": "same branch 0x1044f2 blocked for 8 consecutive steps"
}
```

The orchestrator passes `suggested_probe_strategy` as the goal for the next `[SEND]` step.

---

## Probe Loop Internals

### Full cycle diagram

```
┌─────────────────────────────────────────────────────────────┐
│  START OF CYCLE                                             │
│                                                             │
│  [RESET]                                                    │
│   net-instrumenter:                                         │
│     frida-live_reset_hits()                                 │
│     → read last line of branches.log → current frontier     │
│     → return {ready: true, frontier: "..."}                 │
│                                                             │
│  [SEND]                                                     │
│   packet-crafter (input contract from orchestrator):        │
│     1. open TCP connection to channel                       │
│     2. replay all confirmed steps (bytes.fromhex)          │
│     3. send goal packet                                     │
│     4. save scripts/send_<seq>_s<step>.py                   │
│     → return {ok, packet_hex, packet_fields}                │
│                                                             │
│  [OBSERVE]                                                  │
│   net-instrumenter:                                         │
│     frida-live_get_branch_hits()                            │
│     frida-live_get_last_recv()                              │
│     → build contract JSON                                   │
│     → append one line to branches.log                       │
│     → return contract                                       │
│                                                             │
│  [UPDATE] (orchestrator, no task call)                      │
│     edit(state.json)  — increment counters, update frontier │
│     edit(packet_graph.json) — add node/edge/sequence        │
│                                                             │
│  [CODE-ANALYZE] if new_branch_seen == true                  │
│   code-analyzer:                                            │
│     decompile all newly-hit functions                       │
│     extract seeds → append to state.json (via orchestrator) │
│     install Tier 2 hooks                                    │
│     append to vulnerabilities.jsonl                         │
│                                                             │
│  [SUPERVISOR] if step % 5 == 0 or plateau_counter >= 2      │
│   analysis-supervisor:                                      │
│     list_branches (full gap analysis)                       │
│     read last 30 lines of branches.log                      │
│     → return recommendation + suggested_probe_strategy      │
│                                                             │
│  [HARVEST] if plateau_counter >= 2                          │
│   HARVEST RESET → SEND probe → HARVEST OBSERVE             │
│   → seeds appended to state.json                            │
│   plateau_counter reset to 0                                │
│                                                             │
│  [MODEL] if step % 5 == 0 or phase == done                  │
│   protocol-mapper: build protocol_model.json                │
│                                                             │
│  → back to [RESET]                                          │
└─────────────────────────────────────────────────────────────┘
```

### Exit conditions

| Condition | Exit reason written to state.json |
|---|---|
| `plateau_counter >= 3` AND `branches_covered >= 2` | `plateau_exit` |
| `steps_total >= 30` | `hard_cap_reached` |
| `restart_count > 5` | `max_restarts_exceeded` |

### branches.log contract fields (exact names required)

| Field | Type | Description |
|---|---|---|
| `seq_id` | string | Sequence identifier (e.g. `seq_003`) |
| `step` | integer | Step number within the sequence |
| `packet_hex` | string | Hex-encoded bytes sent |
| `branches_reached` | list[string] | Addresses where hit count > 0 |
| `new_branch_seen` | boolean | True if any address in this list was never seen before |
| `rejected_at` | object or null | `{offset, expected, got}` if server rejected the packet |
| `deciding_operand` | string | Register state at the blocking branch |
| `field_descriptions` | list[object] | Per-field byte-range annotations |
| `next_branch_goal` | string | One-sentence description of the next frontier |
| `risk_notes` | list[string] | Vulnerability hints observed this step |
| `binary_alive` | boolean | False if Frida session became inactive |
| `tool_blocker` | string | `"none"` or reason code if a tool call failed |

---

## Oracle System

Seeds are opaque byte values that unlock comparison gates deep inside the binary's parser. The oracle system extracts them automatically without any source code or prior knowledge.

### Tier 1 — stdlib comparison hooks

Installed at `frida-live_attach` time. Frida hooks the following symbols in every loaded module:

- `strcmp`, `strncmp`, `strcasecmp`, `strncasecmp`
- `memcmp`

For every call where the return value is non-zero (comparison failed), both argument values are captured: `{fn: "strcmp", a0: "USER", a1: "admin"}`. One side is the bytes we sent; the other side is what the binary expected. The expected side becomes a seed indexed by the branch address of the calling instruction.

**Capacity:** Up to 64 comparison events are buffered between HARVEST cycles. The buffer is cleared by `frida-live_reset_comparisons()` before each harvest probe.

### Tier 2 — address-specific argument capture

Installed by `code-analyzer` after each newly-hit function is decompiled. Identifies comparison logic that does not call a stdlib function:

- Custom `verify_token(buf, len)` style functions
- Inline byte-by-byte loops
- `switch` dispatch on a command byte

For each found: calls `frida-live_hook_address(live_addr, label)` which installs a hit counter plus a ring buffer capturing up to 3 arguments (rdi, rsi, rdx) per hit, 16 samples max.

During HARVEST OBSERVE, if Tier 1 yields no comparisons, `net-instrumenter` calls `frida-live_get_address_hits()` and inspects sample arguments to identify expected values.

### Tier 3 — GDB oracle (planned)

When both Tier 1 and Tier 2 yield zero seeds after a HARVEST cycle, the pipeline is blocked by a comparison that neither stdlib hooks nor code-analyzer's address hooks can reach. Tier 3 would spawn the binary under GDB, set a breakpoint at the exact blocking branch instruction, and inspect register values when the breakpoint fires. Not yet implemented.

### Seed naming convention

Seeds are always named mechanically. The pipeline never infers semantic meaning from a seed value.

| Source | Name pattern | Example |
|---|---|---|
| Ghidra static scan (INIT) | `decompile_str_<N>` | `decompile_str_0` |
| Ghidra static scan (code-analyzer) | `decompile_str_<N>` | `decompile_str_3` |
| Frida Tier 1 stdlib hook | `{fn}_a{side}@{index}` | `strcmp_a1@0` |
| Frida Tier 2 address hook | `tier2_a{argidx}@{index}` | `tier2_a1@0` |

Names that imply field semantics (`username`, `password`, `token`, `admin`, `secret`) are forbidden. The binary's field semantics are not known at analysis time.

---

## MCP Servers

### ghidra-headless (`ghidra_headless_analyze.py`)

Exposes Ghidra static analysis via PyGhidra 3.1.0 over stdio JSON-RPC. All results are cached in `ghidra_analysis.json` on first run. The JVM cold-start + full analysis takes ~60–120 seconds per binary; subsequent calls return from cache instantly.

Both `analyze` and `decompile` run PyGhidra in a **subprocess**. The embedded JVM writes initialisation output to stdout which would corrupt the MCP JSON-RPC stdio pipe if run in-process. The subprocess isolates this completely.

**Implementation notes:**
- `sys.setrecursionlimit(10000)` required — PyGhidra's analysis exceeds Python's default 1000 frame limit
- `getExternalEntryPointIterator()` yields `Address` objects — use `sym_table.getPrimarySymbol(addr)` to retrieve symbol names
- Only stderr (fd 2) is redirected to the log file; fd 1 stays as the MCP pipe

| Tool | Input | Output |
|---|---|---|
| `analyze` | `binary_path` | Functions, branches, imports, exports. Writes `ghidra_analysis.json`. ~60 s first run. |
| `list_branches` | `binary_path` | All basic-block branch decision points: address, function name, instruction. Requires cache. |
| `list_imports` | `binary_path` | Imported symbols with addresses. Requires cache. |
| `list_exports` | `binary_path` | Exported entry-point symbols. Requires cache. |
| `list_functions` | `binary_path`, `limit` | All functions with addresses and sizes. Requires cache. |
| `get_xrefs` | `binary_path`, `addr` | All branches referencing the given address. |
| `decompile` | `binary_path`, `addr` | Pseudo-C decompilation of a function. Runs in subprocess. |
| `status` | `binary_path` | Whether `ghidra_analysis.json` cache exists for this binary. |

### frida-live (`frida-mcp-server.py`)

Maintains a single persistent Frida session for the entire pipeline run. One `attach` call per container session; all subsequent tool calls reuse the same injected JS agent. All hooked addresses are accumulated in `_hooked_addrs` and automatically re-installed after `restart`.

**Implementation notes:**
- `frida.spawn([path])` always — no `CAP_SYS_PTRACE` available in the container
- `desock=False` default — `desock.so` conflicts with Frida's stdin control pipe
- `time.sleep(2.0)` after spawn — lets the dynamic linker and process init settle before hooking
- JS agent reads `args[1]` (recv buf pointer) in `onEnter` and reads content in `onLeave` — required because `this.context.rsi` is unreliable after a call returns
- `_call_rpc` tries `exports_sync` first (Frida ≥ 16 API), falls back to `exports`

| Tool | Input | Description |
|---|---|---|
| `attach` | `target`, `desock=false` | Spawn binary + inject JS agent. One call per session. |
| `restart` | — | Kill + re-spawn + reload agent + re-hook all accumulated addresses. |
| `get_pid` | — | PID and path of the spawned process. |
| `hook_branches` | `addrs` (list of hex strings) | Install hit counters. Addresses accumulate for restart re-hook. |
| `get_branch_hits` | — | Hit counts since last `reset_hits`, keyed by address. |
| `reset_hits` | — | Zero all branch counters. Call before each `[SEND]`. |
| `get_last_recv` | — | Last inbound buffer at `recv`/`recvfrom`/`read` as hex string. |
| `get_last_comparisons` | — | Up to 64 recent failed stdlib comparison events `{fn, a0, a1}`. Tier 1 oracle. |
| `reset_comparisons` | — | Clear Tier 1 buffer. Call before a harvest probe. |
| `get_base` | `module` (optional) | Live base address of a module. Used for PIE rebase. |
| `list_exports` | `module` (optional) | Module exports. No arg → scans all modules for network symbols + main module exports. |
| `hook_address` | `addr` (hex), `label` | **Tier 2 oracle** — install hit counter + arg-capture hook (rdi/rsi/rdx, 16 samples). |
| `get_address_hits` | — | All Tier 2 hook hit counts and captured argument samples. |
| `reset_address_hits` | — | Clear all Tier 2 counters and buffers. Call before a harvest probe. |
| `detach` | — | Detach the current Frida session. |
| `status` | — | Returns `session_active`, `script_loaded`, `detach_reason`. |

---

## Data Formats

### state.json

The orchestrator's blackboard. Written by net-instrumenter at INIT and HARVEST OBSERVE. Updated by orchestrator at every `[UPDATE]` step. Never written by any other agent.

```json
{
  "phase": "init | probe_loop | model | done",
  "target": "/workspace/server",
  "channel": "socket:127.0.0.1:2121",
  "rebase_offset": "0x5695c9af4000",
  "image_base": "0x100000",
  "live_base": "0x5695c9bf4000",
  "next_goal": "send PASS command with seed from gate 0x103c11",
  "known_prefix_hex": "555345522061646d696e0d0a",
  "frontier": "0x103c11: strcmp expects TOKEN-LOCAL-12345",
  "branches_covered": 7,
  "new_branch_seen": false,
  "plateau_counter": 1,
  "steps_total": 12,
  "model_version": 3,
  "exit_reason": "",
  "sequences": [
    {"id": "seq_001", "terminal_branch": "0x1044d4", "flaky": false},
    {"id": "seq_002", "terminal_branch": "0x103c11", "flaky": false}
  ],
  "seeds": [
    {
      "name": "decompile_str_0",
      "value": "TOKEN-LOCAL-12345",
      "source": "ghidra_decompile:0x103b7a",
      "gate": "0x103c11"
    },
    {
      "name": "strcmp_a1@0",
      "value": "admin",
      "source": "frida_strcmp@0x103b90",
      "gate": "0x103b90"
    }
  ],
  "restart_count": 0,
  "binary_alive": true,
  "last_restart_reason": ""
}
```

### packet_graph.json

The growing decision graph. Each node is a branch address first reached by a specific packet. Each edge carries the exact bytes sent and field annotations.

```json
{
  "target": "/workspace/server",
  "version": 5,
  "nodes": {
    "ROOT": {"type": "root"},
    "0x1044d4": {
      "branch_addr": "0x1044d4",
      "function": "command_dispatch",
      "description": "first command byte comparison",
      "reached_count": 8
    }
  },
  "edges": [
    {
      "id": "edge_001",
      "from": "ROOT",
      "to": "0x1044d4",
      "sequence_id": "seq_001",
      "packet_fields": [
        {
          "offset": 0, "size": 4, "name": "cmd",
          "value": "55534552",
          "description": "USER command",
          "influence": "dispatched to command_user handler at 0x1044d4"
        }
      ],
      "bytes_hex": "555345520d0a",
      "script": "scripts/send_seq_001_s1.py"
    }
  ],
  "sequences": [
    {
      "id": "seq_001",
      "description": "USER command — pre-auth",
      "steps": [
        {"step": 1, "bytes_hex": "555345520d0a", "goal": "discover command dispatch",
         "branches_reached": ["0x1044d4"]}
      ],
      "terminal_branch": "0x1044d4",
      "flaky": false
    }
  ],
  "field_influence_map": [
    {
      "field_name": "cmd",
      "offset": 0,
      "size": 4,
      "influences_branches": ["0x1044d4"],
      "description": "Command word; first 4 bytes of each line"
    }
  ]
}
```

### vulnerabilities.jsonl

One JSON object per line. Written by code-analyzer in real time during the run. Folded into `protocol_model.json` `risk_hints` by protocol-mapper at model-build time.

```json
{
  "ts": "2026-06-04T12:34:56.789",
  "branch_addr": "0x5695c9c051ba",
  "ghidra_addr": "0x1041ba",
  "function": "command_hi",
  "risk": "buffer_overflow",
  "description": "strcpy(local_28, argv[1]) — dst is 24-byte stack buffer, src is unchecked recv input",
  "decompile_snippet": "strcpy(local_28, argv[1]);",
  "severity": "critical"
}
```

**Recognised risk types:** `buffer_overflow`, `format_string`, `integer_overflow`, `out_of_bounds_write`, `use_after_free`, `stack_overflow`, `resource_exhaustion`

**Severity mapping:** `critical` (direct PC control / stack smash), `high` (heap corruption), `medium` (controlled overflow without direct PC), `low` (information leak, DoS)

### protocol_model.json

The final output written by protocol-mapper. Human- and machine-readable.

```json
{
  "binary": "/workspace/server",
  "name": "SimpleTCP",
  "description": "Line-delimited ASCII command protocol over TCP",
  "transport": {"type": "TCP", "port": 2121},
  "framing": {"format": "line-delimited", "delimiter": "\\r\\n", "encoding": "ASCII"},
  "authentication": {
    "flow": "USER <name> → PASS <password> → auth token issued",
    "token": "TOKEN-LOCAL-12345",
    "token_check": "strcmp at 0x103c11"
  },
  "commands": {
    "USER": {"description": "Set username for auth", "state": "pre-auth", "syntax": "USER <name>"},
    "HI":   {"description": "Echo with buffer overflow in handler", "state": "post-auth",
             "vulnerability": "strcpy into 24-byte stack buffer — no bounds check"}
  },
  "response_codes": {
    "200": "OK", "331": "Password required", "530": "Authentication failed"
  },
  "risk_hints": [
    {"id": "VULN-HI-BO", "function": "command_hi", "type": "stack_buffer_overflow",
     "severity": "critical", "detail": "strcpy(local_28, argv[1]) — 24-byte stack buffer"}
  ],
  "seeds": [
    {"name": "decompile_str_0", "value": "TOKEN-LOCAL-12345", "gate": "0x103c11"}
  ],
  "graph_summary": {
    "total_branches_mapped": 8,
    "decision_tree": "connect → USER → PASS → [auth] → HI|ST|CT|IV|QUIT"
  }
}
```

---

## Installation & Configuration

### Prerequisites

| Requirement | Notes |
|---|---|
| Docker Engine | Any recent version |
| Model backend | Ollama on host (default) or Gemini API key |
| Target binary | Placed in `./workspace/` before starting |
| Host internet | Required for Gemini; not needed for Ollama |

### Build

```bash
./build.sh
```

First build takes ~5–10 minutes (Ghidra 12.1, Frida 17.10.1, PyGhidra 3.1.0, opencode-ai 1.15.13, Python packages). Subsequent builds are fast (layer cache). Rebuild only when `Dockerfile`, `frida-mcp-server.py`, or `ghidra_headless_analyze.py` change.

### Model Backend: Ollama

Ollama must be running on the host before starting the container. The container reaches it at `http://host.docker.internal:11434` (or `http://localhost:11434` with `--network host`).

```bash
# Verify Ollama is reachable and the required model is loaded
curl -s http://localhost:11434/api/tags | python3 -c "
import sys,json; [print(m['name']) for m in json.load(sys.stdin).get('models',[])]"
```

Model references in `opencode.jsonc` use the format `"ollama/<model_name>"`.

### Model Backend: Gemini

Four Dockerfile changes required:

**1. Install the Gemini SDK:**
```dockerfile
RUN apt-get update && apt-get install -y nodejs npm && \
    npm install -g opencode-ai@1.15.13 @ai-sdk/google && \
```

**2. Register the provider in `opencode.jsonc`:**
```json
"gemini": {
  "name": "Google Gemini",
  "npm": "@ai-sdk/google",
  "models": {
    "gemini-2.5-pro":   { "name": "gemini-2.5-pro-preview-06-05" },
    "gemini-2.5-flash": { "name": "gemini-2.5-flash-preview-05-20" },
    "gemini-2.0-flash": { "name": "gemini-2.0-flash" }
  }
}
```

**3. Update agent model assignments:**

| Agent | Recommended |
|---|---|
| `netproto-orchestrator` | `gemini/gemini-2.5-pro` |
| `net-instrumenter` | `gemini/gemini-2.5-flash` |
| `packet-crafter` | `gemini/gemini-2.0-flash` |
| `protocol-mapper` | `gemini/gemini-2.5-pro` |
| `code-analyzer` | `gemini/gemini-2.5-pro` |
| `analysis-supervisor` | `gemini/gemini-2.5-flash` |

**4. Add the API key:**
```dockerfile
ENV GOOGLE_GENERATIVE_AI_API_KEY=AIzaSy...
```

> ⚠️ This bakes the key into the image layer. Do not push to a public registry.

### Agent Delegation Config

The `permission` block in `opencode.jsonc` must be exactly this shape — singular `"permission"`, object-valued `"task"`:

```jsonc
"netproto-orchestrator": {
  "permission": {
    "task": {
      "net-instrumenter":    "allow",
      "packet-crafter":      "allow",
      "protocol-mapper":     "allow",
      "code-analyzer":       "allow",
      "analysis-supervisor": "allow"
    },
    "bash": "deny",
    "glob": "deny",
    "grep": "deny",
    "list": "deny"
  }
}
```

Without the `task` entries the orchestrator cannot spawn sub-agents and runs alone. MCP tool denials (`"ghidra-headless": "deny"` etc.) have no effect in opencode-ai — MCP tool access is controlled exclusively through the agent's prompt FORBIDDEN list.

---

## Running the Pipeline

### Start the container

```bash
./start.sh
```

Runs with `--network host` (required for the binary to bind to real host ports) and `./workspace` bind-mounted to `/workspace`. On container exit, runs `chown -R $(id -u):$(id -g) /workspace` to restore file ownership.

### Invoke the pipeline

Use `phammer` (not `opencode` directly) — it tees all output to a timestamped log file in `/workspace/logs/`:

```bash
phammer "Analyze the binary at /workspace/server. It is a network server.
Run the full protocol inference pipeline and write all output to /workspace/netproto/server/."
```

### Monitor progress (host terminal)

```bash
# Coverage and phase — refreshes every 2 seconds
watch -n2 "cat workspace/netproto/server/state.json | python3 -m json.tool"

# Branch observations as they arrive
tail -f workspace/netproto/server/branches.log | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    print(f\"{e['seq_id']} step={e['step']} new={e['new_branch_seen']} branches={len(e['branches_reached'])}\")
"

# Vulnerabilities found so far
cat workspace/netproto/server/vulnerabilities.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    v = json.loads(line)
    print(v['severity'].upper(), v['function'], '—', v['risk'])
"
```

### Common prompt variants

**Resume an interrupted run:**
```
Resume the protocol inference run for /workspace/server.
Read /workspace/netproto/server/state.json and packet_graph.json.
Ghidra analysis is already cached — skip re-analysis.
Re-attach Frida and continue probing from the current frontier.
```

**Model-only (no new packets):**
```
Do not send any packets.
Delegate to @protocol-mapper to read /workspace/netproto/server/branches.log,
packet_graph.json, and state.json, then write protocol_model.json.
```

**Risk summary:**
```
The run for /workspace/server is done. Read /workspace/netproto/server/protocol_model.json.
List all vulnerabilities with their evidence.
Suggest the best AFL corpus based on confirmed sequences.
```

---

## HTML Report Generation

After a run, the `/generate-protocol-report` skill reads `protocol_model.json` and writes a self-contained `report.html` to the same directory:

```
Read SKILL.md. Follow it exactly to generate an HTML report from
/workspace/netproto/server/protocol_model.json.
```

The report is a single file with no external dependencies — open it in any browser without a server.

### Report sections

| Section | Content |
|---|---|
| **Hero** | Animated counters (commands, response codes, vulnerabilities, port) counting up from zero on load |
| **Probe loop diagram** | All 7 steps rendered as a row of cards; a JS `setInterval` cycles the `.active` highlight every 1.2 s |
| **Packet exchange** | CSS-animated CLIENT ↔ SERVER lane — orange packets fly C→S, cyan packets fly S→C |
| **Session flow** | Every message in the protocol in order, colour-coded by type (banner, command, response, token) |
| **Command cards** | All discovered commands with syntax, auth state, and severity badges for vulnerable commands |
| **Vulnerability cards** | Severity-coloured cards with decompile evidence and synthesised PoC trigger; critical cards pulse with a red glow animation |
| **Manual vs AI** | Side-by-side comparison of manual pentesting vs PacketHammer — time, coverage, seed discovery, cost, reproducibility |
| **Key addresses** | Static Ghidra addresses for all significant functions with PIE rebase note |

### Report spec (`SKILL.md`)

`SKILL.md` in the repo root is the complete machine-readable specification for report generation. It defines the exact HTML template, CSS keyframes, JS blocks, and mapping rules from `protocol_model.json` fields to rendered HTML. The LLM reads it verbatim and follows it exactly — it is not a hint document.

---

## Invariants & Safety Rules

These rules must never be violated. Each was added after a real failure mode.

| Rule | Reason |
|---|---|
| `desock=false` always in `frida-live_attach` | `desock.so` intercepts socket syscalls; the binary never binds to a real OS port, so port discovery finds nothing and the pipeline stalls |
| `frida.spawn()` always, never `frida.attach()` | The container has no `CAP_SYS_PTRACE`; `attach` will always fail |
| `state.json` is never read or written by net-instrumenter in RESET or OBSERVE mode | The orchestrator is the exclusive owner of state updates; if the instrumenter writes state, counters diverge and coverage data corrupts |
| Packet-crafter never reads any file | File reads in the crafter cause it to do "context exploration" instead of immediately connecting; all needed context arrives in the input contract |
| Seed names are always mechanical (`decompile_str_N`, `strcmp_a1@0`, `tier2_a1@0`) | Semantic names (`username`, `password`) imply field meaning that is not known at discovery time; any agent relying on a guessed name will send wrong bytes |
| MCP server process is never killed via bash | The MCP server is managed by opencode; killing it externally leaves opencode in an inconsistent state |
| `image_base` is always read from `ghidra_analysis.json` | Assuming `0x400000` is wrong for most modern PIE binaries; hooks installed at wrong addresses give zero branch hits |
| Net-instrumenter INIT task prompt contains only target path and output dir | Adding extra instructions to the INIT prompt causes the model to override the net-instrumenter's built-in protocol with invented steps |

---

## Troubleshooting

### Sub-agents never called — orchestrator runs alone

**Symptom:** The orchestrator produces analysis text but never calls another agent. No `branches.log` is created.

**Cause:** The `permission.task` block is missing or malformed in `opencode.jsonc`.

**Fix:** Ensure the block uses the singular `"permission"` key with a `"task"` object, not an array:
```jsonc
"permission": { "task": { "net-instrumenter": "allow", ... } }
```
Rebuild with `./build.sh`.

---

### All branch hit counts are 0

**Symptom:** OBSERVE returns branch hits, but all counts are 0. Packets are being sent and received.

**Cause:** `image_base` mismatch — Frida hooks are installed at wrong live addresses.

**Diagnosis:**
```bash
python3 -c "
import json
s = json.load(open('workspace/netproto/server/state.json'))
g = json.load(open('workspace/netproto/server/ghidra_analysis.json'))
print('state  image_base:', s.get('image_base', 'MISSING'))
print('ghidra image_base:', hex(g.get('image_base', 0)))
print('match:', s.get('image_base') == hex(g.get('image_base', 0)))"
```

**Fix:** If they don't match, the net-instrumenter used the wrong base. Check the INIT log and verify step F reads `image_base` from `ghidra_analysis.json`.

---

### Wrong port in state.json

**Symptom:** `channel` is `socket:localhost:9876` (or any port the binary doesn't actually use).

**Cause:** Net-instrumenter guessed a port instead of discovering it, or `desock=true` was passed.

**Fix:** Verify port discovery at step D.5. Ensure `desock=false` in the INIT task prompt (or that the prompt doesn't specify `desock` at all — the net-instrumenter enforces `false` by default).

---

### Binary exits immediately after Frida attach

**Symptom:** `session is gone` error from `frida-live_attach`.

**Cause A:** Previous server instance still holds the port.
```bash
pkill -9 server
```

**Cause B:** `desock=true` was set — binary's `bind()` was intercepted, it received an error, and exited.

---

### MCP error -32000: Connection closed on analyze or decompile

**Cause:** JVM stdout output is contaminating the MCP stdio JSON-RPC pipe.

**Fix:** Both `analyze` and `decompile` in `ghidra_headless_analyze.py` run PyGhidra in a subprocess. If you see this error, the subprocess isolation is broken — check that the worker function is not being called in-process.

---

### Workspace files owned by root after container exit

`start.sh` runs cleanup automatically. If the container was killed before exit:
```bash
docker run --rm -v "$(pwd)/workspace:/workspace" packethammer:latest \
  chown -R $(id -u):$(id -g) /workspace
```

---

## Design Decisions

**Why stdio MCP instead of HTTP?**
opencode-ai launches MCP servers as child processes over stdio. No daemon management, no port allocation, no startup race conditions. The tradeoff is that each agent session gets a fresh MCP server process — which is acceptable because Frida session state is maintained in `_hooked_addrs` and replayed automatically on restart.

**Why a blackboard (shared files) instead of direct agent-to-agent messaging?**
Shared files are inspectable, debuggable, and resumable. If the pipeline crashes mid-run, `state.json` and `packet_graph.json` capture exactly where it was. A direct-call architecture would require a checkpoint system to achieve the same resumability.

**Why does packet-crafter have no file-read access?**
Early versions allowed the crafter to read `state.json` for context. The model would spend its first several tool calls doing "context exploration" (listing directories, reading logs) before connecting to the server. Removing file-read access forces all context to arrive in the input contract, which also makes the crafter's behaviour fully deterministic from the orchestrator's perspective.

**Why are seeds named mechanically?**
A seed named `password` causes every downstream agent to treat it as a known-semantic field and skip the exploration step. A seed named `strcmp_a1@0` is opaque — the crafter applies it when the gate address matches, without making any assumptions about what kind of value it is. This matters for protocols where the "password" is a computed token rather than a human-readable string.

**Why subprocess isolation for PyGhidra?**
The Ghidra JVM writes initialisation banners, progress messages, and debug output to stdout. If PyGhidra runs in-process with the MCP server, this output intermingles with JSON-RPC responses and corrupts the pipe. The subprocess worker redirects the JVM's stdout to /dev/null while keeping the MCP pipe on the parent's fd 1.

**Why `frida.spawn()` instead of `frida.attach()`?**
Docker containers do not have `CAP_SYS_PTRACE` by default, and adding it is a significant security surface expansion. `frida.spawn()` does not require ptrace — Frida starts the binary itself as a child process and injects before the first instruction executes.

---

## Roadmap

### Completed

- [x] End-to-end pipeline producing `protocol_model.json` on a live binary
- [x] `decompile` tool moved to subprocess (JVM isolation)
- [x] Tier 2 oracle: `frida-live_hook_address` + `get_address_hits` + `reset_address_hits`
- [x] `code-analyzer` agent: real-time decompilation, seed extraction, vulnerability scan, Tier 2 hook installation
- [x] `analysis-supervisor` agent: coverage gap analysis, stale-frontier detection, probe strategy recommendation
- [x] Gemini API provider + OpenRouter provider added to Dockerfile
- [x] HTML report generation skill with animated probe-loop diagram, packet exchange, manual vs AI comparison, animated hero counters, critical-vulnerability pulse glow

### Planned

- [ ] **Tier 3 oracle** — GDB breakpoint at blocking branch when Tier 1+2 both yield zero seeds
- [ ] **docker-compose.yml** — Ollama + PacketHammer as a single `docker compose up`
- [ ] **AFL/unicorn corpus generation** — automatically build a fuzzing corpus from `risk_hints` and confirmed sequences
- [ ] **Multi-architecture support** — ARM and RISC-V via Ghidra cross-architecture analysis
- [ ] **Cross-target seed reuse** — query `knowledge.jsonl` for protocol signatures from prior runs before starting Tier 1 harvest
- [ ] **Live dashboard** — auto-refreshing view of `branches.log`, `state.json`, and `vulnerabilities.jsonl`
- [ ] **Challenge-response seeds** — multi-step auth where the token is derived from a server-issued nonce (HMAC, XOR transform)
- [ ] **Binary seed type labeling** — classify each seed as `ascii`, `binary`, or `numeric` to guide crafter field encoding

---

*PacketHammer is an active research tool. The pipeline evolves with each new target binary that breaks it.*
