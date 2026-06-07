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
| [The Agent System](#the-agent-system-server--client-stacks) | Server and Client agent roles and boundaries |
| [Autonomous Pipeline](#autonomous-pipeline) | Hands-off watchdog mode and environment variables |
| [Probe Loop Internals](#probe-loop-internals) | Step-by-step mechanics of each cycle |
| [Oracle System](#oracle-system) | Tier 1, Tier 2, and Tier 3 seed harvesting |
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

---

## Core Concepts

### The Three-Layer Stack

PacketHammer combines three independent layers into a single feedback loop. Each layer sees what the others cannot.

```
┌──────────────────────────────────────────────────────┐
│  Layer 3 — LLM Reasoning                             │
│  Specialized agent stacks (Server or Client) decide  │
│  what to probe next, interpret coverage deltas, and  │
│  build the protocol model. No human decisions.       │
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

### Platform Detection

PacketHammer autonomously determines whether a target binary is for Linux or Windows to select the correct instrumentation stack:

1. **Initial Heuristics**: The orchestrator inspects the file extension (`.exe`, `.dll` for Windows) and path metadata.
2. **Ghidra Analysis**: The selected instrumenter runs `ghidra-headless_analyze`. Ghidra's loader identifies the binary format (ELF for Linux, PE for Windows) and reports it.
3. **Dynamic Confirmation**: During the `INIT` phase, the instrumenter verifies the executable format against its own runtime (e.g., checking for Winsock imports on Windows vs. glibc on Linux).
4. **Fallback**: If the platform is ambiguous, the orchestrator first runs a static analysis task to confirm the format before committing to a specific Frida runtime stack.

---

## System Architecture

Two independent agent stacks — **server** (protocol inference of a listening binary) and **client** (closed-source client reversing) — each with its own primary orchestrator and subagents. They share the same MCP infrastructure.

```
┌────────────────────────────────────────────────────────────────────────┐
│                            Docker Container                             │
│                                                                        │
│  Entry:                                                                │
│   • autonomous  → /opt/run-pipeline.sh   (default CMD, watchdog loop)  │
│   • interactive → phammer run --agent <server|client>-orchestrator …   │
│                                                                        │
│  ┌─ SERVER stack ───────────────┐    ┌─ CLIENT stack ────────────────┐ │
│  │ server-orchestrator (primary)│    │ client-orchestrator (primary) │ │
│  │  owns state.json / graph     │    │  owns state.json / graph      │ │
│  │   ├─► server-instrumenter*   │    │   ├─► client-instrumenter-*   │ │
│  │   ├─► server-packet-crafter  │    │   ├─► client-peer-emulator    │ │
│  │   ├─► server-code-analyzer   │    │   ├─► client-code-analyzer    │ │
│  │   ├─► server-protocol-mapper │    │   ├─► client-protocol-mapper  │ │
│  │   └─► server-analysis-superv │    │   └─► client-analysis-superv  │ │
│  └──────────────┬───────────────┘    └───────────────┬───────────────┘ │
│                 └──────────── shared MCP ─────────────┘                 │
│   ghidra-headless (PyGhidra 3.1.0 → Ghidra 12.1 JVM, stdio)            │
│   frida-live (frida-mcp-server.py, Frida 17.10.1 → target, stdio)      │
│                                                                        │
│  Output root: /workspace/netproto/<target>/…                           │
│  Bind mount:  ./workspace ↔ /workspace   ·   Network: --network host   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## The Agent System (Server & Client Stacks)

Both flows write under the shared output root `/workspace/netproto/<target>/…`. Each orchestrator is `mode: primary`; every other agent is a `mode: subagent`.

### Server stack — protocol inference

| Agent | Trigger | Writes | Role |
|---|---|---|---|
| `server-orchestrator` | User prompt | `state.json`, `graph` | Drives the probe loop. Delegates everything. |
| `server-instrumenter` | INIT/RESET/OBSERVE | `branches.log` | Persistent Frida session, branch hooks, events. |
| `server-packet-crafter`| SEND step | `scripts/send_*.py` | Replays prior steps, sends one new probe packet. |
| `server-code-analyzer` | New branch covered | `vulnerabilities.jsonl` | Decompiles, extracts seeds, scans vulns. |
| `server-protocol-mapper`| 5 steps + exit | `protocol_model.json` | Consolidates logs into a structured model. |
| `server-analysis-superv`| Plateau / 5 steps | — (read-only) | Coverage-gap analysis and strategy. |

### Client stack — closed-source client reversing

| Agent | Trigger | Writes | Role |
|---|---|---|---|
| `client-orchestrator` | User prompt | `state.json`, `graph` | Discovers connect targets, redirects to fake peer. |
| `client-instrumenter` | INIT/DISCOVER/REDIRECT| Frida session | Connect redirection, outbound IO capture. |
| `client-peer-emulator` | REDIRECT | `peer_events.log` | Starts a long-lived local fake peer + scripts. |
| `client-code-analyzer` | New branch covered | seeds/hints | Decompiles connect/send paths, extracts hints. |
| `client-protocol-mapper`| Exit | `protocol_model.json` | Consolidates state, graph, and IO logs. |
| `client-analysis-superv`| Plateau | — (read-only) | Diagnoses connect blockers and redirection issues. |

---

## Autonomous Pipeline

The container's default entrypoint is `/opt/run-pipeline.sh` — a headless watchdog that takes a single prompt and drives the pipeline to a final result with **no human in the loop**.

### Environment Variables

| Env var | Default | Meaning |
|---|---|---|
| `PH_MODE` | `server` | `server` or `client` orchestrator stack |
| `PH_TARGET` | — | Absolute path to the target binary (required) |
| `PH_PROMPT` | — | First prompt (or reads `/workspace/INIT_PROMPT.txt`) |
| `PH_MAX_ITERS` | `50` | Max orchestrator restarts |
| `PH_INTERACTIVE` | `0` | Set to `1` for interactive shell |

---

## Probe Loop Internals

### Server Loop (Probe Cycle)
1. **RESET**: `frida-live_reset_hits()`
2. **SEND**: `server-packet-crafter` sends one goal packet
3. **OBSERVE**: `frida-live_get_branch_hits()` and `frida-live_get_last_recv()`
4. **UPDATE**: Orchestrator updates `state.json` and `packet_graph.json`

### Client Loop (Discovery/Redirect)
1. **DISCOVER**: Observe startup connection attempts
2. **REDIRECT**: Start `client-peer-emulator`, set `frida-live_set_connect_redirects`
3. **OBSERVE**: Capture outbound IO payloads and branch hits

---

## Oracle System

Seeds are opaque byte values that unlock comparison gates.

- **Tier 1**: Always active. Hooks `strcmp`, `memcmp`, etc.
- **Tier 2**: Installed by `code-analyzer`. Hooks custom comparison functions or inline logic.
- **Tier 3**: (Planned) GDB-based register inspection at blocking branches.

---

## Data Formats

### `protocol_model.json`
The final specification including `packet_structure`, `sequences`, `response_codes`, and `risk_hints`.

### `vulnerabilities.jsonl`
Real-time findings: `buffer_overflow`, `format_string`, `integer_overflow`, etc.

---

## Troubleshooting

- **All hits 0**: Check `image_base` in `state.json` vs `ghidra_analysis.json`.
- **Subagents fail**: Check `permission.task` in `opencode.jsonc`.
- **Gemini fails**: Verify API key and model name format (`gemini/<model>`).

---

## Roadmap

- [x] Server and Client autonomous pipelines
- [x] Tier 1 & Tier 2 Oracle
- [x] Automated HTML reports
- [ ] Tier 3 GDB Oracle
- [ ] AFL/Unicorn corpus generation
