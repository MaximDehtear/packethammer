# PacketHammer
## Demo Report

View the interactive PacketHammer protocol report:

👉 [Open SimpleTCP Protocol Report](https://maximdehtear.github.io/packethammer/index.html)

**Autonomous network protocol reverse-engineering via cooperative LLM agents.**

PacketHammer points at a closed-source server binary and — without any source code, documentation, or protocol specification — produces a complete, instrumentation-backed protocol model: every command the server accepts, every code path those commands exercise, the exact byte sequences that traverse each path, seeds needed to pass authentication gates, and a machine-readable vulnerability report.

The entire analysis runs inside a Docker container. You give it a binary; it gives you a structured JSON model and an HTML report.

---

## How It Works

Protocol reverse-engineering is fundamentally an active-learning problem. You need to know what bytes to send in order to observe how the server responds, but you need to observe the server to know what bytes to send. PacketHammer breaks this loop by combining three layers of intelligence operating in a tight feedback cycle.

### The three-layer stack

**Layer 1 — Static analysis (Ghidra)**
Before sending a single byte, PacketHammer runs Ghidra headless analysis on the binary. This produces a complete map of every branch decision point in the code, every imported symbol (`recv`, `strcmp`, `malloc` …), and decompiled pseudo-C for every function that gets hit during the run. The Ghidra MCP server exposes this as a queryable API.

**Layer 2 — Dynamic instrumentation (Frida)**
Frida spawns the target binary as a child process and injects a JS agent. The agent installs hit counters on every branch address discovered by Ghidra. After each packet send, the orchestrator reads exactly which branches were reached and which were not — giving branch-level code coverage as the feedback signal for guiding the next probe.

**Layer 3 — LLM reasoning (opencode agents)**
A stack of specialized agents — one for server-side inference, a parallel one for client-side reversing — reads the coverage data and decides what to do next. They craft packets (or redirect client connections to a local peer), interpret branch hits, decompile newly-covered functions, scan for vulnerabilities in real time, and build the protocol model incrementally. No human makes decisions at any step.

### The probe loop

Each iteration of the core loop is exactly three delegated calls:

```
[RESET]    Clear all Frida hit counters → baseline for this probe
[SEND]     Craft and send one packet toward the current branch frontier
[OBSERVE]  Read which branches were hit, what bytes the server received,
           and what comparisons were evaluated
```

After OBSERVE, the orchestrator updates `state.json` (phase, coverage counters, seeds, frontier) and `packet_graph.json` (a growing decision graph), then immediately loops. Two additional agents fire conditionally:

- **CODE-ANALYZE** — triggered whenever a previously-unseen branch is first hit. Decompiles the covering function, extracts seeds, installs Tier 2 oracle hooks, appends vulnerability findings.
- **SUPERVISOR** — triggered every 5 steps and on coverage plateau. Performs a gap analysis comparing all known branches against all reached branches, and recommends the next probe direction.

The loop exits when the coverage plateau counter reaches 3 (with at least 2 branches confirmed) or when the hard cap of 30 steps is reached.

### Seed harvesting and oracle tiers

Many server protocols reject packets that do not present a valid token, magic value, or credential. The binary compares the received bytes against an expected value deep inside its parser. PacketHammer extracts these expected values automatically using two oracle tiers.

**Tier 1 — stdlib comparison hooks (always active)**
Frida hooks `strcmp`, `strncmp`, `strcasecmp`, and `memcmp` at attach time. Every failed comparison is recorded as `{fn, a0, a1}` — one side is the bytes we sent, the other side is what the binary expected. That expected side becomes a seed.

**Tier 2 — address-specific argument capture (installed by server-code-analyzer)**
When a function contains custom comparison logic that does not call a stdlib function, Tier 1 is blind. After `server-code-analyzer` decompiles the function, it identifies non-stdlib comparisons and calls `frida-live_hook_address(live_addr, label)` to install an argument-capture hook at the specific instruction. The HARVEST step reads these samples as a fallback when Tier 1 yields nothing.

Harvested seeds are written to `state.json` and passed to the server-packet-crafter on subsequent iterations. Seeds are always named mechanically (`strcmp_a1@0`, `tier2_a1@0`, `decompile_str_0`) — the pipeline never infers semantic meaning.

### PIE address rebasing

On modern Linux the kernel loads position-independent executables at a randomised base address each run. Ghidra analyzes the binary at its static load address (e.g. `0x100000`); Frida sees the binary at a different live address (e.g. `0x5695c9bf4000`). Every Frida hook address must be rebased before installation:

```
rebase_offset = live_base − image_base
live_addr     = ghidra_addr − image_base + live_base
```

`image_base` is read from `ghidra_analysis.json` — it is never assumed or hardcoded.

---

## Architecture

Two independent agent stacks — **server** (protocol inference of a listening binary) and
**client** (closed-source client reversing) — each with its own primary orchestrator and
subagents. They never delegate across the boundary and only share the MCP infrastructure.

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
│  Output root: /workspace/netproto/<target>/…   (shared by both modes)  │
│  Bind mount:  ./workspace ↔ /workspace   ·   Network: --network host   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## The Agent System (split server/client stacks)

Both flows write under the shared output root `/workspace/netproto/<target>/…`. Each
orchestrator is `mode: primary`; every other agent is a `mode: subagent` it delegates to via
the `task` tool. Choose a flow with `--agent server-orchestrator` or `--agent client-orchestrator`
(or `PH_MODE` for autonomous runs).

### Server stack — protocol inference of a listening binary

| Agent | Trigger | Owns | Role |
|---|---|---|---|
| `server-orchestrator` | User prompt / `PH_MODE=server` | `state.json`, `packet_graph.json` | Drives the probe loop. Delegates everything — never touches Frida or Ghidra directly. |
| `server-instrumenter` (`-linux` / `-windows`) | INIT / RESET / OBSERVE / HARVEST | `branches.log`, Frida session | Holds the persistent Frida session, installs branch hooks, captures comparison/recv events. |
| `server-packet-crafter` | SEND step | `scripts/send_*.py` | Ephemeral per step — replays confirmed prior steps, then sends one new probe packet. |
| `server-code-analyzer` | Each new branch covered | `vulnerabilities.jsonl` | Decompiles newly-hit functions, extracts seeds, installs Tier 2 hooks, appends vuln findings. |
| `server-protocol-mapper` | Every 5 steps + exit | `protocol_model.json` (+ append `knowledge.jsonl`) | Reads all logs and builds the final structured protocol model. |
| `server-analysis-supervisor` | Every 5 steps or plateau ≥ 2 | — (read-only) | Coverage-gap + stale-frontier analysis; returns `priority_ghidra_branches` and probe strategy. |

### Client stack — closed-source client reversing

| Agent | Trigger | Owns | Role |
|---|---|---|---|
| `client-orchestrator` | User prompt / `PH_MODE=client` | `state.json`, `packet_graph.json`, `client_sends.log`, `io_events.log` | Discovers connect targets, redirects them in-process to a local fake peer, records outbound messages. Sole writer of the two client logs. |
| `client-instrumenter-linux` / `-windows` | INIT / DISCOVER / REDIRECT / TRIGGER / OBSERVE | Frida session | Attaches (`desock=false`), discovers `connect`/`WSAConnect` targets, applies sockaddr redirects, captures outbound IO. |
| `client-peer-emulator` | REDIRECT | `scripts/peer_*.py`, `peer_events.log` | Starts a **long-lived** local fake peer (pid file + readiness probe), logs peer-side observations. Never writes the client logs. |
| `client-code-analyzer` | Each new branch covered | static hints / seeds | Decompiles connect/send/TLS/config paths, extracts hints, installs Tier 2 hooks. |
| `client-protocol-mapper` | Exit (if runtime IO exists) | `protocol_model.json` | Consolidates state, graph, client logs and peer scripts into the outbound model. |
| `client-analysis-supervisor` | Every 5 steps / plateau | — (read-only) | Diagnoses stale connect triggers, missing redirects, empty IO, TLS/cert blockers, endpoint divergence. |

### Agent boundaries

Each agent has strictly-enforced tool access. Both orchestrators have `read`, `edit`, and `task`
only — they cannot call Frida or Ghidra directly, and a server orchestrator cannot delegate client
agents (or vice versa). The packet-crafter has no file-read access — all context arrives in its
input contract. Both analysis-supervisors are read-only (no writes, no delegation) and emit Ghidra
static addresses (`priority_ghidra_branches`); the orchestrator rebases them to live addresses.

Log ownership is explicit. Server: `server-instrumenter` writes `state.json` only at INIT and
HARVEST OBSERVE; the orchestrator owns all other updates. Client: the `client-orchestrator` is the
**sole** writer of `client_sends.log` and `io_events.log` (Frida-originated truth), while
`client-peer-emulator` writes only `peer_events.log`. MCP servers are managed by opencode in both
modes and must never be killed, restarted, or inspected manually.

---

## Quick Start

### Prerequisites

- Docker installed and running
- A model backend: **Ollama** on the host with the required model pulled, or a **Gemini API key**
- Target binary placed in `./workspace/`

```bash
# Verify Ollama is reachable
curl -s http://localhost:11434/api/tags | python3 -c "
import sys,json; [print(m['name']) for m in json.load(sys.stdin).get('models',[])]"
```

### 1. Build

The OpenRouter API key is **not** stored in the repo — pass it at build time from your shell:

```bash
export OPENROUTER_API_KEY=sk-or-...   # your key; stays out of git
./build.sh
```

`build.sh` forwards it via `--build-arg OPENROUTER_API_KEY`, which the build injects into `opencode.jsonc`. Omit it if you only use Ollama or Gemini. Takes ~5–10 minutes on first build (Ghidra + Frida + PyGhidra + opencode). Rebuild after changes to `Dockerfile`, `frida-mcp-server.py`, or `ghidra_headless_analyze.py`.

### 2. Place your binary

```bash
cp /path/to/your/server ./workspace/server
chmod +x ./workspace/server
```

The container sees it as `/workspace/server`.

### 3. Start (interactive TUI)

```bash
./start.sh
```

Runs interactively with `--network host` and `./workspace` bind-mounted to `/workspace`. `start.sh` passes `PH_INTERACTIVE=1`, which drops you into a shell instead of the autonomous runner. On exit, it automatically restores ownership of any files written as root inside the container.

> The container's **default** entrypoint (when no `PH_INTERACTIVE` and no task env is set) is the autonomous runner — see [step 5](#5-autonomous-run-hands-off). Running `./start.sh` (or any container start with no `PH_TARGET`/`PH_PROMPT`) falls back to the interactive shell.

### 4. Run (interactive)

Use `phammer` instead of `opencode` directly — it captures all agent output to a timestamped log file. Pick the orchestrator for your task with `--agent`:

```bash
# Server-side protocol inference
phammer run --agent server-orchestrator "Analyze the binary at /workspace/server. It is a network server.
Run the full protocol inference pipeline and write all output to /workspace/netproto/server/."

# Client-side closed-source reversing (discover connect target, redirect to a local fake peer)
phammer run --agent client-orchestrator "Analyze the client binary at /workspace/client.
Discover where it connects, redirect that connection in-process to a local fake peer,
and record the client's outbound messages. Write output to /workspace/netproto/client/."
```

There are two primary orchestrators — `server-orchestrator` and `client-orchestrator` — each with its own subagent stack, so always pass `--agent` to choose the flow. The orchestrator initialises Frida, runs Ghidra, and begins its loop. No further input is required.

### 5. Autonomous run (hands-off)

The container's default entrypoint is `/opt/run-pipeline.sh` — a headless watchdog that takes a single first prompt and drives the pipeline to a final result with **no human in the loop**. It restarts the orchestrator if it stalls or dies (resuming from `state.json`, never re-INITing), stops on a real terminal condition, writes `RESULT.md`, and sets the container exit code to reflect the outcome.

Drive it entirely through environment variables:

```bash
docker run --rm \
  --network host --add-host host.docker.internal:host-gateway \
  -v "$(pwd)/workspace:/workspace" \
  -e PH_MODE=server \
  -e PH_TARGET=/workspace/server \
  -e PH_PROMPT="Analyze the binary at /workspace/server. Run the full protocol inference pipeline and write all output to /workspace/netproto/server/." \
  packethammer:latest
```

| Env var | Default | Meaning |
|---|---|---|
| `PH_MODE` | `server` | `server` (protocol inference) or `client` (closed-source client reversing) — selects the orchestrator stack |
| `PH_TARGET` | — | Absolute path to the target binary (required) |
| `PH_PROMPT` | — | First prompt; if empty, read from `/workspace/INIT_PROMPT.txt` |
| `PH_MODEL` | — | Optional model id override for the orchestrator |
| `PH_MAX_ITERS` | `50` | Max orchestrator (re)starts before giving up |
| `PH_WALLCLOCK_SEC` | `14400` | Hard wall-clock budget (seconds) |
| `PH_STALL_LIMIT` | `3` | Consecutive no-progress iterations before stopping |
| `PH_INTERACTIVE` | `0` | Set to `1` to drop to an interactive shell instead of running |

Client-mode is the same call with `PH_MODE=client` and a client binary:

```bash
docker run --rm \
  --network host --add-host host.docker.internal:host-gateway \
  -v "$(pwd)/workspace:/workspace" \
  -e PH_MODE=client \
  -e PH_TARGET=/workspace/client \
  -e PH_PROMPT="Discover where /workspace/client connects, redirect it in-process to a local fake peer, and record its outbound messages. Write output to /workspace/netproto/client/." \
  packethammer:latest
```

The final summary lands at `/workspace/netproto/<target>/RESULT.md` (phase, exit reason, coverage, and links to `protocol_model.json` and the evidence logs). Because `./workspace` is bind-mounted, it's available on the host immediately. Exit code `0` means a clean `done`; non-zero means a blocker, stall, or watchdog limit (the reason is in `RESULT.md`).

To debug interactively instead, run with `-e PH_INTERACTIVE=1` (or use `./start.sh`, which keeps the legacy interactive shell) and drive it with `phammer` as in step 4.

---

## Example Prompts

<details>
<summary>Minimal run</summary>

```
Analyze /workspace/server. Run the full protocol inference pipeline.
Write all output to /workspace/netproto/server/.
```
</details>

<details>
<summary>With known port</summary>

```
Analyze the binary at /workspace/server. It listens on TCP port 2121.
Use channel socket:127.0.0.1:2121. Run full protocol inference.
Write output to /workspace/netproto/server/.
```
</details>

<details>
<summary>Client mode — closed-source client (use <code>--agent client-orchestrator</code>)</summary>

```
Analyze the client binary at /workspace/client.
Discover where it tries to connect (resolver/connect), redirect that connection
in-process to a local fake peer, and record the client's outbound messages.
Preserve the original destination alongside the redirect, and write output to
/workspace/netproto/client/.
```
</details>

<details>
<summary>Resume an interrupted run</summary>

```
Resume the protocol inference run for /workspace/server.
Read /workspace/netproto/server/state.json and packet_graph.json.
Ghidra analysis is already cached — skip re-analysis.
Re-attach Frida and continue probing from the current frontier.
```
</details>

<details>
<summary>Build model only (no new packet sends)</summary>

```
Do not send any packets.
Delegate to @server-protocol-mapper to read /workspace/netproto/server/branches.log,
packet_graph.json, and state.json, then write protocol_model.json.
Include all observed sequences with per-step annotations and a vulnerability report.
```
</details>

<details>
<summary>Risk summary after a completed run</summary>

```
The run for /workspace/server is done. Read /workspace/netproto/server/protocol_model.json.
List all vulnerabilities with their evidence.
Which fields are unchecked or partially validated?
Suggest the best starting corpus for AFL based on the confirmed sequences.
```
</details>

<details>
<summary>Generate HTML report</summary>

```
Read SKILL.md. Follow it exactly to generate an HTML report from
/workspace/netproto/server/protocol_model.json.
```

Produces `report.html` — fully self-contained, opens in any browser without a server. Includes an animated probe-loop diagram, live packet exchange visual, command cards, severity-coloured vulnerability cards with PoC triggers, and a manual vs AI comparison section.
</details>

---

## Using Gemini Instead of Ollama

<details>
<summary>Full setup instructions</summary>

### 1. Edit the Dockerfile — install the Gemini SDK

Find the `npm install -g opencode-ai` line and add `@ai-sdk/google`:

```dockerfile
RUN apt-get update && apt-get install -y nodejs npm && \
    npm install -g opencode-ai@1.15.13 @ai-sdk/google && \
```

### 2. Register the Gemini provider

In `config/opencode/opencode.jsonc`, add a `"gemini"` entry to the `"provider"` object:

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

### 3. Update model assignments

Model assignments live in `config/opencode/opencode.jsonc` (the `agent.<name>.model` field),
which is COPYed into the image at build. Edit that file, then `./build.sh`. The table below is for
the server stack; apply the same per-role choices to the matching `client-*` agents.

| Agent role (server / client) | Recommended model |
|---|---|
| `*-orchestrator` | `gemini/gemini-2.5-pro` |
| `*-instrumenter*` | `gemini/gemini-2.5-flash` |
| `server-packet-crafter` / `client-peer-emulator` | `gemini/gemini-2.0-flash` |
| `*-protocol-mapper` | `gemini/gemini-2.5-pro` |
| `*-code-analyzer` | `gemini/gemini-2.5-pro` |
| `*-analysis-supervisor` | `gemini/gemini-2.5-flash` |

### 4. Add your API key to the Dockerfile

```dockerfile
ENV GOOGLE_GENERATIVE_AI_API_KEY=AIzaSy...your_key_here...
```

`@ai-sdk/google` reads `GOOGLE_GENERATIVE_AI_API_KEY` automatically. Rebuild:

```bash
./build.sh
```

> **Security note:** This bakes the API key into the image layer. Do not push the image to a public registry or commit the Dockerfile to a public repository.

> The container runs with `--network host`, so it reaches `generativelanguage.googleapis.com` directly as long as the host has internet access. No proxy configuration is required.

</details>

---

## Output Files

When the run completes (`phase: done` in `state.json`):

| File | Contents |
|------|----------|
| `state.json` | Final phase, coverage counts, exit reason, all confirmed sequences, harvested seeds |
| `branches.log` | Per-packet JSONL trace — every probe sent, branches reached, field annotations, oracle output |
| `packet_graph.json` | Full decision graph: nodes keyed by branch address, edges with packet bytes and field influence map |
| `protocol_model.json` | Complete protocol specification: transport, framing, commands, response codes, session flow, vulnerabilities |
| `vulnerabilities.jsonl` | Real-time findings appended by server-code-analyzer during the run — includes decompile evidence |
| `ghidra_analysis.json` | Static analysis cache — reused across restarts and runs on the same binary |
| `scripts/send_<seq>_s<step>.py` | Reproducible standalone Python scripts for every discovered sequence step |

---

## Monitoring a Live Run

From a second terminal on the host while the container is running:

```bash
# Watch state.json — coverage counts, phase, current frontier
watch -n2 "cat workspace/netproto/server/state.json | python3 -m json.tool"

# Stream branch observations as they arrive
tail -f workspace/netproto/server/branches.log | python3 -c "
import sys,json
for line in sys.stdin:
    e=json.loads(line)
    print(e.get('seq_id'), e.get('step'), e.get('new_branch_seen'), e.get('branches_reached'))"

# Inspect the growing decision graph
cat workspace/netproto/server/packet_graph.json | python3 -m json.tool
```

---

## MCP Servers

### `ghidra-headless`

Static analysis via PyGhidra 3.1.0. All results are cached in `ghidra_analysis.json` on first run (~60–120 s for JVM cold start + full analysis). Subsequent calls return from cache instantly.

Both `analyze` and `decompile` run PyGhidra in a subprocess — the embedded JVM writes to stdout which would corrupt the MCP JSON-RPC stdio pipe if run in-process.

| Tool | Description |
|------|-------------|
| `analyze` | Full analysis: functions, branches, imports, exports. Writes `ghidra_analysis.json`. |
| `list_branches` | All basic-block branch decision points with address, function, and instruction. Requires cache. |
| `list_imports` | Imported symbols (`recv`, `read`, `send`, `malloc` …). Requires cache. |
| `list_exports` | Exported entry-point symbols. Requires cache. |
| `list_functions` | All functions with addresses and sizes. Requires cache. |
| `get_xrefs` | All branches referencing a given address. |
| `decompile` | Decompile a function to pseudo-C via subprocess worker. |
| `status` | Whether analysis is cached for the given binary. |

### `frida-live`

Persistent Frida session — one attach per container run, unlimited queries. All hooked addresses are accumulated in `_hooked_addrs` and automatically re-installed after a `restart` call. Uses `frida.spawn()` (no `CAP_SYS_PTRACE` required).

| Tool | Description |
|------|-------------|
| `attach` | Spawn binary via `frida.spawn` and inject the JS agent. Call once per session. |
| `restart` | Kill the spawned process, re-spawn, reload the JS agent, re-hook all previously installed addresses. |
| `get_pid` | PID and path of the currently spawned process. |
| `hook_branches` | Install hit counters at a list of branch addresses. Addresses accumulate across calls. |
| `get_branch_hits` | Hit counts since the last `reset_hits`, keyed by address. |
| `reset_hits` | Zero all branch counters. Call before each packet send. |
| `get_last_recv` | Last inbound buffer at `recv`/`read` as a hex string. |
| `get_last_comparisons` | Up to 64 recent failed `strcmp`/`memcmp` events `{fn, a0, a1}` — Tier 1 oracle. |
| `reset_comparisons` | Clear the Tier 1 comparison buffer. Call before a harvest probe. |
| `get_base` | Live base address of a module. Used to compute the PIE rebase offset. |
| `list_exports` | Module exports. With no module argument, scans all modules for network symbols. |
| `hook_address` | **Tier 2 oracle** — install a hit counter + argument capture hook at a specific instruction address. Captures up to 3 args (rdi/rsi/rdx), 16 samples max. |
| `get_address_hits` | All Tier 2 hook hit counts and captured argument samples. |
| `reset_address_hits` | Clear all Tier 2 counters and sample buffers. Call before a harvest probe. |
| `detach` | Detach the current Frida session. |
| `status` | Returns `session_active`, `script_loaded`, `detach_reason`. |

---

## Data Schemas

<details>
<summary>state.json</summary>

Written by `server-instrumenter` at INIT. Updated by `orchestrator` after each OBSERVE cycle.

```json
{
  "phase": "init|probe_loop|model|done",
  "target": "/workspace/server",
  "channel": "socket:127.0.0.1:2121",
  "rebase_offset": "0x5695c9af4000",
  "image_base": "0x100000",
  "live_base": "0x5695c9bf4000",
  "frontier": "0xADDR: description of blocking comparison",
  "branches_covered": 7,
  "plateau_counter": 0,
  "steps_total": 12,
  "exit_reason": "",
  "sequences": [
    {"id": "seq_001", "terminal_branch": "0x401200", "flaky": false}
  ],
  "seeds": [
    {"name": "decompile_str_0", "value": "TOKEN-LOCAL-12345",
     "source": "ghidra_decompile:0x103b7a", "gate": "0x103c11"},
    {"name": "strcmp_a1@0", "value": "0x4d61676963",
     "source": "frida_memcmp@0x103c25", "gate": "0x103c25"}
  ],
  "restart_count": 0,
  "binary_alive": true
}
```

`rebase_offset = live_base − image_base`. `image_base` is always read from `ghidra_analysis.json`, never hardcoded or assumed.
</details>

<details>
<summary>branches.log (one JSON object per line)</summary>

Written by `server-instrumenter` in OBSERVE MODE after each packet send.

```json
{
  "seq_id": "seq_001",
  "step": 3,
  "packet_hex": "555345520d0a",
  "branches_reached": ["0x1044d4", "0x103eff"],
  "new_branch_seen": true,
  "rejected_at": {"offset": 0, "expected": "PASS", "got": "USER"},
  "deciding_operand": "rax=USER vs PASS at 0x103f12",
  "field_descriptions": [
    {"offset": 0, "size": 4, "name": "cmd", "hex": "55534552",
     "influence": "command dispatch at 0x1044d4"}
  ],
  "next_branch_goal": "send PASS command to reach auth gate at 0x103f12",
  "risk_notes": [],
  "binary_alive": true,
  "tool_blocker": "none"
}
```
</details>

<details>
<summary>vulnerabilities.jsonl (one JSON object per line)</summary>

Written by `server-code-analyzer` in real time as functions are decompiled.

```json
{
  "ts": "2026-06-04T12:34:56.789",
  "branch_addr": "0x5695c9c07200",
  "ghidra_addr": "0x1041ba",
  "function": "command_hi",
  "risk": "buffer_overflow",
  "description": "strcpy(dst, src) where dst is a 24-byte stack buffer and src is unbounded recv input",
  "decompile_snippet": "strcpy(local_28, argv[1]);",
  "severity": "critical"
}
```
</details>

---

## Docker Environment

| Component | Details |
|-----------|---------|
| Base OS | Ubuntu 24.04 |
| System tools | `gdb`, `strace`, `binwalk`, `upx`, AFL++, `iproute2`, `net-tools`, `lsof` |
| Java | OpenJDK 21 (Ghidra requirement) |
| Python packages | `angr`, `z3`, `pwntools`, `capstone`, `frida==17.10.1`, `frida-tools`, `scapy` |
| PyGhidra | 3.1.0 at `/opt/ghidra/`; `GHIDRA_INSTALL_DIR=/opt/ghidra` |
| Ghidra | `ghidra_12.1_PUBLIC` at `/opt/ghidra/` |
| Node.js / opencode | `opencode-ai@1.15.13` |
| Workspace | `/workspace` bind-mounted from `./workspace` on host |

The container runs as root (`--network host` required for host port sharing). `start.sh` runs a `chown` cleanup pass on exit to return workspace ownership to the host user.

---

## Debugging

All logs land in `./workspace/logs/` and are accessible from the host throughout the run.

| File | Contents |
|------|----------|
| `frida-mcp_<ts>.jsonl` | Every JSON-RPC call to `frida-live` + Frida C-layer stderr |
| `ghidra-mcp_<ts>.jsonl` | Every JSON-RPC call to `ghidra-headless` + JVM stderr |
| `opencode_<ts>.log` | Full agent session output written by the `phammer` wrapper |

```bash
# Inside the container — pretty-print latest session
show-logs.sh

# From the host — stream frida tool calls with truncated responses
python3 -c "
import json, glob
f = sorted(glob.glob('workspace/logs/frida-mcp_*.jsonl'))[-1]
for line in open(f):
    e = json.loads(line)
    d, ts = e['dir'], e['ts'][-8:]
    if d == 'recv':
        name = (e['data'].get('params') or {}).get('name') or e['data'].get('method','?')
        print(ts, '>>', name)
    elif d == 'send':
        text = ((e['data'].get('result') or {}).get('content') or [{}])[0].get('text','')
        print(ts, '<<', text[:80])
    elif d == 'error':
        print(ts, '!!', e['data'].get('exception',''))
"

# All errors across all log files
grep '"dir": "error"' workspace/logs/*.jsonl
```

---

## Troubleshooting

<details>
<summary>Sub-agents are never called — orchestrator runs alone</summary>

The `permission` block in `opencode.jsonc` is missing or malformed. It must use the singular `"permission"` key with a `"task"` object mapping each sub-agent name to `"allow"`:

```jsonc
"permission": {
  "task": {
    "server-instrumenter":    "allow",
    "server-packet-crafter":      "allow",
    "server-protocol-mapper":     "allow",
    "server-code-analyzer":       "allow",
    "server-analysis-supervisor": "allow"
  }
}
```

Rebuild with `./build.sh` to pick up the fix.
</details>

<details>
<summary>All branch hit counts are 0</summary>

The most common cause is a wrong `image_base` — hooks are installed at incorrect live addresses, so no branch is ever matched. Verify:

```bash
python3 -c "
import json
s = json.load(open('workspace/netproto/server/state.json'))
g = json.load(open('workspace/netproto/server/ghidra_analysis.json'))
print('state  image_base:', s.get('image_base', 'MISSING'))
print('ghidra image_base:', hex(g.get('image_base', 0)))
print('match:', s.get('image_base') == hex(g.get('image_base', 0)))"
```

If they don't match, the server-instrumenter read or assumed a wrong base. Check the INIT log and rebuild.
</details>

<details>
<summary>Wrong port in state.json (e.g. socket:localhost:9876)</summary>

The server-instrumenter guessed a port instead of discovering it. After INIT, it must run `lsof -Pan -i tcp -p <PID>` or `ss -tlnp | grep <PID>` to read the actual listening port. Check that the INIT prompt does not pass `desock=true` — with desock active the binary intercepts socket syscalls and never binds to a real OS port, so discovery finds nothing.
</details>

<details>
<summary>"bind failed: Address already in use" / "session is gone"</summary>

A previous server instance is still running from a prior Frida session:

```bash
pkill -9 server
```
</details>

<details>
<summary>Workspace files are owned by root after the container exits</summary>

`start.sh` runs a `chown` cleanup pass automatically. If the container was killed with Ctrl+C before that ran:

```bash
docker run --rm -v "$(pwd)/workspace:/workspace" packethammer:latest \
  chown -R $(id -u):$(id -g) /workspace
```
</details>

<details>
<summary>Gemini agents fail silently</summary>

1. **Verify the API key is set** inside the container: `echo $GOOGLE_GENERATIVE_AI_API_KEY`
2. **Verify the model name format**: must be `"gemini/<model_key>"` matching a key defined in the `"gemini"` provider block
3. **Test internet connectivity** from inside the container:
   ```bash
   curl -s "https://generativelanguage.googleapis.com/v1beta/models?key=${GOOGLE_GENERATIVE_AI_API_KEY}" \
     | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK:', len(d.get('models',[])), 'models') if 'models' in d else print('ERROR:', d)"
   ```
4. **Verify the SDK is installed**: `npm list -g @ai-sdk/google` inside the container. If missing, add it to the `npm install -g` line and rebuild.
</details>

---

## Directory Structure

```
packethammer/
├── README.md
├── SKILL.md                         — /generate-protocol-report skill specification
├── LICENSE.md
├── COMMERCIAL-LICENSE.md
├── Dockerfile                       — image build (COPYs config/, injects API key)
├── build.sh                         — docker build wrapper
├── start.sh                         — interactive TUI launcher (PH_INTERACTIVE=1) + post-exit chown
├── config/                          — tracked opencode config + autonomous runner
│   ├── opencode/opencode.jsonc      — providers, models, per-agent permissions/wiring
│   ├── opencode/agents/*.md         — server-* and client-* agent prompts
│   └── run-pipeline.sh              — autonomous headless runner (watchdog → RESULT.md)
├── frida-mcp-server.py              — frida-live MCP server (Tier 1 + 2 oracle + client redirect/IO)
├── ghidra_headless_analyze.py       — ghidra-headless MCP server (stdio JSON-RPC, PyGhidra)
├── ghidra/
│   └── ghidra_12.1_PUBLIC_20260513.zip
├── ghidra-bridge/                   — GhidraMCP plugin (Ghidra HTTP extension + MCP bridge)
│   ├── bridge_mcp_ghidra.py         — MCP adapter that speaks HTTP to the Ghidra plugin
│   ├── src/                         — Java source for the Ghidra extension
│   ├── target/
│   │   └── GhidraMCP-12.1-SNAPSHOT.zip
│   └── requirements.txt
└── workspace/                       — bind-mounted to /workspace inside the container
    ├── server                       — target binary (place yours here)
    └── netproto/
        ├── knowledge.jsonl          — cross-target protocol signature memory
        └── server/                  — created at runtime, one directory per binary
            ├── state.json
            ├── branches.log
            ├── packet_graph.json
            ├── protocol_model.json
            ├── vulnerabilities.jsonl
            ├── ghidra_analysis.json
            └── scripts/
                └── send_<seq>_s<step>.py
```

## License

This project is source-available for personal, educational, research,
and non-commercial use only.

Commercial use is not allowed without a separate paid commercial license.

See [LICENSE](./LICENSE) for non-commercial terms.

For commercial licensing, see [COMMERCIAL-LICENSE.md](./COMMERCIAL-LICENSE.md)
or contact: maxim.dehtear@yahoo.com
