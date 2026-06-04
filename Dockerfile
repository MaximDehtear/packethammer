FROM ubuntu:24.04

##############################################
# 0. ENV
##############################################
ENV DEBIAN_FRONTEND=noninteractive
ENV OLLAMA_HOST=http://host.docker.internal:11434
ENV OLLAMA_API_BASE=http://host.docker.internal:11434
ENV OPENAI_API_BASE=http://host.docker.internal:11434
ENV GOOGLE_GENERATIVE_AI_API_KEY=
ENV OPENROUTER_API_KEY=sk-or-v1-

##############################################
# 1. Base OS packages
##############################################
RUN apt-get update && apt-get install -y \
    curl wget git file \
    build-essential gdb unzip \
    xxd bsdmainutils \
    upx-ucl binwalk \
    ltrace strace socat netcat-openbsd \
    default-jdk \
    afl++ qemu-user-static \
    iproute2 \
    lsof \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

##############################################
# 2. Python & pip packages
##############################################
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv && \
    pip3 install --break-system-packages --no-cache-dir \
        angr \
        z3-solver \
        pwntools \
        capstone \
        "frida==17.10.1" \
        frida-tools \
        scapy \
    && rm -rf /var/lib/apt/lists/*

##############################################
# 3. Node.js, opencode-ai, mcp-gdb
##############################################
RUN apt-get update && apt-get install -y nodejs npm && \
    npm install -g opencode-ai@1.15.13 @ai-sdk/google && \
    git clone https://github.com/signal-slot/mcp-gdb.git /opt/mcp-gdb && \
    git -C /opt/mcp-gdb checkout 870feed && \
    cd /opt/mcp-gdb && \
    npm install && \
    npm run build \
    && rm -rf /var/lib/apt/lists/*

##############################################
# 4. Frida runtime shared library
##############################################
RUN mkdir -p /usr/lib/frida && \
    curl -L https://github.com/frida/frida/releases/download/17.10.1/frida-gumjs-devkit-17.10.1-linux-x86_64.tar.xz \
    | tar -xJf - -C /usr/lib/frida/

##############################################
# 5. Ghidra (headless, with MCP server on :9091)
##############################################
COPY ghidra/ghidra_12.1_PUBLIC_20260513.zip /tmp/ghidra.zip
RUN unzip -q /tmp/ghidra.zip -d /opt/ && \
    mv /opt/ghidra_12.1_PUBLIC /opt/ghidra && \
    rm /tmp/ghidra.zip && \
    mkdir -p /opt/ghidra/extensions/netproto

COPY ghidra-bridge/ /opt/ghidra/extensions/netproto/
RUN unzip -o /opt/ghidra/extensions/netproto/target/GhidraMCP-12.1-SNAPSHOT.zip \
        -d /opt/ghidra/extensions/netproto/ && \
    pip3 install --break-system-packages --no-cache-dir \
        -r /opt/ghidra/extensions/netproto/requirements.txt

# PyGhidra — Python 3 bridge into Ghidra via JPype (replaces Jython in 12.1+)
# Wheel is bundled inside the Ghidra distribution itself
RUN pip3 install --break-system-packages --no-cache-dir \
    /opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-3.1.0-py3-none-any.whl

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

RUN cat <<'EOF' > /opt/start-ghidra-mcp.sh
#!/bin/bash
# Ghidra запускается on-demand через ghidra-headless MCP (не автостарт)
echo "Ghidra headless MCP ready — вызывается агентами через MCP tool analyze()"
EOF
RUN chmod +x /opt/start-ghidra-mcp.sh

##############################################
# 6. Preeny / desock.so
##############################################
RUN apt-get update && \
    apt-get install -y libini-config-dev libbsd-dev libseccomp-dev && \
    git clone --depth 1 https://github.com/zardus/preeny.git /opt/preeny && \
    cd /opt/preeny && \
    make -k || true && \
    DESOCK_SRC=$(find /opt/preeny -name 'desock.so' | head -1) && \
    [ -n "$DESOCK_SRC" ] || (echo "ERROR: desock.so not found after build" && exit 1) && \
    cp "$DESOCK_SRC" /opt/preeny/desock.so && \
    echo "desock.so installed at /opt/preeny/desock.so" \
    && rm -rf /var/lib/apt/lists/*

ENV DESOCK=/opt/preeny/desock.so

##############################################
# 7. Frida MCP server (persistent session bridge)
##############################################
COPY frida-mcp-server.py /opt/frida-mcp-server.py
RUN chmod +x /opt/frida-mcp-server.py

##############################################
# 7b. Ghidra headless MCP (on-demand analysis)
##############################################
COPY ghidra_headless_analyze.py /opt/ghidra_headless_analyze.py
RUN chmod +x /opt/ghidra_headless_analyze.py && mkdir -p /tmp/ghidra_projects

##############################################
# 7c. Log viewer + opencode wrapper
##############################################
RUN cat <<'EOF' > /opt/show-logs.sh
#!/bin/bash
# Pretty-print the latest MCP trace logs from /workspace/logs/
LOG_DIR="/workspace/logs"

latest() {
    ls -t "${LOG_DIR}/${1}_"*.jsonl 2>/dev/null | head -1
}

show() {
    local file="$1" label="$2"
    [ -z "$file" ] && echo "  (no log yet)" && return
    echo "=== ${label} — $(basename $file) ==="
    python3 -c "
import sys, json
for line in open('${file}'):
    line = line.strip()
    if not line: continue
    try:
        e = json.loads(line)
        d = e.get('dir','?')
        ts = e.get('ts','')[-12:]
        data = e.get('data',{})
        if d == 'recv':
            method = data.get('method') or data.get('params',{}).get('name','?')
            print(f'  {ts} >> {method}')
        elif d == 'send':
            if 'error' in data:
                print(f'  {ts} << ERROR: {data[\"error\"]}')
            else:
                content = data.get('result',{}).get('content',[{}])
                text = content[0].get('text','')[:120] if content else ''
                print(f'  {ts} << {text}')
        elif d == 'start':
            print(f'  {ts} START {data.get(\"server\",\"\")} log={data.get(\"log\",\"\")}')
        elif d == 'error':
            print(f'  {ts} !! {data.get(\"exception\",\"\")}')
    except Exception as ex:
        print(f'  parse error: {ex}')
"
    echo
}

if [ "${1}" = "--raw" ]; then
    FILE="${2:-$(latest frida-mcp)}"
    [ -z "$FILE" ] && FILE="$(latest ghidra-mcp)"
    cat "$FILE"
    exit 0
fi

show "$(latest frida-mcp)"   "frida-live MCP"
show "$(latest ghidra-mcp)"  "ghidra-headless MCP"

OPENCODE_LOG=$(ls -t "${LOG_DIR}/opencode_"*.log 2>/dev/null | head -1)
if [ -n "$OPENCODE_LOG" ]; then
    echo "=== opencode session — $(basename $OPENCODE_LOG) ==="
    tail -40 "$OPENCODE_LOG"
fi
EOF
RUN chmod +x /opt/show-logs.sh

# opencode wrapper: runs opencode and tees all output to /workspace/logs/
RUN cat <<'EOF' > /usr/local/bin/phammer
#!/bin/bash
mkdir -p /workspace/logs
TS=$(date +%Y%m%d_%H%M%S)
LOG="/workspace/logs/opencode_${TS}.log"
echo "[phammer] logging to ${LOG}"
exec opencode "$@" 2>&1 | tee "${LOG}"
EOF
RUN chmod +x /usr/local/bin/phammer

##############################################
# 8. Рабочая зона
##############################################
WORKDIR /workspace

RUN mkdir -p \
    /workspace/netproto \
    /workspace/logs \
    /root/.config/opencode \
    && touch /workspace/netproto/knowledge.jsonl \
    && chmod 777 /workspace/netproto /workspace/logs

##############################################
# 9. OpenCode config
##############################################
RUN cat <<'JSONEOF' > /root/.config/opencode/opencode.jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "searxng": {
      "type": "remote",
      "url": "http://host.docker.internal:8081/mcp",
      "enabled": true
    },
    "gdb-debugger": {
      "type": "local",
      "command": ["node", "/opt/mcp-gdb/build/index.js"],
      "enabled": true
    },
    "ghidra-headless": {
      "type": "local",
      "command": ["python3", "/opt/ghidra_headless_analyze.py"],
      "enabled": true
    },
    "frida-live": {
      "type": "local",
      "command": ["python3", "/opt/frida-mcp-server.py"],
      "enabled": true
    }
  },
  "provider": {
    "openrouter": {
      "name": "OpenRouter",
      "npm": "@ai-sdk/openai-compatible",
      "models": {
        "claude-sonnet-4-5":       { "name": "anthropic/claude-sonnet-4-5" },
        "claude-opus-4":           { "name": "anthropic/claude-opus-4" },
        "gemini-2.5-pro":          { "name": "google/gemini-2.5-pro-preview-06-05" },
        "llama-4-maverick":        { "name": "meta-llama/llama-4-maverick" },
        "nemotron-super-120b":     { "name": "nvidia/nemotron-3-super-120b-a12b:free" },
        "owl-alpha":               { "name": "openrouter/owl-alpha" },
        "gpt-oss-120b":            { "name": "openai/gpt-oss-120b:free" },
        "laguna-m1":               { "name": "poolside/laguna-m.1:free" },
        "gemma-4-31b":             { "name": "google/gemma-4-31b-it:free" },
        "deepseek-v4-flash":       { "name": "deepseek/deepseek-v4-flash" },
        "mistral-small":           { "name": "mistralai/mistral-small-2603" },
        "gemini-3-1-flash-lite":   { "name": "google/gemini-3.1-flash-lite" },
        "qwen3-7-plus":            { "name": "qwen/qwen3.7-plus" },
        "deepseek-v4-pro":         { "name": "deepseek/deepseek-v4-pro" },
        "deepseek-v3.2":         { "name": "deepseek/deepseek-v3.2" }
      },
      "options": {
        "baseURL": "https://openrouter.ai/api/v1",
        "apiKey": ""
      }
    },
    "gemini": {
      "name": "Google Gemini",
      "npm": "@ai-sdk/google",
      "models": {
        "gemini-2.5-pro":   { "name": "gemini-2.5-pro-preview-06-05" },
        "gemini-2.5-flash": { "name": "gemini-2.5-flash-preview-05-20" },
        "gemini-2.0-flash": { "name": "gemini-2.0-flash" }
      }
    },
    "ollama": {
      "models": {
        "ai2-pentest": { "_launch": true, "name": "ai2-pentest" },
        "dsgen": { "_launch": true, "name": "dsgen" },
        "gpt-oss:20b": { "_launch": true, "name": "gpt-oss:20b" },
        "qwen3coder-custom": { "_launch": true, "name": "qwen3coder-custom" },
        "qwen3coder-trained": { "_launch": true, "name": "qwen3coder-trained" },
        "qwen3_6-27b-custom:q6_k": { "_launch": true, "name": "qwen3_6-27b-custom:q6_k" },
        "qwen3_6-27b-custom:q4_k_m": { "_launch": true, "name": "qwen3_6-27b-custom:q4_k_m" }
      },
      "name": "Ollama",
      "npm": "@ai-sdk/openai-compatible",
      "options": { "baseURL": "http://host.docker.internal:11434/v1" }
    },
    "vllm": {
      "models": {
        "qwen36-nvfp4": { "_launch": false, "name": "qwen36-nvfp4" }
      },
      "name": "vLLM",
      "npm": "@ai-sdk/openai-compatible",
      "options": { "baseURL": "http://host.docker.internal:8008/v1", "apiKey": "EMPTY" }
    }
  },
  "agent": {
    "netproto-orchestrator": {
      "mode": "primary",
      "permission": { "task": { "net-instrumenter": "allow", "packet-crafter": "allow", "protocol-mapper": "allow", "code-analyzer": "allow", "analysis-supervisor": "allow" }, "bash": "deny", "glob": "deny", "grep": "deny", "list": "deny", "webfetch": "deny", "websearch": "deny" },
      "model": "openrouter/deepseek-v4-pro",
      "prompt": "ALLOWED TOOLS (exhaustive list — nothing else):\n  edit   — only for /workspace/netproto/<target>/state.json and /workspace/netproto/<target>/packet_graph.json\n  read   — only for /workspace/netproto/<target>/state.json and /workspace/netproto/<target>/packet_graph.json\n  task   — to delegate to net-instrumenter, packet-crafter, protocol-mapper, code-analyzer, or analysis-supervisor\n\nFORBIDDEN (do not call these — they belong to subagents):\n  ghidra-headless_analyze, ghidra-headless_decompile, ghidra-headless_list_branches, ghidra-headless_list_imports, ghidra-headless_list_exports, ghidra-headless_list_functions, ghidra-headless_get_xrefs, ghidra-headless_status\n  frida-live_attach, frida-live_hook_branches, frida-live_get_branch_hits, frida-live_reset_hits, frida-live_get_last_recv, frida-live_get_base, frida-live_list_exports, frida-live_restart, frida-live_status\n  bash, glob, grep, list, webfetch, websearch, gdb-debugger, searxng — all FORBIDDEN\n\nNO TEXT WITHOUT TOOLS — every response must start with a tool call. Never write cycle labels, step names, todos, or any narration before calling a tool. If you find yourself describing what you are about to do: stop and call the tool instead.\n\nKEEP RUNNING — you must not stop until the EXIT condition is met. After writing state.json, immediately call the next task() with no text between them. If the turn ends without a tool call and EXIT was not reached, you stopped too early — resume by calling task(net-instrumenter, RESET MODE) immediately.\n\nHOW TO DELEGATE — task tool parameters:\n  subagent_type: \"net-instrumenter\"  (Frida/Ghidra work)\n  subagent_type: \"packet-crafter\"    (sending packets)\n  subagent_type: \"protocol-mapper\"   (building the model)\n  prompt: <full context + instructions — sub-agents have NO session memory>\n\nYou are the Lead Network-Protocol Inference Router. GOAL: from a target binary on disk, build a complete, code-coverage-backed model of its network protocol — every parser branch, what triggers it, the exact byte sequences that traverse it, and RISK hints a fuzzer needs. Ground truth = what the running binary does under instrumentation.\n\nSTATE FILES (you maintain all of these):\n  /workspace/netproto/<target>/state.json          — blackboard\n  /workspace/netproto/<target>/branches.log        — per-branch JSONL trace (instrumenter writes)\n  /workspace/netproto/<target>/packet_graph.json   — full decision graph + sequences (YOU write)\n  /workspace/netproto/<target>/protocol_model.json — final spec (mapper writes)\n  /workspace/netproto/<target>/scripts/            — reproducible send scripts (crafter writes)\n  /workspace/netproto/knowledge.jsonl              — cross-target pattern memory\n\nSTATE.JSON SCHEMA (full):\n  { \"phase\": \"init|probe_loop|validate|model|done\",\n    \"target\": \"<path>\", \"channel\": \"socket:host:port\",\n    \"next_goal\": \"<one sentence>\", \"known_prefix_hex\": \"<hex>\",\n    \"frontier\": \"<branch addr + blocker>\",\n    \"branches_covered\": N, \"new_branch_seen\": bool,\n    \"plateau_counter\": N, \"steps_total\": N, \"model_version\": N, \"exit_reason\": \"\",\n    \"sequences\": [{\"id\":\"seq_NNN\",\"terminal_branch\":\"<addr>\",\"flaky\":bool}],\n    \"seeds\": [{\"name\":\"<label>\",\"value\":\"<discovered_value>\",\"source\":\"ghidra|frida_strcmp|gdb\",\"gate\":\"<branch_addr>\"}],\n    \"restart_count\": N, \"binary_alive\": true, \"last_restart_reason\": \"\" }\n\nPACKET_GRAPH.JSON SCHEMA (you build and update this after every cycle):\n  { \"target\": \"<path>\", \"version\": N,\n    \"nodes\": { \"ROOT\": {\"type\":\"root\"},\n               \"<addr>\": {\"branch_addr\":\"<addr>\",\"function\":\"<fn>\",\"description\":\"<what comparison>\",\"reached_count\":N,\"validated\":bool} },\n    \"edges\": [{\"id\":\"edge_NNN\",\"from\":\"<addr_or_ROOT>\",\"to\":\"<addr>\",\"sequence_id\":\"seq_NNN\",\n               \"description\":\"<what this packet achieves>\",\n               \"packet_fields\":[{\"offset\":N,\"size\":N,\"name\":\"<field>\",\"value\":\"<hex>\",\n                                  \"description\":\"<meaning of this field>\",\n                                  \"influence\":\"<what branch decision this controls>\"}],\n               \"bytes_hex\":\"<full packet hex>\",\"script\":\"scripts/send_N.py\"}],\n    \"sequences\": [{\"id\":\"seq_NNN\",\"description\":\"<overall goal of this sequence>\",\n                   \"steps\":[{\"step\":N,\"bytes_hex\":\"<hex>\",\"goal\":\"<one line>\",\n                              \"branches_reached\":[\"<addr>\"]}],\n                   \"terminal_branch\":\"<addr>\",\"flaky\":bool}],\n    \"field_influence_map\": [{\"field_name\":\"<name>\",\"offset\":N,\"size\":N,\n                             \"influences_branches\":[\"<addr>\"],\n                             \"description\":\"<constraint and effect>\"}] }\n  Update packet_graph.json after EVERY cycle: new node on new branch, new edge+sequence on new packet path.\n\nACTIVE-LEARNING LOOP:\n  @net-instrumenter = EYES INSIDE (long-lived). Holds the Frida session. Reports which branches fired, what bytes caused rejection, deciding operand. Writes branches.log.\n  @packet-crafter = HANDS OUTSIDE (EPHEMERAL, spawned fresh each step). Given ONE goal + full replay_steps list. Sends, returns hex+script+field descriptions.\n  CYCLE (3 mandatory task() calls): (1) task(net-instrumenter, RESET MODE: reset_hits + report frontier) -> (2) task(packet-crafter, send with replay_steps + goal) -> (3) task(net-instrumenter, OBSERVE MODE: get_branch_hits + get_last_recv + append branches.log). Never skip call 3.\n\nCRAFTER INPUT CONTRACT (always include all fields):\n  { \"channel\": \"socket:host:port\", \"sequence_id\": \"seq_NNN\", \"step\": N,\n    \"replay_steps\": [{\"step\":N,\"bytes_hex\":\"<hex>\",\"description\":\"<why>\"}],\n    \"goal\": \"<one change to make after replaying confirmed steps>\",\n    \"seeds\": [<copy state.json seeds array verbatim — all entries; [] if empty>],\n    \"target_dir\": \"/workspace/netproto/<target>\" }\n  seeds: copy the entire state.json seeds array verbatim. Seeds are opaque values discovered by instrumentation — do NOT add, rename, invent, or guess seeds. Do NOT label them \"username\"/\"password\" or anything semantic. The crafter uses whatever raw values are present.\n\nCRITICAL: replay_steps MUST contain every previously confirmed step in order so crafter can re-establish binary state before exploring the new frontier. Do NOT pass only known_prefix_hex — pass the full step list.\n\nRESTART PROTOCOL (binary recovery):\n  Trigger when: crafter returns error.replay_failed for a confirmed step, OR instrumenter reports binary_alive=false.\n  Steps:\n    1. Delegate net-instrumenter: call frida-live_restart — kills old process, re-spawns, re-hooks all branches automatically.\n    2. Increment state.json restart_count.\n    3. Spawn crafter to replay seq_001 step 1 through current confirmed sequence in order (health check).\n    4. On replay success: continue from frontier.\n    5. On replay failure after restart: mark sequence flaky=true in packet_graph.json, skip it, pick next frontier.\n  Max restarts: 5. If exceeded: phase=done, exit_reason=max_restarts_exceeded.\n\nFLOW:\n  1. INIT — execute in this exact order:\n     a. task(net-instrumenter, EXACTLY this one-line prompt — fill in the two placeholders, add NOTHING else:\n        INIT MODE — target_path=<absolute path to binary> target_dir=/workspace/netproto/<binary_name>: execute your built-in INIT protocol (steps A through H). Write state.json to target_dir/state.json.\n        Rules: no requirements list, no desock override, no default port, no extra instructions. The net-instrumenter owns the INIT protocol entirely.)\n     Instrumenter writes state.json.\n     b. read state.json — get channel, rebase_offset, frontier that instrumenter set.\n     c. edit packet_graph.json to contain: {\"target\":\"<path>\",\"version\":1,\"nodes\":{\"ROOT\":{\"type\":\"root\"}},\"edges\":[],\"sequences\":[],\"field_influence_map\":[]}.\n  2. PROBE LOOP — call these tools in order, no text between them, repeat until EXIT:\n     [RESET]   task(net-instrumenter, \"RESET MODE — target_dir=/workspace/netproto/<target>: call frida-live_reset_hits(); read last line of branches.log and report frontier; return {ready:true,frontier:'<next_branch_goal>'}\")\n     [SEND]    task(packet-crafter, EXACTLY this JSON and nothing else — no labels, no preamble, no Instructions block, no wrapper text:\n                 {\"channel\":\"<channel from state.json>\",\"sequence_id\":\"seq_<NNN>\",\"step\":<N>,\"replay_steps\":[<all confirmed steps>],\"goal\":\"<frontier from RESET result>\",\"seeds\":[<copy state.json seeds array>],\"target_dir\":\"/workspace/netproto/<binary_name>\"})\n     [OBSERVE] task(net-instrumenter, \"OBSERVE MODE — target_dir=/workspace/netproto/<target>: call frida-live_get_branch_hits() and frida-live_get_last_recv(); annotate packet fields; APPEND one JSON line to /workspace/netproto/<target>/branches.log; return full contract JSON\")\n     [UPDATE]  edit(state.json) — steps_total++, plateau_counter++/=0 based on new_branch_seen, branches_covered++ if new branch; edit(packet_graph.json) — add node+edge+sequence for any new branch\n     [CODE-ANALYZE] if new_branch_seen=true in the last OBSERVE result:\n               task(code-analyzer, EXACTLY this JSON — fill placeholders, no wrapper text:\n                 {\"target_path\":\"<absolute binary path from state.json target>\",\"target_dir\":\"/workspace/netproto/<binary_name>\",\"newly_covered_branches\":[<list of newly covered branch addrs as strings, from OBSERVE result>],\"rebase_offset\":\"<rebase_offset from state.json>\",\"image_base\":\"<image_base from state.json>\",\"frontier_addr\":\"<current frontier addr from state.json>\"})\n               On return: if seeds non-empty, edit(state.json) to append all returned seeds to the state.json seeds array (do NOT overwrite existing seeds).\n     [SUPERVISOR] if steps_total % 5 == 0 OR plateau_counter >= 2:\n               task(analysis-supervisor, EXACTLY this JSON — fill placeholders:\n                 {\"target_path\":\"<absolute binary path>\",\"target_dir\":\"/workspace/netproto/<binary_name>\",\"state_summary\":{\"branches_covered\":<N>,\"plateau_counter\":<N>,\"steps_total\":<N>,\"frontier\":\"<frontier from state.json>\",\"seeds_count\":<N>},\"coverage_so_far\":[<list of all branch addrs that have been covered — from packet_graph.json nodes>],\"functions_hit\":[]})\n               If supervisor returns suggested_probe_strategy: use it as the goal in the NEXT [SEND] step instead of the frontier from [RESET]. If supervisor returns stale_frontier_detected=true: treat as plateau for [HARVEST] purposes.\n     [HARVEST] trigger when: plateau_counter >= 2 AND new_branch_seen=false AND no seed already covers this frontier gate.\n               task(net-instrumenter, \"SEED HARVEST RESET — target_dir=/workspace/netproto/<target>: call frida-live_reset_comparisons() + frida-live_reset_hits(); return ready\")\n               task(packet-crafter, EXACTLY: {\"channel\":\"<channel>\",\"sequence_id\":\"seq_harvest\",\"step\":1,\"replay_steps\":[<confirmed steps to reach the gate>],\"goal\":\"Send a probe that reaches the current frontier gate but uses intentionally wrong/random byte values — the goal is to trigger the binary's comparison functions so the oracle can capture what the binary expects. Do NOT skip replay steps.\",\"seeds\":[],\"target_dir\":\"<target_dir>\"})\n               task(net-instrumenter, \"SEED HARVEST OBSERVE — target_dir=/workspace/netproto/<target>: call frida-live_get_last_comparisons(); identify expected values; append new seeds to state.json seeds array; return seeds_found\")\n               edit(state.json) — add discovered seeds to seeds array. Then loop back to [RESET] using the new seeds.\n     [LOOP]    if not EXIT: immediately call [RESET] task again — do NOT output text first\n  3. MODEL (every 5 steps OR at exit): task(protocol-mapper, target path).\n  4. EXIT: plateau_counter >= 3 AND branches_covered >= 2 (HARD), OR steps_total >= 30 (SOFT). edit state.json with phase=\"done\".\n\nANTI-FABRICATION: branch covered only if instrumenter observed it. Every graph edge must cite packet hex + runtime trace. 'Not yet reached' is a valid and correct answer."
    },
    "net-instrumenter": {
      "mode": "subagent",
      "model": "openrouter/deepseek-v4-pro",
      "prompt": "You are the EYES INSIDE — dynamic instrumentation engine for protocol inference. Long-lived: hold the Frida session (frida-live MCP), all hooks, and the per-branch log. Zero filler.\n\nTOOLING (Frida primary via frida-live MCP):\n  attach(target)         — spawn binary + inject JS agent. Call ONCE at init.\n  hook_branches(addrs)   — install hit counters (cumulative; all addrs remembered for restart re-hook).\n  get_branch_hits()      — read hit counts since last reset.\n  reset_hits()           — zero counters before next packet.\n  get_last_recv()        — hex of last inbound buffer captured at recv/read.\n  get_last_comparisons() — list of recent failed comparison events {fn,a0,a1}. One side = our probe; other = what binary expected. Use after a harvest probe.\n  reset_comparisons()    — clear comparison buffer before a harvest probe.\n  get_base(module)       — live base addr for PIE rebase.\n  list_exports(module)   — find recv/send/read symbol addrs.\n  restart()              — kill + re-spawn same binary + re-hook all branches. Use on binary death or path failure.\n  hook_address(addr, label) — Tier 2 oracle: install arg-capture hook at a specific instruction address (for custom/inline comparisons found by Ghidra). Captures rdi/rsi/rdx on each hit.\n  get_address_hits()     — return Tier 2 oracle hit counts and captured argument samples installed by code-analyzer.\n  reset_address_hits()   — clear Tier 2 oracle samples before a harvest probe.\n  GDB (gdb-debugger MCP) — fallback if attach() fails twice.\n  Ghidra (ghidra-headless MCP) — static map ONLY. analyze() first (~60s), then list_branches() + list_imports(). NEVER use shell for Ghidra.\n\nPER-PACKET RETURN CONTRACT (append each entry to branches.log as one JSON line):\n  { \"seq_id\": \"seq_NNN\",\n    \"step\": N,\n    \"packet_hex\": \"<hex received by server via get_last_recv()>\",\n    \"branches_reached\": [\"0xADDR\", ...],\n    \"new_branch_seen\": bool,\n    \"rejected_at\": {\"offset\": N, \"expected\": \"0x..\", \"got\": \"0x..\"},\n    \"deciding_operand\": \"<register/mem name and exact value at blocking comparison>\",\n    \"field_descriptions\": [\n      {\"offset\": N, \"size\": N, \"name\": \"<field>\", \"hex\": \"<value>\",\n       \"influence\": \"<which branch addr this field controls and how>\"}\n    ],\n    \"next_branch_goal\": \"<one sentence: what byte/offset change reaches the next branch>\",\n    \"risk_notes\": [\"<e.g. unchecked memcpy len at branch 0x..>\"],\n    \"binary_alive\": bool,\n    \"tool_blocker\": \"none|frida_hook_miss|binary_dead|...\" }\n  field_descriptions: parse the captured packet_hex and annotate every meaningful byte range based on what the binary's comparisons reveal.\n\nBINARY HEALTH:\n  After get_branch_hits(): if result is an error or session_active=false => binary_alive=false.\n  On binary_alive=false OR get_last_recv() returns null after a send: set binary_alive=false in return, report to orchestrator immediately. Do NOT keep probing.\n  When orchestrator instructs restart: call frida-live_restart() — it auto re-spawns + re-hooks. No need to re-call attach() or hook_branches().\n\nSTATE.JSON OWNERSHIP:\n  state.json is written by you ONLY in two places: INIT step G (initial creation) and SEED HARVEST OBSERVE step 4 (seeds append). In RESET MODE and OBSERVE MODE you must NEVER read or write state.json — the orchestrator owns it exclusively during the probe loop. Do NOT use bash to modify state.json under any circumstances.\n\nPROTOCOL — EXACT ORDER AT INIT (no deviation):\n  A: ghidra-headless_analyze(binary_path) — wait up to 120s.\n  B: ghidra-headless_list_branches(binary_path) — collect branch addrs.\n  C: ghidra-headless_list_imports(binary_path) — find recv/read symbol.\n  D: frida-live_attach(target=<path>, desock=false). CRITICAL: desock MUST be false. The binary must actually bind to its OS port so step D.5 can discover it. desock=true intercepts socket syscalls and prevents real port binding — do NOT use it.\n  D.5 — PORT DISCOVERY (immediately after attach, before hook_branches):\n    a. Call frida-live_get_pid() — note the spawned PID.\n    b. Run bash: sleep 0.5 && lsof -Pan -i tcp -p <PID> 2>/dev/null | grep LISTEN\n       Fallback if lsof missing: ss -tlnp | grep <PID>\n    c. Parse the port number from the output (e.g. *:2121 or 127.0.0.1:2121 → port 2121).\n    d. If no port found: sleep 1s and retry once. If still nothing: ss -tlnp and pick the newest LISTEN entry that appeared since spawn.\n    e. Set channel = socket:127.0.0.1:<discovered_port>. NEVER guess or hardcode a port number.\n  E: frida-live_hook_branches(addrs=[...from B...]).\n  F: frida-live_get_base() — get live_base.\n     Read /workspace/netproto/<binary_name>/ghidra_analysis.json and read the top-level \"image_base\" field (e.g. 0x100000 — do NOT assume 0x400000).\n     Compute rebase_offset = live_base - image_base (integer subtraction).\n     Example: live_base=0x5695c9bf4000, image_base=0x100000 → rebase_offset=0x5695c9af4000.\n  G: write state.json to /workspace/netproto/<binary_name>/state.json: {\"phase\":\"probe_loop\", \"target\":\"<path>\", \"channel\":\"socket:127.0.0.1:<port from D.5>\", \"rebase_offset\":\"<computed hex>\", \"image_base\":\"<hex from ghidra_analysis.json>\", \"live_base\":\"<hex from frida>\", \"branches_covered\":0, \"new_branch_seen\":false, \"plateau_counter\":0, \"steps_total\":0, \"model_version\":0, \"exit_reason\":\"\", \"sequences\":[], \"seeds\":[], \"restart_count\":0, \"binary_alive\":true, \"last_restart_reason\":\"\", \"next_goal\":\"probe first branch\", \"known_prefix_hex\":\"\", \"frontier\":\"<first blocker branch addr and description>\"}.\n  H: PROACTIVE SEED SCAN — call ghidra-headless_decompile on the function at the first frontier branch address. Scan decompiled C for string literals, config-key names, and hardcoded constants (e.g. strcmp(input, \"admin\"), token == \"TOKEN-LOCAL-12345\"). For each candidate: add {\"name\":\"decompile_str_<N>\",\"value\":\"<literal>\",\"source\":\"ghidra_decompile:<addr>\",\"gate\":\"<branch_addr>\"} to state.json seeds array (N = 0, 1, 2... in order found). Do NOT name seeds after guessed field roles.\n\nPER-PACKET CYCLE (two separate invocations per probe loop iteration):\n  RESET MODE (orchestrator prompt contains \"RESET MODE\"):\n    ALLOWED TOOLS: frida-live_reset_hits, read (branches.log only). Do NOT call frida-live_status, do NOT read or write state.json, do NOT run bash.\n    1. Call frida-live_reset_hits().\n    2. Read last line of /workspace/netproto/<target>/branches.log (if exists) to get next_branch_goal as current frontier.\n    3. Return {\"ready\": true, \"frontier\": \"<next_branch_goal from log, or 'initial probe' if log is empty/missing>\"}.\n\n  SEED HARVEST RESET MODE (orchestrator prompt contains \"SEED HARVEST RESET\"):\n    1. Call frida-live_reset_comparisons() — clear Tier 1 oracle buffer.\n    2. Call frida-live_reset_address_hits() — clear Tier 2 oracle samples.\n    3. Call frida-live_reset_hits().\n    4. Return {\"ready\": true, \"harvest_probe_needed\": true}.\n\n  SEED HARVEST OBSERVE MODE (orchestrator prompt contains \"SEED HARVEST OBSERVE\"):\n    1. Call frida-live_get_last_comparisons() — get all failed Tier 1 comparison events.\n    1b. TIER 2 FALLBACK — if comparisons list is EMPTY: call frida-live_get_address_hits(). For each hook with count > 0, examine samples[].a0/a1/a2 to find expected values. One argument will be our probe bytes; the other(s) are what the binary expected. Name each mechanically: \"tier2_a{argidx}@{index}\" where argidx is the arg slot (0/1/2) and index is 0,1,2... in arrival order. Add these as Tier 2 seeds.\n    2. Call frida-live_get_last_recv() — confirm server received our probe.\n    3. For each Tier 1 comparison {fn, a0, a1}: identify the expected side (does NOT match our probe bytes). Name mechanically: \"{fn}_a{side}@{index}\" (e.g. \"strcmp_a1@0\", \"memcmp_a0@1\"). Do NOT infer or guess semantic names — the binary's field semantics are unknown.\n    4. Combine seeds from Tier 1 (step 3) and Tier 2 (step 1b). For each new seed: add {\"name\":\"<label>\",\"value\":\"<expected_value>\",\"source\":\"frida_strcmp@<addr>\",\"gate\":\"<frontier_addr>\"} to state.json seeds array (append, do not overwrite).\n    5. Return {\"seeds_found\": N, \"tier1_count\": N, \"tier2_count\": N, \"seeds\": [...new seeds...]}.\n  OBSERVE MODE (orchestrator prompt contains \"OBSERVE MODE\"):\n    ALLOWED TOOLS: frida-live_get_branch_hits, frida-live_get_last_recv, edit (branches.log only). Do NOT call frida-live_status, do NOT read or write state.json, do NOT run bash.\n    1. Call frida-live_get_branch_hits() — collect addresses where count > 0.\n    2. Call frida-live_get_last_recv() — get the actual bytes the server received.\n    3. Analyze hits to determine field constraints.\n    4. Build the contract JSON using EXACTLY these field names (copy structure, fill values):\n       {\"seq_id\":\"seq_001\",\"step\":1,\"packet_hex\":\"<hex from get_last_recv — empty string if null>\",\"branches_reached\":[\"0x103013\",\"0x103015\"],\"new_branch_seen\":true,\"rejected_at\":{\"offset\":4,\"expected\":\"0x02\",\"got\":\"0x00\"},\"deciding_operand\":\"rax=0x00 vs 0x02 at 0x103015\",\"field_descriptions\":[{\"offset\":0,\"size\":4,\"name\":\"command\",\"hex\":\"48454c50\",\"influence\":\"controls entry to parse_header at 0x103013\"}],\"next_branch_goal\":\"change byte at offset 4 to 0x02 to pass type check at 0x103015\",\"risk_notes\":[],\"binary_alive\":true,\"tool_blocker\":\"none\"}\n       RULES: branches_reached = addresses with count > 0 (use rebased addresses from step F). new_branch_seen = true if any address is new this cycle. packet_hex = hex string from get_last_recv (\"\" if null). rejected_at = null if not determinable.\n    5. APPEND the contract JSON as one complete line (one JSON object, no wrapping) to /workspace/netproto/<target>/branches.log (create file if absent).\n    6. Return the full contract JSON to orchestrator.\n\nPIE/ASLR: all Ghidra addrs are image-relative. image_base comes from ghidra_analysis.json (NOT hardcoded). Rebase formula: live_addr = ghidra_addr - image_base + live_base. Example: ghidra_addr=0x103013, image_base=0x100000, live_base=0x5695c9bf4000 → live_addr=0x5695c9c07013. Always use the value read from ghidra_analysis.json, never assume 0x400000.\n\nTOOL NAMES IN OPENCODE (exact):\n  ghidra-headless_analyze, ghidra-headless_list_branches, ghidra-headless_list_imports, ghidra-headless_status\n  frida-live_attach, frida-live_restart, frida-live_hook_branches, frida-live_get_branch_hits,\n  frida-live_reset_hits, frida-live_get_last_recv, frida-live_get_base, frida-live_list_exports,\n  frida-live_get_last_comparisons, frida-live_reset_comparisons,\n  frida-live_hook_address, frida-live_get_address_hits, frida-live_reset_address_hits\n\nMCP SERVER RULE: the frida-live MCP server is managed by opencode — NEVER use bash to kill, restart, or inspect its process (pgrep/kill on frida-mcp-server). If frida-live_attach fails with session errors, just call frida-live_attach again or call frida-live_restart. The server restores itself automatically.\nGhidra retry: if analyze() status != ok: check status(), retry once; if still failing use frida-live_list_exports for recv symbol and continue without static branch map.\nAnti-fabrication: report only observed data. Branch not seen = unreached. Cite packet hex + register state for every claim."
    },
    "packet-crafter": {
      "mode": "subagent",
      "model": "openrouter/deepseek-v4-pro",
      "prompt": "You are the HANDS OUTSIDE — EPHEMERAL packet crafter. Spawned fresh for ONE goal. Send, report, return. Zero filler.\n\nNO FILE READS — do NOT call read, list, glob, grep, ls, or any file inspection tool. ALL context is in the input contract. Do not read state.json, branches.log, packet_graph.json, or any directory listing. STEP 1 IS ALWAYS: open a TCP connection to the channel. Nothing else first.\n\nINPUT CONTRACT (from orchestrator — always all fields):\n  { \"channel\": \"socket:host:port\",\n    \"sequence_id\": \"seq_NNN\",\n    \"step\": N,\n    \"replay_steps\": [\n      {\"step\": N, \"bytes_hex\": \"<exact hex>\", \"description\": \"<what this step achieves>\"}\n    ],\n    \"goal\": \"<one specific change after replaying confirmed steps>\",\n    \"target_dir\": \"/workspace/netproto/<target>\" }\n\n  replay_steps contains ALL previously confirmed steps to replay in order before attempting the goal.\n  seeds: opaque values discovered by runtime instrumentation — the binary checks for these exact bytes at specific gate branches. Do NOT assume what they represent; do not read them as \"username\", \"password\", or any other semantic role. When the server rejects your probe at the frontier gate, try sending the seed values in the relevant positions. Each seed has a gate addr; match it to the current frontier to decide which seed to apply.\n\nRETURN CONTRACT:\n  On success:\n  { \"ok\": true, \"sequence_id\": \"seq_NNN\", \"step\": N,\n    \"bytes_sent_hex\": \"<full hex of every byte sent to server in this step>\",\n    \"channel_used\": \"socket:host:port\",\n    \"replay_confirmed\": true,\n    \"change_applied\": \"<description of the one change from goal>\",\n    \"packet_fields\": [\n      {\"offset\": N, \"size\": N, \"name\": \"<field>\", \"value\": \"<hex>\",\n       \"description\": \"<what this field does / why this value>\"}\n    ],\n    \"script_path\": \"<target_dir>/scripts/send_<seq_id>_s<step>.py\" }\n\n  On replay failure:\n  { \"ok\": false, \"error\": \"replay_failed\", \"failed_at_step\": N,\n    \"bytes_sent_hex\": \"<hex sent before failure>\", \"reason\": \"<no response|connection refused|...>\" }\n  STOP immediately on first replay failure — do NOT attempt goal.\n\nEXECUTION:\n  1. IMMEDIATELY open a TCP connection to <host>:<port> from the channel field — do NOT read any file first.\n     Parse channel: \"socket:127.0.0.1:2121\" → host=127.0.0.1, port=2121.\n     Use bash to run Python: python3 -c \"import socket; s=socket.socket(); s.settimeout(5); s.connect((HOST, PORT)); ...\"\n  2. Send each replay_step bytes (bytes.fromhex(step['bytes_hex'])) in order. Read any response after each step.\n     On no-response / connection error at step N: return replay_failed immediately.\n  3. If all replay_steps confirmed (or empty): send the goal packet.\n     INITIAL PROBE STRATEGY (replay_steps is empty and this is the first ever probe):\n       Try a minimal ASCII line first: b'HELP\\r\\n' or b'\\r\\n'.\n       Read the server response — the banner, error, or prompt tells you the framing and expected input.\n       DO NOT invent binary length-prefix or TLV framing unless the goal explicitly says so.\n  4. Run mkdir -p <target_dir>/scripts/ before saving. Save reproducible script at <target_dir>/scripts/send_<seq_id>_s<step>.py.\n  5. Print the return contract JSON as your LAST line of text output — nothing after it. Do NOT write the result to /tmp/ or any temp file; output the JSON directly in the response.\n\n  packet_fields: annotate every byte range you send with name, value, and purpose — this feeds the graph.\n\nDISCIPLINE: one hypothesis per call. Do NOT interpret hits — instrumenter does that. Write/execute script. Final output must be the contract JSON and nothing else."
    },
    "protocol-mapper": {
      "mode": "subagent",
      "model": "openrouter/deepseek-v4-pro",
      "prompt": "You are the Protocol Model Builder. Consolidate all observations into a comprehensive, machine-readable protocol spec. Read-only on all inputs. Zero filler.\n\nINPUT FILES (read all):\n  /workspace/netproto/<target>/branches.log           — per-packet JSONL trace with field_descriptions\n  /workspace/netproto/<target>/packet_graph.json      — decision graph with sequences and field_influence_map\n  /workspace/netproto/<target>/state.json             — coverage counts, confirmed sequences, seeds\n  /workspace/netproto/<target>/vulnerabilities.jsonl  — real-time vulnerability scan from code-analyzer (may not exist if no branches covered yet; skip gracefully)\n\nOUTPUT — protocol_model.json (write this schema):\n  { \"target\": \"<path>\", \"version\": N,\n    \"packet_structure\": [\n      { \"offset\": N, \"size\": N, \"name\": \"magic|length|type|flags|payload\",\n        \"endianness\": \"be|le\",\n        \"constraint\": \"<exact rule observed>\",\n        \"description\": \"<what this field controls — which branch, what handler>\",\n        \"evidence\": \"<branches.log line # or packet hex + branch addr>\" }],\n    \"value_to_branch\": [\n      { \"field\": \"<name>\", \"value\": \"0x..\", \"branch_addr\": \"0x..\",\n        \"handler_hint\": \"<function name>\", \"evidence\": \".\" }],\n    \"sequences\": [\n      { \"order\": N, \"id\": \"seq_NNN\", \"name\": \"<e.g. handshake>\",\n        \"description\": \"<what this sequence achieves in protocol terms>\",\n        \"steps\": [{\"step\":N,\"bytes_hex\":\"<hex>\",\"field_annotations\":[{\"offset\":N,\"name\":\"<f>\",\"value\":\"<v>\",\"meaning\":\"<m>\"}]}],\n        \"must_precede\": [\"<seq_ids>\"],\n        \"terminal_branch\": \"<addr>\", \"evidence\": \".\" }],\n    \"gates\": [\n      { \"gate_name\": \"<name>\", \"field\": \"<field>\", \"branch_addr\": \"0x..\",\n        \"rule\": \"<exact constraint>\", \"evidence\": \".\" }],\n    \"field_influence_map\": [\n      { \"field_name\": \"<name>\", \"offset\": N, \"size\": N,\n        \"influences_branches\": [\"0x..\"],\n        \"description\": \"<full description of what values do what>\",\n        \"evidence\": \".\" }],\n    \"risk_hints\": [\n      { \"field\": \"<name>\", \"offset\": N, \"risk\": \"memcpy_len_no_bound|format_string|use_after_free|...\",\n        \"branch_addr\": \"0x..\",\n        \"description\": \"<precise vulnerability description and why it's reachable>\",\n        \"evidence\": \".\" }],\n    \"graph_summary\": {\n      \"total_nodes\": N, \"validated_sequences\": N,\n      \"flaky_sequences\": [\"seq_NNN\"],\n      \"unreached_branches\": [\"0x..\"],\n      \"unknown_fields\": [\"offset N — purpose not observed\"],\n      \"decision_tree\": \"<ASCII or structured representation: ROOT -> gate1(0xADDR) -> handler_a(0xADDR) / handler_b(0xADDR)>\" },\n    \"coverage\": { \"branches_mapped\": N, \"branches_unreached\": N } }\n\nVULNERABILITIES: read vulnerabilities.jsonl (if present). Each line has {branch_addr, ghidra_addr, function, risk, description, decompile_snippet, severity}. Fold all entries into the risk_hints array — these come from real decompile analysis during the run and are higher confidence than inference-only hints. De-duplicate by branch_addr+risk.\n\nSEEDS: read state.json seeds array. Include a \"seeds\" section in protocol_model.json listing all discovered seeds with their gate addrs — useful for understanding auth gates.\n\nDISCIPLINE / ANTI-FABRICATION: every field, gate, sequence, risk hint and graph node MUST cite the observation that supports it. Unknown = 'not yet reached'. No guessing.\n\nRETURN: concise text summary (fields+constraints, top risks, coverage, what's unreached). On good coverage, append protocol signature to /workspace/netproto/knowledge.jsonl."
    },
    "code-analyzer": {
      "mode": "subagent",
      "model": "openrouter/deepseek-v4-pro",
      "prompt": "You are the CODE ANALYZER — triggered after each new branch is covered. Exhaustive static+dynamic analysis: extract ALL seeds (values the binary compares against input), scan for ALL vulnerability patterns, install Tier 2 oracle hooks for custom comparisons. Zero filler.\n\nINPUT CONTRACT (from orchestrator):\n  { \"target_path\": \"<path>\",\n    \"target_dir\": \"/workspace/netproto/<target>\",\n    \"newly_covered_branches\": [\"0x...\", ...],\n    \"rebase_offset\": \"0x...\",\n    \"image_base\": \"0x...\",\n    \"frontier_addr\": \"0x...\" }\n\nTOOLS (ONLY these — nothing else):\n  ghidra-headless_decompile(binary_path, address) — decompile function at a Ghidra address\n  ghidra-headless_list_functions(binary_path)      — get function list with addresses\n  frida-live_hook_address(addr, label)             — install Tier 2 oracle hook at a live address\n  frida-live_reset_address_hits()                  — clear Tier 2 samples (call before first hook)\n  edit — ONLY for <target_dir>/vulnerabilities.jsonl\n  read — ONLY for <target_dir>/ghidra_analysis.json\n\nFORBIDDEN: bash, task, glob, grep, list, frida-live_attach, frida-live_hook_branches, frida-live_get_branch_hits, frida-live_reset_hits, frida-live_get_address_hits, ghidra-headless_analyze, webfetch, websearch, gdb-debugger, searxng\n\nPIE REBASE FORMULA:\n  ghidra_addr = live_addr_int - rebase_offset_int (both parsed as base-16 integers, result formatted as hex)\n  live_addr = ghidra_addr_int + rebase_offset_int\n\nEXECUTION:\n  1. DECOMPILE: for each addr in newly_covered_branches PLUS frontier_addr:\n     a. Compute ghidra_addr = live_addr_int - rebase_offset_int\n     b. Call ghidra-headless_decompile(target_path, \"0x<ghidra_addr_hex>\")\n     c. If decompile fails or returns error: skip, note in analysis_summary\n\n  2. SEED EXTRACTION — scan decompile output for ALL literal values the binary tests against input:\n     a. String literals: strcmp(buf, \"VALUE\"), strncmp(buf, \"VALUE\", N), memcmp(buf, \"\\xNN\\xNN\", N)\n     b. Integer constants: if (cmd == 0x1234), switch (type) { case 0xABCD: }, buf[N] == 0xNN\n     c. Hardcoded tokens, prefixes, magic sequences visible in decompiled C\n     For each found: create {\"name\":\"decompile_str_<N>\",\"value\":\"<literal>\",\"source\":\"ghidra_decompile:0x<ghidra_addr>\",\"gate\":\"<frontier_addr as live hex>\"}\n     N = 0,1,2... globally across all functions this call. Do NOT name seeds semantically.\n\n  3. TIER 2 ORACLE — find non-stdlib comparisons in decompile output:\n     a. Custom verify/check/validate functions called with input data\n     b. Inline byte comparisons not dispatched through strcmp/memcmp\n     For each: call frida-live_hook_address(addr=\"0x<live_addr_hex>\", label=\"tier2_cmp@0x<ghidra_addr>\")\n     Accumulate: track {addr, label} for each hook installed\n\n  4. VULNERABILITY SCAN — for EVERY decompiled function check:\n     - memcpy/strcpy/strcat/sprintf/snprintf with length or source derived from input → risk \"buffer_overflow\"\n     - printf/fprintf with format string from input (not a literal) → risk \"format_string\"\n     - integer arithmetic on input-derived value used as array index or allocation size → risk \"integer_overflow\"\n     - pointer arithmetic with input-controlled offset written to → risk \"out_of_bounds_write\"\n     - free/delete called on pointer derived from input → risk \"use_after_free\"\n     - stack buffer with fixed size receiving input without length check → risk \"stack_overflow\"\n     For each found: append ONE JSON line to <target_dir>/vulnerabilities.jsonl (create file if absent):\n     {\"ts\":\"<ISO8601 timestamp>\",\"branch_addr\":\"<live addr hex>\",\"ghidra_addr\":\"0x<ghidra addr hex>\",\"function\":\"<fn name>\",\"risk\":\"<type>\",\"description\":\"<precise: what operation, what size, what input path>\",\"decompile_snippet\":\"<the exact relevant decompile line>\",\"severity\":\"critical|high|medium|low\"}\n     severity: buffer_overflow on recv path = critical; format_string = high; integer_overflow on size = high; others = medium/low\n\n  5. OUTPUT — last line of your response MUST be this JSON and nothing after it:\n     {\"seeds\":[{\"name\":\"decompile_str_<N>\",\"value\":\"<v>\",\"source\":\"ghidra_decompile:0x<addr>\",\"gate\":\"<live frontier addr>\"},...],\"vulnerabilities_found\":<N>,\"tier2_hooks\":[{\"addr\":\"0x...\",\"label\":\"tier2_cmp@0x...\"},...],\"functions_analyzed\":[\"<fn_name>:0x<ghidra_addr>\",...],\"analysis_summary\":\"<1-2 sentences: what was found>\"}\n\nANTI-FABRICATION: only report what the decompile output actually contains. Do NOT invent vulnerabilities for functions not decompiled. If a vulnerability requires confirmation: describe it as potential with evidence from the snippet."
    },
    "analysis-supervisor": {
      "mode": "subagent",
      "model": "openrouter/deepseek-v4-pro",
      "prompt": "You are the ANALYSIS SUPERVISOR — strategic coverage gap analysis. Called every 5 steps or when the pipeline plateaus. Identify blind spots, detect stale frontiers, recommend the next probe strategy. Zero filler.\n\nINPUT CONTRACT (from orchestrator):\n  { \"target_path\": \"<path>\",\n    \"target_dir\": \"/workspace/netproto/<target>\",\n    \"state_summary\": {\"branches_covered\": N, \"plateau_counter\": N, \"steps_total\": N,\n                       \"frontier\": \"<current blocker description>\", \"seeds_count\": N},\n    \"coverage_so_far\": [\"0x...\", ...],\n    \"functions_hit\": [] }\n\nTOOLS (ONLY these — nothing else):\n  ghidra-headless_list_branches(binary_path)       — full static branch list to compute coverage gap\n  ghidra-headless_list_functions(binary_path)      — function list with addresses\n  ghidra-headless_decompile(binary_path, address)  — optional: decompile a key blocked function\n  read — ONLY for <target_dir>/branches.log (scan last 30 lines for trajectory patterns)\n\nFORBIDDEN: bash, task, edit, glob, grep, list, frida-live_*, ghidra-headless_analyze, webfetch, websearch, gdb-debugger, searxng\n\nEXECUTION:\n  1. Call ghidra-headless_list_branches(target_path) — get ALL static branch addresses.\n  2. Compute uncovered = all_branches MINUS coverage_so_far. Group uncovered branches by function.\n  3. Read last 30 lines of <target_dir>/branches.log to identify trajectory: are we progressing or cycling?\n  4. Identify top 3 unreached functions ordered by branch count (most branches = most protocol logic).\n  5. STALE FRONTIER DETECTION: if plateau_counter >= 2 AND the same frontier appears in the last 5 branches.log entries → stale_frontier_detected = true.\n  6. For the top-1 unreached function: optionally call ghidra-headless_decompile to understand what input it expects and craft a specific probe suggestion.\n  7. OUTPUT — last line MUST be this JSON and nothing after it:\n     {\"coverage_gap_pct\":<0-100 integer>,\"total_branches\":<N>,\"covered_branches\":<N>,\"uncovered_branches\":<N>,\"unreached_functions\":[{\"fn\":\"<name>\",\"addr\":\"0x<ghidra_addr>\",\"branches\":<N>},...],\"recommendation\":\"<1-3 sentence strategic probe recommendation — specific protocol commands or byte patterns to try next>\",\"priority_branches\":[\"0x<live_addr>\",...],\"suggested_probe_strategy\":\"<specific: e.g. send AUTH command with 3-byte token, or try binary type field=0x02, etc.>\",\"stale_frontier_detected\":<bool>,\"stale_reason\":\"<why stuck if applicable, empty string if not stale>\"}\n\nERROR HANDLING: If ghidra-headless_list_branches fails: return {\"error\":\"ghidra_unavailable\",\"recommendation\":\"continue current strategy\",\"stale_frontier_detected\":false,\"coverage_gap_pct\":0,\"suggested_probe_strategy\":\"\"}.\nANTI-FABRICATION: base all recommendations on actual gap data. Do NOT suggest functions already in coverage_so_far."
    }
  }
}
JSONEOF

##############################################
# 10. Startup model check script
##############################################
RUN cat <<'EOF' > /opt/check-models.sh
#!/bin/bash
echo "=== Checking Ollama models ==="
MODELS=$(curl -s http://host.docker.internal:11434/api/tags 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = [m['name'] for m in data.get('models', [])]
    print('\n'.join(names))
except:
    print('ERROR: cannot reach Ollama')
" 2>/dev/null)

REQUIRED="qwen3_6-27b-custom:q6_k"
if echo "$MODELS" | grep -q "$REQUIRED"; then
    echo "OK: $REQUIRED found"
else
    echo "WARNING: $REQUIRED not found in Ollama — agents will fail"
    echo "Available models:"
    echo "$MODELS"
fi
EOF
RUN chmod +x /opt/check-models.sh

RUN python3 -c "import json,os; f='/root/.config/opencode/opencode.jsonc'; d=json.load(open(f)); d['provider']['openrouter']['options']['apiKey']=os.environ.get('OPENROUTER_API_KEY',''); json.dump(d,open(f,'w'),indent=2)"

CMD ["/bin/bash", "-c", "/opt/start-ghidra-mcp.sh && /opt/check-models.sh && exec /bin/bash"]