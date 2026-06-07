#!/bin/bash
# PacketHammer autonomous runner.
# Goal: first prompt in -> final result out, with NO human in the loop.
# Drives the server- or client-orchestrator headlessly, restarts it if it stalls or dies,
# stops on a real terminal condition, and writes RESULT.md.
#
# Inputs (env):
#   PH_MODE          server | client            (default: server)
#   PH_TARGET        absolute path to target binary (required unless PH_INTERACTIVE=1)
#   PH_PROMPT        first prompt text; if empty, read from /workspace/INIT_PROMPT.txt
#   PH_MODEL         optional model id override for the orchestrator
#   PH_MAX_ITERS     max orchestrator (re)starts          (default: 50)
#   PH_WALLCLOCK_SEC hard wall-clock budget in seconds    (default: 14400 = 4h)
#   PH_STALL_LIMIT   consecutive no-progress iters before giving up (default: 3)
#   PH_INTERACTIVE   if 1, drop to an interactive shell instead of running
set -uo pipefail

if [ "${PH_INTERACTIVE:-0}" = "1" ]; then
    echo "[run-pipeline] PH_INTERACTIVE=1 -> interactive shell"
    exec /bin/bash
fi

PH_MODE="${PH_MODE:-server}"
PH_TARGET="${PH_TARGET:-}"
PH_PROMPT="${PH_PROMPT:-}"
PH_MODEL="${PH_MODEL:-}"
PH_MAX_ITERS="${PH_MAX_ITERS:-50}"
PH_WALLCLOCK_SEC="${PH_WALLCLOCK_SEC:-14400}"
PH_STALL_LIMIT="${PH_STALL_LIMIT:-3}"

if [ "$PH_MODE" != "server" ] && [ "$PH_MODE" != "client" ]; then
    echo "[run-pipeline] FATAL: PH_MODE must be 'server' or 'client' (got '$PH_MODE')"; exit 64
fi
if [ -z "$PH_PROMPT" ] && [ -f /workspace/INIT_PROMPT.txt ]; then
    PH_PROMPT="$(cat /workspace/INIT_PROMPT.txt)"
fi
if [ -z "$PH_TARGET" ]; then
    echo "[run-pipeline] FATAL: PH_TARGET (absolute path to target binary) is required"; exit 64
fi
if [ -z "$PH_PROMPT" ]; then
    echo "[run-pipeline] FATAL: no first prompt (set PH_PROMPT or /workspace/INIT_PROMPT.txt)"; exit 64
fi

AGENT="${PH_MODE}-orchestrator"
TARGET_NAME="$(basename "$PH_TARGET")"
TARGET_DIR="/workspace/netproto/${TARGET_NAME}"
STATE="${TARGET_DIR}/state.json"
mkdir -p "$TARGET_DIR" /workspace/logs

# --- helpers -----------------------------------------------------------------
state_field() {  # $1=field  -> prints value or empty
    python3 - "$STATE" "$1" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: d={}
v=d.get(sys.argv[2],"")
print("" if v is None else v)
PY
}

is_done() {  # exit 0 if terminal
    python3 - "$STATE" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: sys.exit(1)
phase=d.get("phase"); er=(d.get("exit_reason") or "").strip(); tb=(d.get("tool_blocker") or "none")
sys.exit(0 if (phase=="done" or er or tb not in ("none","")) else 1)
PY
}

set_exit_reason() {  # $1=reason — only sets if not already terminal
    python3 - "$STATE" "$1" <<'PY'
import json,sys
p,reason=sys.argv[1],sys.argv[2]
try: d=json.load(open(p))
except Exception: d={}
if not (d.get("exit_reason") or "").strip():
    d["exit_reason"]=reason
d.setdefault("phase","done")
json.dump(d,open(p,'w'),indent=2)
PY
}

# --- watchdog loop -----------------------------------------------------------
start_ts=$(date +%s)
iter=0
last_steps="__init__"
stall=0
echo "[run-pipeline] mode=$PH_MODE agent=$AGENT target=$PH_TARGET dir=$TARGET_DIR"

while : ; do
    iter=$((iter+1))
    if [ "$iter" -eq 1 ]; then
        PROMPT="$PH_PROMPT"
    else
        PROMPT="CONTINUE the ${PH_MODE} protocol pipeline for target ${PH_TARGET}. Read ${STATE} and resume from its current phase WITHOUT resetting progress (do not re-INIT if state already exists). Keep going until phase=done or a real blocker is recorded."
    fi
    echo "[run-pipeline] iter ${iter}/${PH_MAX_ITERS} starting ${AGENT}"
    if [ -n "$PH_MODEL" ]; then
        phammer run --agent "$AGENT" --model "$PH_MODEL" "$PROMPT"
    else
        phammer run --agent "$AGENT" "$PROMPT"
    fi

    if is_done; then
        echo "[run-pipeline] terminal condition reached"; break
    fi

    now=$(date +%s)
    if [ $((now - start_ts)) -ge "$PH_WALLCLOCK_SEC" ]; then
        echo "[run-pipeline] wall-clock budget exhausted"; set_exit_reason "watchdog_timeout"; break
    fi
    if [ "$iter" -ge "$PH_MAX_ITERS" ]; then
        echo "[run-pipeline] max iterations reached"; set_exit_reason "watchdog_limit"; break
    fi

    steps="$(state_field steps_total)"
    if [ "$steps" = "$last_steps" ]; then
        stall=$((stall+1))
        echo "[run-pipeline] no progress (steps_total=$steps, stall=$stall/$PH_STALL_LIMIT)"
    else
        stall=0; last_steps="$steps"
    fi
    if [ "$stall" -ge "$PH_STALL_LIMIT" ]; then
        echo "[run-pipeline] stalled — no progress for $PH_STALL_LIMIT iterations"; set_exit_reason "stalled"; break
    fi
done

# --- assemble final result ---------------------------------------------------
python3 - "$STATE" "$TARGET_DIR" "$PH_MODE" "$PH_TARGET" <<'PY'
import json,sys,os,datetime
state_path,tdir,mode,target=sys.argv[1:5]
try: st=json.load(open(state_path))
except Exception: st={}
def exists(n): return os.path.exists(os.path.join(tdir,n))
model=os.path.join(tdir,"protocol_model.json")
lines=[]
lines.append(f"# PacketHammer Result — {os.path.basename(target)}")
lines.append("")
lines.append(f"- Generated: {datetime.datetime.now().isoformat(timespec='seconds')}")
lines.append(f"- Mode: {mode}")
lines.append(f"- Target: {target}")
lines.append(f"- Phase: {st.get('phase','?')}")
lines.append(f"- Exit reason: {st.get('exit_reason') or '(none)'}")
lines.append(f"- Tool blocker: {st.get('tool_blocker','none')}")
lines.append(f"- Steps total: {st.get('steps_total','?')}")
lines.append(f"- Branches covered: {st.get('branches_covered','?')}")
if mode=="client":
    lines.append(f"- Protocol observed: {st.get('protocol_observed','?')}")
    lines.append(f"- Redirect enabled: {st.get('redirect_enabled','?')}, blocked: {st.get('connect_redirect_blocked','?')}")
lines.append("")
lines.append("## Artifacts")
for n in ["protocol_model.json","state.json","packet_graph.json","client_sends.log",
          "io_events.log","peer_events.log","branches.log","knowledge.jsonl"]:
    if exists(n): lines.append(f"- `{os.path.join(tdir,n)}`")
lines.append("")
lines.append("## Protocol model" )
if os.path.exists(model):
    lines.append(f"See `{model}`.")
else:
    lines.append("No protocol_model.json was produced (no runtime IO captured or run blocked early).")
open(os.path.join(tdir,"RESULT.md"),"w").write("\n".join(lines)+"\n")
print("[run-pipeline] wrote", os.path.join(tdir,"RESULT.md"))
# container exit code: 0 if done cleanly, 2 otherwise
sys.exit(0 if st.get("phase")=="done" and not (st.get("exit_reason") or "").startswith(("watchdog","stalled","peer_not_ready","connect_redirect_blocked")) else 2)
PY
rc=$?
echo "[run-pipeline] finished (exit ${rc}). Result: ${TARGET_DIR}/RESULT.md"
exit $rc
