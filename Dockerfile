FROM ubuntu:24.04

##############################################
# 0. ENV
##############################################
ENV DEBIAN_FRONTEND=noninteractive
ENV OLLAMA_HOST=http://host.docker.internal:11434
ENV OLLAMA_API_BASE=http://host.docker.internal:11434
ENV OPENAI_API_BASE=http://host.docker.internal:11434
ENV GOOGLE_GENERATIVE_AI_API_KEY=
# Provide the OpenRouter key at build time (never committed):
#   export OPENROUTER_API_KEY=sk-or-...   then   ./build.sh
# or: docker build --build-arg OPENROUTER_API_KEY=sk-or-... .
ARG OPENROUTER_API_KEY=
ENV OPENROUTER_API_KEY=${OPENROUTER_API_KEY}

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
    wine64 \
    wine \
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
COPY config/opencode/agents/ /root/.config/opencode/agents/

COPY config/opencode/opencode.jsonc /root/.config/opencode/opencode.jsonc

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

REQUIRED="qwen3_6-27b-custom:q6_K qwen3_6-27b-custom:q4_K_M"
MISSING=0
for REQUIRED_MODEL in $REQUIRED; do
    if echo "$MODELS" | grep -q "$REQUIRED_MODEL"; then
        echo "OK: $REQUIRED_MODEL found"
    else
        echo "WARNING: $REQUIRED_MODEL not found in Ollama — agents using it will fail"
        MISSING=1
    fi
done
if [ "$MISSING" = "1" ]; then
    echo "Available models:"
    echo "$MODELS"
fi
EOF
RUN chmod +x /opt/check-models.sh

##############################################
# 10b. Autonomous pipeline runner (headless, watchdog, RESULT.md)
##############################################
COPY config/run-pipeline.sh /opt/run-pipeline.sh
RUN chmod +x /opt/run-pipeline.sh

RUN python3 -c "import json,os; f='/root/.config/opencode/opencode.jsonc'; d=json.load(open(f)); d['provider']['openrouter']['options']['apiKey']=os.environ.get('OPENROUTER_API_KEY',''); json.dump(d,open(f,'w'),indent=2)"

# Default: fully autonomous run. Set PH_INTERACTIVE=1 to drop to a shell instead.
# Provide PH_MODE (server|client), PH_TARGET (binary path), and PH_PROMPT (or /workspace/INIT_PROMPT.txt).
CMD ["/bin/bash", "-c", "/opt/start-ghidra-mcp.sh && /opt/check-models.sh && exec /opt/run-pipeline.sh"]