#!/usr/bin/env python3
"""
frida-mcp-server.py — Persistent Frida session MCP server (stdio transport).
Keeps one Frida session alive between agent calls so net-instrumenter
can attach once and query repeatedly without losing hooks.

MCP tools exposed:
  attach(target)              — spawn or attach by path or PID
  list_exports(module)        — list exported symbols
  get_base(module)            — get live base address (PIE rebase)
  hook_branches(addrs)        — install branch-hit counters at given offsets
  get_branch_hits()           — return hit counts since last reset
  get_last_recv()             — return last buffer captured at recv/read
  reset_hits()                — reset branch counters
  detach()                    — detach session
  status()                    — return session state
"""

import sys
import os
import json
import time
import frida
import threading
import traceback
from datetime import datetime
from typing import Any

DESOCK_SO = "/opt/preeny/desock.so"
LOG_DIR   = "/workspace/logs"

# ── trace logger ─────────────────────────────────────────────────────────────
_log_fh = None

def _open_log():
    global _log_fh
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"{LOG_DIR}/frida-mcp_{ts}.jsonl"
        _log_fh = open(path, "a", buffering=1)
        # Redirect fd 2 so Frida C-layer errors land in the log
        os.dup2(_log_fh.fileno(), 2)
        sys.stderr = _log_fh
        _trace("start", {"server": "frida-live", "version": "1.0.0", "log": path})
    except Exception:
        pass

def _trace(direction: str, data):
    if _log_fh is None:
        return
    try:
        _log_fh.write(json.dumps(
            {"ts": datetime.now().isoformat(), "dir": direction, "data": data},
            default=str
        ) + "\n")
        _log_fh.flush()
    except Exception:
        pass

# ── session state ────────────────────────────────────────────────────────────
_session        = None
_script         = None
_lock           = threading.Lock()
_last_recv      = b""
_branch_hits: dict[str, int] = {}
_detach_reason  = None
_target_path    = None   # path used in last spawn (for restart)
_target_env     = None   # env used in last spawn
_spawned_pid    = None   # PID of spawned child
_hooked_addrs: list[str] = []  # accumulated hooked addresses (for re-hook after restart)

# ── Frida JS injected into the target ────────────────────────────────────────
JS_AGENT = r"""
'use strict';

// Branch hit counters  { "0xADDR": count }
var _hits = {};
// Last inbound buffer captured at recv/read
var _lastRecv = null;
// Comparison oracle — failed stdlib comparisons to discover expected values
var _comparisons = [];
// Tier 2 oracle — address-specific argument capture for custom/inline comparisons
var _addrHooks = {};

// Hook stdlib comparison functions to capture both sides of failed comparisons.
// One side will be our probe; the other is what the binary expects (the seed).
['strcmp','strncmp','strcasecmp','strncasecmp','memcmp'].forEach(function(sym) {
    try {
        var fn = Module.findExportByName(null, sym);
        if (!fn) return;
        var hasLen = (sym === 'strncmp' || sym === 'strncasecmp' || sym === 'memcmp');
        Interceptor.attach(fn, {
            onEnter: function(args) {
                this._fn = sym;
                this._a  = [args[0], args[1]];
                this._n  = hasLen ? Math.min(Math.max(0, args[2].toInt32()), 256) : 256;
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0) return; // matched — not interesting
                var sides = [];
                for (var i = 0; i < 2; i++) {
                    var s = '?';
                    try { s = this._a[i].readCString(); }
                    catch(e1) {
                        try {
                            var ba = this._a[i].readByteArray(Math.min(this._n, 64));
                            s = '0x' + Array.from(new Uint8Array(ba))
                                .map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join('');
                        } catch(e2) {}
                    }
                    sides.push(s);
                }
                _comparisons.push({fn: this._fn, a0: sides[0], a1: sides[1]});
                if (_comparisons.length > 64) _comparisons.shift();
            }
        });
    } catch(e) {
        send({type:'init_error', sym: sym, msg: e.toString()});
    }
});

// Hook recv / recvfrom / read to capture inbound data
['recv', 'recvfrom', 'read'].forEach(function(sym) {
    try {
        var fn = Module.findExportByName(null, sym);
        if (!fn) return;
        Interceptor.attach(fn, {
            onEnter: function(args) {
                this._buf = args[1];
            },
            onLeave: function(retval) {
                var n = retval.toInt32();
                if (n <= 0) return;
                try {
                    var buf = this._buf;
                    if (buf) _lastRecv = buf.readByteArray(n);
                } catch(e) {}
            }
        });
    } catch(e) {
        send({type:'init_error', sym: sym, msg: e.toString()});
    }
});

rpc.exports = {
    hookBranches: function(addrs) {
        addrs.forEach(function(a) {
            var p = ptr(a);
            _hits[a] = 0;
            try {
                Interceptor.attach(p, { onEnter: function() { _hits[a]++; } });
            } catch(e) {
                send({type:'hook_error', addr:a, msg:e.toString()});
            }
        });
        return Object.keys(_hits).length;
    },
    getBranchHits: function() { return _hits; },
    resetHits: function() {
        Object.keys(_hits).forEach(function(k){ _hits[k]=0; });
    },
    getLastComparisons: function() { return _comparisons.slice(); },
    resetComparisons:   function() { _comparisons = []; return true; },
    getLastRecv: function() {
        if (!_lastRecv) return null;
        return Array.from(new Uint8Array(_lastRecv))
            .map(function(b){ return ('0'+b.toString(16)).slice(-2); })
            .join('');
    },
    getBase: function(mod) {
        var m = mod ? Process.findModuleByName(mod) : Process.enumerateModules()[0];
        return m ? m.base.toString() : null;
    },
    listExports: function(mod) {
        if (mod) {
            var m = Process.findModuleByName(mod);
            if (!m) return [];
            return m.enumerateExports().map(function(e){
                return {name: e.name, address: e.address.toString(), module: m.name};
            });
        }
        // No module specified: search all modules for network/IO symbols
        var result = [];
        var targets = ['recv','recvfrom','read','send','sendto','write','accept','connect','socket'];
        targets.forEach(function(sym) {
            var addr = Module.findExportByName(null, sym);
            if (addr) result.push({name: sym, address: addr.toString(), module: 'libc'});
        });
        // Also add main module exports
        var mainMod = Process.enumerateModules()[0];
        if (mainMod) {
            mainMod.enumerateExports().forEach(function(e){
                result.push({name: e.name, address: e.address.toString(), module: mainMod.name});
            });
        }
        return result;
    },
    hookAddress: function(addr, label) {
        if (_addrHooks[addr]) return {ok: true, already: true};
        _addrHooks[addr] = {label: label || addr, count: 0, samples: []};
        try {
            var p = ptr(addr);
            Interceptor.attach(p, {
                onEnter: function(args) {
                    _addrHooks[addr].count++;
                    if (_addrHooks[addr].samples.length >= 16) return;
                    var s = {};
                    for (var i = 0; i < 3; i++) {
                        try {
                            var c = args[i].readCString();
                            if (c && c.length < 256) { s['a'+i] = c; continue; }
                        } catch(e) {}
                        try {
                            var ba = args[i].readByteArray(64);
                            s['a'+i] = '0x' + Array.from(new Uint8Array(ba))
                                .map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join('');
                        } catch(e2) { s['a'+i] = args[i].toString(); }
                    }
                    _addrHooks[addr].samples.push(s);
                }
            });
            return {ok: true, hooked: addr};
        } catch(e) {
            send({type:'hook_error', addr: addr, msg: e.toString()});
            return {ok: false, error: e.toString()};
        }
    },
    getAddressHits: function() { return _addrHooks; },
    resetAddressHits: function() {
        Object.keys(_addrHooks).forEach(function(k){
            _addrHooks[k].count = 0;
            _addrHooks[k].samples = [];
        });
        return true;
    }
};
"""

# ── helpers ───────────────────────────────────────────────────────────────────
def _ensure_detached():
    global _session, _script
    if _script:
        try: _script.unload()
        except: pass
        _script = None
    if _session:
        try: _session.detach()
        except: pass
        _session = None

def _call_rpc(method, *args):
    if not _script:
        raise RuntimeError("No active session — call attach() first")
    try:
        exports = _script.exports_sync
    except AttributeError:
        exports = _script.exports
    return getattr(exports, method)(*args)

# ── MCP tool handlers ─────────────────────────────────────────────────────────
def tool_attach(params: dict) -> dict:
    global _session, _script, _target_path, _target_env, _spawned_pid, _hooked_addrs
    target = params.get("target")
    use_desock = params.get("desock", False)
    if not target:
        return {"error": "target required (path or pid)"}
    with _lock:
        _ensure_detached()
        # Kill any previously spawned binary before spawning a new one.
        # Without this, the old process keeps the port bound and the new spawn exits immediately.
        if _spawned_pid:
            try:
                import signal as _sig
                os.kill(_spawned_pid, _sig.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            _spawned_pid = None
            time.sleep(0.3)
        try:
            if str(target).isdigit():
                _session = frida.attach(int(target))
                _spawned_pid = int(target)
            else:
                env = dict(os.environ)
                if use_desock and os.path.exists(DESOCK_SO):
                    existing = env.get("LD_PRELOAD", "")
                    env["LD_PRELOAD"] = (existing + ":" + DESOCK_SO).lstrip(":")
                pid = frida.spawn([target], env=env)
                _session = frida.attach(pid)
                _spawned_pid = pid
                _target_path = target
                _target_env  = env
                _hooked_addrs = []  # reset hook list on fresh attach
                def _on_detach(reason, crash):
                    global _detach_reason
                    _detach_reason = reason
                    sys.stderr.write(f"[frida] detach: reason={reason} crash={crash}\n")
                    sys.stderr.flush()
                _session.on('detached', _on_detach)
                frida.resume(pid)
                time.sleep(2.0)  # wait for dynamic linker and process init
            _script = _session.create_script(JS_AGENT)
            _script.load()
            session_pid = getattr(_session, 'pid', None) or "attached"
            return {"ok": True, "pid": session_pid, "detach_reason": _detach_reason}
        except Exception as e:
            return {"error": str(e), "trace": traceback.format_exc()}

def tool_restart(_params: dict) -> dict:
    """Kill spawned process, re-spawn same binary, reload JS agent, re-hook all branches."""
    global _session, _script, _spawned_pid, _detach_reason
    if not _target_path:
        return {"error": "no previous spawn — call attach(target=<path>) first"}
    with _lock:
        old_pid = _spawned_pid
        _ensure_detached()
        if old_pid:
            try:
                import signal as _signal
                os.kill(old_pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        time.sleep(0.5)
        try:
            env = _target_env or dict(os.environ)
            pid = frida.spawn([_target_path], env=env)
            _session = frida.attach(pid)
            _spawned_pid = pid
            _detach_reason = None
            def _on_detach(reason, crash):
                global _detach_reason
                _detach_reason = reason
                sys.stderr.write(f"[frida] detach: reason={reason} crash={crash}\n")
                sys.stderr.flush()
            _session.on('detached', _on_detach)
            frida.resume(pid)
            time.sleep(2.0)
            _script = _session.create_script(JS_AGENT)
            _script.load()
            # Re-hook all previously installed branch addresses
            rehook_count = 0
            if _hooked_addrs:
                rehook_count = _call_rpc("hook_branches", _hooked_addrs)
            return {"ok": True, "pid": pid, "target": _target_path, "rehook_count": rehook_count}
        except Exception as e:
            return {"error": str(e), "trace": traceback.format_exc()}

def tool_get_pid(_params: dict) -> dict:
    return {"pid": _spawned_pid, "target": _target_path}

def tool_detach(_params: dict) -> dict:
    with _lock:
        _ensure_detached()
    return {"ok": True}

def tool_status(_params: dict) -> dict:
    return {"session_active": _session is not None, "script_loaded": _script is not None,
            "detach_reason": _detach_reason}

def tool_hook_branches(params: dict) -> dict:
    global _hooked_addrs
    addrs = params.get("addrs", [])
    if not addrs:
        return {"error": "addrs list required"}
    with _lock:
        n = _call_rpc("hook_branches", addrs)
        _hooked_addrs = list(set(_hooked_addrs + addrs))  # accumulate for restart re-hook
    return {"hooks_installed": n}

def tool_get_branch_hits(_params: dict) -> dict:
    with _lock:
        hits = _call_rpc("get_branch_hits")
    return {"hits": hits}

def tool_reset_hits(_params: dict) -> dict:
    with _lock:
        _call_rpc("reset_hits")
    return {"ok": True}

def tool_get_last_recv(_params: dict) -> dict:
    with _lock:
        hexstr = _call_rpc("get_last_recv")
    return {"hex": hexstr}

def tool_get_last_comparisons(_params: dict) -> dict:
    with _lock:
        result = _call_rpc("get_last_comparisons")
    return {"comparisons": result}

def tool_reset_comparisons(_params: dict) -> dict:
    with _lock:
        _call_rpc("reset_comparisons")
    return {"ok": True}

def tool_get_base(params: dict) -> dict:
    mod = params.get("module", None)
    with _lock:
        base = _call_rpc("get_base", mod)
    return {"base": base}

def tool_list_exports(params: dict) -> dict:
    mod = params.get("module", None)
    with _lock:
        exports = _call_rpc("list_exports", mod)
    return {"exports": exports}

def tool_hook_address(params: dict) -> dict:
    addr = params.get("addr")
    label = params.get("label", addr)
    if not addr:
        return {"error": "addr required"}
    with _lock:
        result = _call_rpc("hook_address", addr, label)
    return result

def tool_get_address_hits(_params: dict) -> dict:
    with _lock:
        hits = _call_rpc("get_address_hits")
    return {"hits": hits}

def tool_reset_address_hits(_params: dict) -> dict:
    with _lock:
        _call_rpc("reset_address_hits")
    return {"ok": True}

# ── MCP stdio loop ────────────────────────────────────────────────────────────
TOOLS = {
    "attach":           tool_attach,
    "detach":           tool_detach,
    "restart":          tool_restart,
    "get_pid":          tool_get_pid,
    "status":           tool_status,
    "hook_branches":    tool_hook_branches,
    "get_branch_hits":  tool_get_branch_hits,
    "reset_hits":       tool_reset_hits,
    "get_last_recv":         tool_get_last_recv,
    "get_last_comparisons":  tool_get_last_comparisons,
    "reset_comparisons":     tool_reset_comparisons,
    "get_base":              tool_get_base,
    "list_exports":          tool_list_exports,
    "hook_address":          tool_hook_address,
    "get_address_hits":      tool_get_address_hits,
    "reset_address_hits":    tool_reset_address_hits,
}

TOOL_DEFS = [
    {"name": "attach",          "description": "Spawn or attach to target by path or PID. When path given, spawns with LD_PRELOAD=desock.so by default to redirect socket to stdin. Pass desock=false to disable.",
     "inputSchema": {"type":"object","properties":{"target":{"type":"string"},"desock":{"type":"boolean","default":True}},"required":["target"]}},
    {"name": "detach",          "description": "Detach current Frida session",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "restart",         "description": "Kill spawned process, re-spawn same binary, reload JS agent, re-hook all previously installed branch addresses. Use when binary is unresponsive or a path cannot be reproduced.",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "get_pid",         "description": "Return PID and path of currently spawned process",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "status",          "description": "Return current session state",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "hook_branches",   "description": "Install hit counters at branch addresses (hex strings)",
     "inputSchema": {"type":"object","properties":{"addrs":{"type":"array","items":{"type":"string"}}},"required":["addrs"]}},
    {"name": "get_branch_hits", "description": "Return branch hit counts since last reset",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "reset_hits",      "description": "Reset all branch hit counters to 0",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "get_last_recv",   "description": "Return last inbound buffer captured at recv/read as hex",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "get_last_comparisons", "description": "Return up to 64 recent failed stdlib comparison events (strcmp/memcmp/…). Each entry has {fn, a0, a1} where one side is the probe value and the other is what the binary expected. Use after a harvest probe to discover seeds.",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "reset_comparisons", "description": "Clear the comparison oracle buffer. Call before sending a harvest probe so results are uncontaminated.",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "get_base",        "description": "Get live base address of a module (for PIE rebase)",
     "inputSchema": {"type":"object","properties":{"module":{"type":"string"}}}},
    {"name": "list_exports",    "description": "List exported symbols of a module",
     "inputSchema": {"type":"object","properties":{"module":{"type":"string"}}}},
    {"name": "hook_address",    "description": "Tier 2 oracle: install a hit counter + argument capture hook at a specific instruction address. Use for custom/inline comparisons found by Ghidra decompile. Captures up to 3 args (rdi/rsi/rdx convention) per hit, up to 16 samples.",
     "inputSchema": {"type":"object","properties":{"addr":{"type":"string","description":"hex address string e.g. 0x5695c9c07013"},"label":{"type":"string","description":"human-readable label for this hook"}},"required":["addr"]}},
    {"name": "get_address_hits","description": "Return all Tier 2 oracle hook hit counts and captured argument samples since last reset_address_hits",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "reset_address_hits","description": "Reset all Tier 2 oracle hook counters and sample buffers. Call before sending a harvest probe so results are uncontaminated.",
     "inputSchema": {"type":"object","properties":{}}},
]

def send_msg(obj: dict):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def handle(req: dict) -> dict:
    method = req.get("method", "")
    rid    = req.get("id")

    if method == "initialize":
        return {"jsonrpc":"2.0","id":rid,"result":{
            "protocolVersion":"2024-11-05",
            "capabilities":{"tools":{}},
            "serverInfo":{"name":"frida-live","version":"1.0.0"}
        }}

    if method == "tools/list":
        return {"jsonrpc":"2.0","id":rid,"result":{"tools": TOOL_DEFS}}

    if method == "tools/call":
        name   = req["params"]["name"]
        params = req["params"].get("arguments", {})
        if name not in TOOLS:
            return {"jsonrpc":"2.0","id":rid,"error":{"code":-32601,"message":f"Unknown tool: {name}"}}
        try:
            result = TOOLS[name](params)
            return {"jsonrpc":"2.0","id":rid,"result":{
                "content":[{"type":"text","text":json.dumps(result)}]
            }}
        except Exception as e:
            return {"jsonrpc":"2.0","id":rid,"result":{
                "content":[{"type":"text","text":json.dumps({"error":str(e)})}],
                "isError": True
            }}

    return {"jsonrpc":"2.0","id":rid,"error":{"code":-32601,"message":f"Method not found: {method}"}}

def main():
    _open_log()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            _trace("recv", req)
            resp = handle(req)
            send_msg(resp)
            _trace("send", resp)
        except Exception as e:
            err = {"jsonrpc":"2.0","id":None,"error":{"code":-32700,"message":str(e)}}
            send_msg(err)
            _trace("error", {"exception": str(e), "trace": traceback.format_exc()})

if __name__ == "__main__":
    main()