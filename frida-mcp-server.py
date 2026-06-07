#!/usr/bin/env python3
"""
frida-mcp-server.py — Persistent Frida session MCP server (stdio transport).
Keeps one Frida session alive between agent calls so server-instrumenter /
client-instrumenter can attach once and query repeatedly without losing hooks.

MCP tools exposed:
  attach(target)              — spawn or attach by path or PID
  list_exports(module)        — list exported symbols
  get_base(module)            — get live base address (PIE rebase)
  hook_branches(addrs)        — install branch-hit counters at given offsets
  get_branch_hits()           — return hit counts since last reset
  get_last_recv()             — return last buffer captured at recv/read
  get_file_reads()            — return small config/credential file reads captured at runtime
  reset_file_reads()          — clear captured file-read oracle buffer
  get_connect_attempts()      — return observed DNS/connect attempts for client-mode targets
  reset_connect_attempts()    — clear observed client connection attempts
  set_connect_redirects()     — rewrite connect/WSAConnect sockaddr targets in-process
  get_io_events()             — return outbound send/SSL_write/WSASend events
  reset_io_events()           — clear outbound IO event buffer
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
import shutil
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
// File-backed seed oracle — small reads from config/credential-looking files.
var _fileReads = [];
var _fdPaths = {};
var _streamPaths = {};
var _handlePaths = {};
// Client-mode oracle — DNS/connect attempts, optional in-process redirects, and outbound IO.
var _connectAttempts = [];
var _connectRedirects = [];
var _redirectErrors = [];
var _resolvedHosts = {};
var _lastResolvedHost = null;
var _lastResolvedService = null;
var _lastResolvedTs = 0;
var _ioEvents = [];
// Socket fd/handle tracking so _lastRecv and write/writev IO are not contaminated by file IO.
var _socketFds = {};

var AF_INET = 2;
var AF_INET6_LINUX = 10;
var AF_INET6_WINDOWS = 23;

function _isInterestingPath(path) {
    if (!path) return false;
    var p = path.toString();
    if (p.indexOf('/proc/') === 0 || p.indexOf('/sys/') === 0 || p.indexOf('/dev/') === 0) return false;
    if (p.indexOf('/lib/') === 0 || p.indexOf('/usr/lib/') === 0) return false;
    return /(conf|config|cfg|cred|credential|secret|passwd|password|auth|token|key|user|login|account|\.env|\.ini|\.json|\.yaml|\.yml|\.toml|\.txt)$/i.test(p);
}

function _bytesToHex(bytes) {
    var arr = bytes.byteLength !== undefined ? new Uint8Array(bytes) : bytes;
    return Array.from(arr).map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join('');
}

function _bytesToText(bytes) {
    var arr = bytes.byteLength !== undefined ? new Uint8Array(bytes) : bytes;
    var chars = [];
    for (var i = 0; i < arr.length; i++) {
        var b = arr[i];
        if (b === 0) break;
        chars.push((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13 ? String.fromCharCode(b) : '.');
    }
    return chars.join('');
}

function _readAnsi(p, maxLen) {
    try { return p.readCString(maxLen || 256); } catch(e) { return null; }
}

function _readUtf16(p, maxChars) {
    try { return p.readUtf16String(maxChars || 256); } catch(e) { return null; }
}

function _readStringAny(p, wide, max) {
    if (!p || p.isNull()) return '?';
    var s = wide ? _readUtf16(p, max) : _readAnsi(p, max);
    if (s !== null) return s;
    try {
        var ba = p.readByteArray(Math.min(max || 64, 128));
        return '0x' + _bytesToHex(ba);
    } catch(e) { return '?'; }
}

function _recordComparison(fn, args, ret, wide, hasLen, lenIndex) {
    try {
        if (ret.toInt32() === 0) return;
        var n = hasLen ? Math.min(Math.max(0, args[lenIndex].toInt32()), 256) : 256;
        _comparisons.push({fn: fn, a0: _readStringAny(args[0], wide, n), a1: _readStringAny(args[1], wide, n)});
        if (_comparisons.length > 64) _comparisons.shift();
    } catch(e) {}
}

function _recordFileRead(path, fn, data) {
    if (!path || !data) return;
    var bytes = null;
    if (data.byteLength !== undefined) {
        bytes = new Uint8Array(data.slice(0, Math.min(data.byteLength, 512)));
    } else {
        try {
            var ba = data.readByteArray(512);
            if (!ba) return;
            bytes = new Uint8Array(ba);
        } catch(e) { return; }
    }
    if (!bytes || bytes.length <= 0) return;
    _fileReads.push({path: path.toString(), fn: fn, size: bytes.length, hex: _bytesToHex(bytes), text: _bytesToText(bytes)});
    if (_fileReads.length > 64) _fileReads.shift();
}

function _pushRing(buf, item, maxLen) {
    buf.push(item);
    if (buf.length > maxLen) buf.shift();
}

function _nowSeconds() { return Date.now() / 1000.0; }

function _readSockaddrHex(sa, len) {
    try { return _bytesToHex(sa.readByteArray(Math.max(0, Math.min(len || 32, 128)))); }
    catch(e) { return null; }
}

function _readPortBE(sa) { return (sa.add(2).readU8() << 8) | sa.add(3).readU8(); }

function _writePortBE(sa, port) {
    sa.add(2).writeU8((port >> 8) & 0xff);
    sa.add(3).writeU8(port & 0xff);
}

function _ipv4FromSockaddr(sa) {
    return [sa.add(4).readU8(), sa.add(5).readU8(), sa.add(6).readU8(), sa.add(7).readU8()].join('.');
}

function _ipv6FromSockaddr(sa) {
    var parts = [];
    for (var i = 0; i < 16; i += 2) {
        var hi = sa.add(8 + i).readU8();
        var lo = sa.add(8 + i + 1).readU8();
        parts.push(((hi << 8) | lo).toString(16));
    }
    return parts.join(':');
}

function _writeIpv6ToSockaddr(sa, ip) {
    var bytes = null;
    if (ip === '::1') {
        bytes = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
    } else if (ip.indexOf('.') >= 0) {
        var v4 = ip.split('.').map(function(x) { return parseInt(x, 10); });
        if (v4.length !== 4 || v4.some(function(x) { return isNaN(x) || x < 0 || x > 255; })) throw new Error('invalid IPv4-mapped redirect host: ' + ip);
        bytes = [0,0,0,0,0,0,0,0,0,0,255,255,v4[0],v4[1],v4[2],v4[3]];
    } else {
        throw new Error('only ::1 or IPv4-mapped redirects are supported for AF_INET6 sockaddr');
    }
    for (var i = 0; i < 16; i++) sa.add(8 + i).writeU8(bytes[i]);
}

function _parseSockaddr(sa, len) {
    if (!sa || sa.isNull()) return null;
    var family = sa.readU16();
    var out = {family: family, port: null, resolved_ip: null, original_sockaddr_hex: _readSockaddrHex(sa, len || 32)};
    if (family === AF_INET && (len === 0 || len >= 8 || len === undefined)) {
        out.port = _readPortBE(sa);
        out.resolved_ip = _ipv4FromSockaddr(sa);
    } else if ((family === AF_INET6_LINUX || family === AF_INET6_WINDOWS) && (len === 0 || len >= 24 || len === undefined)) {
        out.port = _readPortBE(sa);
        out.resolved_ip = _ipv6FromSockaddr(sa);
    }
    return out;
}

function _hostForIp(ip) {
    // Prefer an exact resolver-recorded host for this IP. Only fall back to the last
    // resolved host when the connect happens right after a resolve (timestamp window),
    // so a later hardcoded-IP connect is not misattributed to a stale hostname.
    var hosts = ip ? _resolvedHosts[ip] : null;
    if (hosts && hosts.length) return hosts[hosts.length - 1];
    if (_lastResolvedHost && (_nowSeconds() - _lastResolvedTs) <= 2.0) return _lastResolvedHost;
    return null;
}

function _recordConnectAttempt(api, sa, len) {
    var parsed = _parseSockaddr(sa, len);
    if (!parsed) return null;
    var host = _hostForIp(parsed.resolved_ip);
    var event = {
        host: host, resolved_ip: parsed.resolved_ip, port: parsed.port, family: parsed.family, api: api,
        ts: _nowSeconds(), original_sockaddr_hex: parsed.original_sockaddr_hex
    };
    _pushRing(_connectAttempts, event, 256);
    return event;
}

function _redirectMatches(rule, attempt) {
    if (!rule || !attempt) return false;
    if (rule.original_port !== undefined && rule.original_port !== null && parseInt(rule.original_port, 10) !== attempt.port) return false;
    if (rule.original_ip && rule.original_ip !== attempt.resolved_ip) return false;
    if (rule.original_host && rule.original_host !== attempt.host) return false;
    return !!(rule.local_host && rule.local_port);
}

function _rewriteSockaddr(sa, len, rule, attempt) {
    var family = sa.readU16();
    var redirectPort = parseInt(rule.local_port, 10);
    var redirectHost = rule.local_host.toString();
    if (family === AF_INET) {
        var parts = redirectHost.split('.').map(function(x) { return parseInt(x, 10); });
        if (parts.length !== 4 || parts.some(function(x) { return isNaN(x) || x < 0 || x > 255; })) return {ok:false, error:'AF_INET redirect requires IPv4 local_host'};
        _writePortBE(sa, redirectPort);
        for (var i = 0; i < 4; i++) sa.add(4 + i).writeU8(parts[i]);
    } else if (family === AF_INET6_LINUX || family === AF_INET6_WINDOWS) {
        try { _writePortBE(sa, redirectPort); _writeIpv6ToSockaddr(sa, redirectHost); }
        catch(e) { return {ok:false, error:e.toString()}; }
    } else {
        return {ok:false, error:'unsupported sockaddr family for redirect: ' + family};
    }
    var redirect = _parseSockaddr(sa, len);
    var entry = {
        host: attempt.host, resolved_ip: attempt.resolved_ip, port: attempt.port, family: attempt.family, api: attempt.api + ':redirect',
        ts: _nowSeconds(), original_sockaddr_hex: attempt.original_sockaddr_hex,
        original_dst: {host: attempt.host, ip: attempt.resolved_ip, port: attempt.port},
        redirect_dst: {host: redirectHost, ip: redirect ? redirect.resolved_ip : redirectHost, port: redirectPort}
    };
    _pushRing(_connectAttempts, entry, 256);
    return {ok:true, entry:entry};
}

function _maybeRedirectConnect(sa, len, attempt) {
    for (var i = 0; i < _connectRedirects.length; i++) {
        if (!_redirectMatches(_connectRedirects[i], attempt)) continue;
        var res = _rewriteSockaddr(sa, len, _connectRedirects[i], attempt);
        if (res && !res.ok && res.error) {
            var e = {rule_index: i, error: 'rewrite_failed: ' + res.error, ts: _nowSeconds()};
            _pushRing(_redirectErrors, e, 64);
            _pushRing(_connectAttempts, {host:attempt.host, resolved_ip:attempt.resolved_ip, port:attempt.port, family:attempt.family, api:attempt.api + ':redirect_error', ts:_nowSeconds(), error:res.error, original_sockaddr_hex:attempt.original_sockaddr_hex}, 256);
        }
        return res;
    }
    return {ok:false, skipped:true};
}

function _recordResolve(host, ip, api) {
    if (host) {
        _lastResolvedHost = host;
        _lastResolvedTs = _nowSeconds();
        var parts = api ? api.split(':') : [];
        _lastResolvedService = parts.length > 1 ? parts.slice(1).join(':') : null;
    }
    if (ip) {
        if (!_resolvedHosts[ip]) _resolvedHosts[ip] = [];
        _resolvedHosts[ip].push(host);
        if (_resolvedHosts[ip].length > 8) _resolvedHosts[ip].shift();
    }
    _pushRing(_connectAttempts, {host: host || null, resolved_ip: ip || null, port: null, family: null, api: api, ts: _nowSeconds(), original_sockaddr_hex: null}, 256);
}

function _recordIoEvent(api, buf, len, meta) {
    var n = Math.max(0, Math.min(len || 0, 4096));
    if (!buf || buf.isNull() || n <= 0) return;
    try {
        var bytes = buf.readByteArray(n);
        var ev = meta || {};
        ev.api = api; ev.ts = _nowSeconds(); ev.size = n; ev.hex = _bytesToHex(bytes); ev.text = _bytesToText(bytes);
        _pushRing(_ioEvents, ev, 256);
    } catch(e) {}
}

// Aggregate multiple scatter/gather buffers (iovec, WSABUF) into one outbound IO event.
function _recordIoSegments(api, segments, meta) {
    var hex = '', text = '', size = 0, limit = 4096;
    for (var i = 0; i < segments.length; i++) {
        if (size >= limit) break;
        var buf = segments[i].buf, len = segments[i].len;
        var n = Math.max(0, Math.min(len || 0, limit - size));
        if (!buf || buf.isNull() || n <= 0) continue;
        try {
            var bytes = buf.readByteArray(n);
            hex += _bytesToHex(bytes); text += _bytesToText(bytes); size += n;
        } catch(e) {}
    }
    if (size <= 0) return;
    var ev = meta || {};
    ev.api = api; ev.ts = _nowSeconds(); ev.size = size; ev.hex = hex; ev.text = text;
    _pushRing(_ioEvents, ev, 256);
}

function _markSocketFd(fd) { if (fd !== undefined && fd >= 0) _socketFds[fd] = true; }
function _isSocketFd(fd)   { return _socketFds[fd] === true; }

// Read an iovec array into {buf,len} segments. iovec = { void* iov_base; size_t iov_len; }.
function _iovSegments(iovPtr, iovcnt) {
    var segs = [], ps = Process.pointerSize;
    if (!iovPtr || iovPtr.isNull()) return segs;
    var count = Math.min(iovcnt || 0, 64);
    for (var i = 0; i < count; i++) {
        try {
            var base = iovPtr.add(i * ps * 2).readPointer();
            var len = _readSize(iovPtr.add(i * ps * 2 + ps));
            segs.push({buf: base, len: len});
        } catch(e) { break; }
    }
    return segs;
}

// size_t / pointer-width unsigned read.
function _readSize(p) { return Process.pointerSize === 8 ? p.readU64().toNumber() : p.readU32(); }

// Walk a struct sockaddr* and return its IP string, or null.
function _ipFromSockaddrPtr(sa) {
    if (!sa || sa.isNull()) return null;
    try {
        var family = sa.readU16();
        if (family === AF_INET) return _ipv4FromSockaddr(sa);
        if (family === AF_INET6_LINUX || family === AF_INET6_WINDOWS) return _ipv6FromSockaddr(sa);
    } catch(e) {}
    return null;
}

// Walk a getaddrinfo/GetAddrInfoW result list and return resolved IPs.
// Linux glibc addrinfo: ai_addr @24, ai_next @40 (LP64). Windows ADDRINFOW: ai_addr @32, ai_next @40.
function _ipsFromAddrinfo(head, addrOffset, nextOffset) {
    var ips = [];
    var node = head;
    for (var i = 0; i < 16 && node && !node.isNull(); i++) {
        try {
            var sa = node.add(addrOffset).readPointer();
            var ip = _ipFromSockaddrPtr(sa);
            if (ip && ips.indexOf(ip) < 0) ips.push(ip);
            node = node.add(nextOffset).readPointer();
        } catch(e) { break; }
    }
    return ips;
}

// Walk a gethostbyname hostent* and return resolved IPv4 addresses.
function _ipsFromHostent(he) {
    var ips = [];
    if (!he || he.isNull()) return ips;
    try {
        var ps = Process.pointerSize;
        var addrType = he.add(ps * 2).readInt();        // h_addrtype
        var addrListPtr = he.add(ps * 2 + 8).readPointer(); // h_addr_list
        if (addrType !== AF_INET || !addrListPtr || addrListPtr.isNull()) return ips;
        for (var i = 0; i < 16; i++) {
            var addr = addrListPtr.add(i * ps).readPointer();
            if (!addr || addr.isNull()) break;
            var ip = [addr.readU8(), addr.add(1).readU8(), addr.add(2).readU8(), addr.add(3).readU8()].join('.');
            if (ips.indexOf(ip) < 0) ips.push(ip);
        }
    } catch(e) {}
    return ips;
}

// Hook stdlib / CRT / WinAPI comparison functions to capture both sides of failed comparisons.
// One side will be our probe; the other is what the binary expects (the seed).
[
    {name:'strcmp', wide:false, hasLen:false, lenIndex:2},
    {name:'strncmp', wide:false, hasLen:true, lenIndex:2},
    {name:'strcasecmp', wide:false, hasLen:false, lenIndex:2},
    {name:'strncasecmp', wide:false, hasLen:true, lenIndex:2},
    {name:'_stricmp', wide:false, hasLen:false, lenIndex:2},
    {name:'_strnicmp', wide:false, hasLen:true, lenIndex:2},
    {name:'lstrcmpA', wide:false, hasLen:false, lenIndex:2},
    {name:'lstrcmpiA', wide:false, hasLen:false, lenIndex:2},
    {name:'wcscmp', wide:true, hasLen:false, lenIndex:2},
    {name:'wcsncmp', wide:true, hasLen:true, lenIndex:2},
    {name:'_wcsicmp', wide:true, hasLen:false, lenIndex:2},
    {name:'_wcsnicmp', wide:true, hasLen:true, lenIndex:2},
    {name:'lstrcmpW', wide:true, hasLen:false, lenIndex:2},
    {name:'lstrcmpiW', wide:true, hasLen:false, lenIndex:2}
].forEach(function(spec) {
    try {
        var fn = Module.findExportByName(null, spec.name);
        if (!fn) return;
        Interceptor.attach(fn, {
            onEnter: function(args) { this._args = [args[0], args[1], args[2]]; },
            onLeave: function(retval) { _recordComparison(spec.name, this._args, retval, spec.wide, spec.hasLen, spec.lenIndex); }
        });
    } catch(e) { send({type:'init_error', sym: spec.name, msg:e.toString()}); }
});

try {
    var memcmpFn = Module.findExportByName(null, 'memcmp');
    if (memcmpFn) Interceptor.attach(memcmpFn, {
        onEnter: function(args) { this._args = [args[0], args[1], args[2]]; },
        onLeave: function(retval) {
            if (retval.toInt32() === 0) return;
            var n = Math.min(Math.max(0, this._args[2].toInt32()), 256);
            var sides = ['?', '?'];
            for (var i = 0; i < 2; i++) {
                try { sides[i] = '0x' + _bytesToHex(this._args[i].readByteArray(Math.min(n, 64))); } catch(e) {}
            }
            _comparisons.push({fn:'memcmp', a0:sides[0], a1:sides[1]});
            if (_comparisons.length > 64) _comparisons.shift();
        }
    });
} catch(e) { send({type:'init_error', sym:'memcmp', msg:e.toString()}); }

// Track config/credential-looking files so later read/fgets/fread calls can reveal file-backed seeds.
try {
    var openFn = Module.findExportByName(null, 'open');
    if (openFn) Interceptor.attach(openFn, {
        onEnter: function(args) { try { this._path = args[0].readCString(); } catch(e) {} },
        onLeave: function(retval) {
            var fd = retval.toInt32();
            if (fd >= 0 && _isInterestingPath(this._path)) _fdPaths[fd] = this._path;
        }
    });
} catch(e) { send({type:'init_error', sym:'open', msg:e.toString()}); }

try {
    var openatFn = Module.findExportByName(null, 'openat');
    if (openatFn) Interceptor.attach(openatFn, {
        onEnter: function(args) { try { this._path = args[1].readCString(); } catch(e) {} },
        onLeave: function(retval) {
            var fd = retval.toInt32();
            if (fd >= 0 && _isInterestingPath(this._path)) _fdPaths[fd] = this._path;
        }
    });
} catch(e) { send({type:'init_error', sym:'openat', msg:e.toString()}); }

try {
    var fopenFn = Module.findExportByName(null, 'fopen');
    if (fopenFn) Interceptor.attach(fopenFn, {
        onEnter: function(args) { try { this._path = args[0].readCString(); } catch(e) {} },
        onLeave: function(retval) {
            if (!retval.isNull() && _isInterestingPath(this._path)) _streamPaths[retval.toString()] = this._path;
        }
    });
} catch(e) { send({type:'init_error', sym:'fopen', msg:e.toString()}); }

try {
    var wfopenFn = Module.findExportByName(null, '_wfopen');
    if (wfopenFn) Interceptor.attach(wfopenFn, {
        onEnter: function(args) { try { this._path = args[0].readUtf16String(); } catch(e) {} },
        onLeave: function(retval) {
            if (!retval.isNull() && _isInterestingPath(this._path)) _streamPaths[retval.toString()] = this._path;
        }
    });
} catch(e) { send({type:'init_error', sym:'_wfopen', msg:e.toString()}); }

try {
    var createFileAFn = Module.findExportByName(null, 'CreateFileA');
    if (createFileAFn) Interceptor.attach(createFileAFn, {
        onEnter: function(args) { try { this._path = args[0].readCString(); } catch(e) {} },
        onLeave: function(retval) {
            if (!retval.isNull() && retval.toString() !== '0xffffffffffffffff' && _isInterestingPath(this._path)) _handlePaths[retval.toString()] = this._path;
        }
    });
} catch(e) { send({type:'init_error', sym:'CreateFileA', msg:e.toString()}); }

try {
    var createFileWFn = Module.findExportByName(null, 'CreateFileW');
    if (createFileWFn) Interceptor.attach(createFileWFn, {
        onEnter: function(args) { try { this._path = args[0].readUtf16String(); } catch(e) {} },
        onLeave: function(retval) {
            if (!retval.isNull() && retval.toString() !== '0xffffffffffffffff' && _isInterestingPath(this._path)) _handlePaths[retval.toString()] = this._path;
        }
    });
} catch(e) { send({type:'init_error', sym:'CreateFileW', msg:e.toString()}); }

try {
    var readFileFn = Module.findExportByName(null, 'ReadFile');
    if (readFileFn) Interceptor.attach(readFileFn, {
        onEnter: function(args) {
            this._handle = args[0].toString();
            this._buf = args[1];
            this._requested = args[2].toInt32();
            this._bytesReadPtr = args[3];
        },
        onLeave: function(retval) {
            if (retval.toInt32() === 0) return;
            var path = _handlePaths[this._handle];
            if (!path || !this._buf) return;
            var n = this._requested;
            try { if (!this._bytesReadPtr.isNull()) n = this._bytesReadPtr.readU32(); } catch(e) {}
            if (n <= 0) return;
            try { _recordFileRead(path, 'ReadFile', this._buf.readByteArray(Math.min(n, 512))); } catch(e) {}
        }
    });
} catch(e) { send({type:'init_error', sym:'ReadFile', msg:e.toString()}); }

try {
    var fgetsFn = Module.findExportByName(null, 'fgets');
    if (fgetsFn) Interceptor.attach(fgetsFn, {
        onEnter: function(args) { this._buf = args[0]; this._size = args[1].toInt32(); this._stream = args[2].toString(); },
        onLeave: function(retval) {
            if (retval.isNull()) return;
            var path = _streamPaths[this._stream];
            if (!path || this._size <= 0) return;
            try { _recordFileRead(path, 'fgets', this._buf.readByteArray(Math.min(this._size, 512))); } catch(e) {}
        }
    });
} catch(e) { send({type:'init_error', sym:'fgets', msg:e.toString()}); }

try {
    var freadFn = Module.findExportByName(null, 'fread');
    if (freadFn) Interceptor.attach(freadFn, {
        onEnter: function(args) {
            this._buf = args[0];
            this._size = args[1].toInt32();
            this._stream = args[3].toString();
        },
        onLeave: function(retval) {
            var count = retval.toInt32();
            var path = _streamPaths[this._stream];
            if (!path || count <= 0 || this._size <= 0) return;
            try { _recordFileRead(path, 'fread', this._buf.readByteArray(Math.min(count * this._size, 512))); } catch(e) {}
        }
    });
} catch(e) { send({type:'init_error', sym:'fread', msg:e.toString()}); }

// Hook resolver/connect APIs for client-mode endpoint discovery and in-process redirection.
try {
    var getaddrinfoFn = Module.findExportByName(null, 'getaddrinfo');
    if (getaddrinfoFn) Interceptor.attach(getaddrinfoFn, {
        onEnter: function(args) {
            this._host = args[0].isNull() ? null : _readAnsi(args[0], 256);
            this._service = args[1].isNull() ? null : _readAnsi(args[1], 64);
            this._res = args[3];
        },
        onLeave: function(retval) {
            if (!this._host) return;
            var api = 'getaddrinfo' + (this._service ? ':' + this._service : '');
            var ips = [];
            if (retval.toInt32() === 0 && this._res && !this._res.isNull()) {
                try { ips = _ipsFromAddrinfo(this._res.readPointer(), 24, 40); } catch(e) {}
            }
            if (ips.length) ips.forEach(function(ip) { _recordResolve(this._host, ip, api); }, this);
            else _recordResolve(this._host, null, api);
        }
    });
} catch(e) { send({type:'init_error', sym:'getaddrinfo', msg:e.toString()}); }

try {
    var getAddrInfoWFn = Module.findExportByName(null, 'GetAddrInfoW');
    if (getAddrInfoWFn) Interceptor.attach(getAddrInfoWFn, {
        onEnter: function(args) {
            this._host = args[0].isNull() ? null : _readUtf16(args[0], 256);
            this._service = args[1].isNull() ? null : _readUtf16(args[1], 64);
            this._res = args[3];
        },
        onLeave: function(retval) {
            if (!this._host) return;
            var api = 'GetAddrInfoW' + (this._service ? ':' + this._service : '');
            var ips = [];
            if (retval.toInt32() === 0 && this._res && !this._res.isNull()) {
                try { ips = _ipsFromAddrinfo(this._res.readPointer(), 32, 40); } catch(e) {}
            }
            if (ips.length) ips.forEach(function(ip) { _recordResolve(this._host, ip, api); }, this);
            else _recordResolve(this._host, null, api);
        }
    });
} catch(e) { send({type:'init_error', sym:'GetAddrInfoW', msg:e.toString()}); }

try {
    var gethostbynameFn = Module.findExportByName(null, 'gethostbyname');
    if (gethostbynameFn) Interceptor.attach(gethostbynameFn, {
        onEnter: function(args) { this._host = args[0].isNull() ? null : _readAnsi(args[0], 256); },
        onLeave: function(retval) {
            if (!this._host) return;
            var ips = retval.isNull() ? [] : _ipsFromHostent(retval);
            if (ips.length) ips.forEach(function(ip) { _recordResolve(this._host, ip, 'gethostbyname'); }, this);
            else _recordResolve(this._host, null, 'gethostbyname');
        }
    });
} catch(e) { send({type:'init_error', sym:'gethostbyname', msg:e.toString()}); }

try {
    var inetPtonFn = Module.findExportByName(null, 'inet_pton');
    if (inetPtonFn) Interceptor.attach(inetPtonFn, {
        onEnter: function(args) {
            this._family = args[0].toInt32();
            this._src = args[1].isNull() ? null : _readAnsi(args[1], 256);
        },
        onLeave: function(retval) { if (this._src) _recordResolve(this._src, this._src, 'inet_pton'); }
    });
} catch(e) { send({type:'init_error', sym:'inet_pton', msg:e.toString()}); }

try {
    var inetAddrFn = Module.findExportByName(null, 'inet_addr');
    if (inetAddrFn) Interceptor.attach(inetAddrFn, {
        onEnter: function(args) { this._src = args[0].isNull() ? null : _readAnsi(args[0], 256); },
        onLeave: function(retval) { if (this._src) _recordResolve(this._src, this._src, 'inet_addr'); }
    });
} catch(e) { send({type:'init_error', sym:'inet_addr', msg:e.toString()}); }

// Track which fds are sockets so _lastRecv and write/writev IO ignore plain file IO.
try {
    var socketFn = Module.findExportByName(null, 'socket');
    if (socketFn) Interceptor.attach(socketFn, {
        onLeave: function(retval) { _markSocketFd(retval.toInt32()); }
    });
} catch(e) { send({type:'init_error', sym:'socket', msg:e.toString()}); }

['accept', 'accept4'].forEach(function(sym) {
    try {
        var fn = Module.findExportByName(null, sym);
        if (!fn) return;
        Interceptor.attach(fn, { onLeave: function(retval) { _markSocketFd(retval.toInt32()); } });
    } catch(e) { send({type:'init_error', sym:sym, msg:e.toString()}); }
});

['connect', 'WSAConnect'].forEach(function(sym) {
    try {
        var fn = Module.findExportByName(null, sym);
        if (!fn) return;
        Interceptor.attach(fn, {
            onEnter: function(args) {
                _markSocketFd(args[0].toInt32());
                var sa = args[1];
                var len = args[2].toInt32();
                var attempt = _recordConnectAttempt(sym, sa, len);
                if (attempt) {
                    var rewrite = _maybeRedirectConnect(sa, len, attempt);
                    if (rewrite && rewrite.ok) this._redirect = rewrite.entry;
                }
            }
        });
    } catch(e) { send({type:'init_error', sym:sym, msg:e.toString()}); }
});

// Hook outbound sends for client-mode protocol discovery.
['send', 'sendto'].forEach(function(sym) {
    try {
        var fn = Module.findExportByName(null, sym);
        if (!fn) return;
        Interceptor.attach(fn, {
            onEnter: function(args) {
                this._fd = args[0].toInt32();
                this._buf = args[1];
                this._len = args[2].toInt32();
            },
            onLeave: function(retval) {
                var n = retval.toInt32();
                if (n > 0) _recordIoEvent(sym, this._buf, Math.min(n, this._len), {fd:this._fd});
            }
        });
    } catch(e) { send({type:'init_error', sym:sym, msg:e.toString()}); }
});

try {
    var sslWriteFn = Module.findExportByName(null, 'SSL_write');
    if (sslWriteFn) Interceptor.attach(sslWriteFn, {
        onEnter: function(args) { this._buf = args[1]; this._len = args[2].toInt32(); },
        onLeave: function(retval) { var n = retval.toInt32(); if (n > 0) _recordIoEvent('SSL_write', this._buf, Math.min(n, this._len), {}); }
    });
} catch(e) { send({type:'init_error', sym:'SSL_write', msg:e.toString()}); }

// SSL_write_ex(ssl, buf, num, *written) — OpenSSL 1.1.1+ returns 1 on success, bytes in *written.
try {
    var sslWriteExFn = Module.findExportByName(null, 'SSL_write_ex');
    if (sslWriteExFn) Interceptor.attach(sslWriteExFn, {
        onEnter: function(args) { this._buf = args[1]; this._num = args[2].toInt32(); this._written = args[3]; },
        onLeave: function(retval) {
            if (retval.toInt32() === 0) return;
            var n = this._num;
            try { if (this._written && !this._written.isNull()) n = _readSize(this._written); } catch(e) {}
            if (n > 0) _recordIoEvent('SSL_write_ex', this._buf, Math.min(n, this._num), {});
        }
    });
} catch(e) { send({type:'init_error', sym:'SSL_write_ex', msg:e.toString()}); }

// BIO_write(bio, buf, len) — captures plaintext written into a BIO chain.
try {
    var bioWriteFn = Module.findExportByName(null, 'BIO_write');
    if (bioWriteFn) Interceptor.attach(bioWriteFn, {
        onEnter: function(args) { this._buf = args[1]; this._len = args[2].toInt32(); },
        onLeave: function(retval) { var n = retval.toInt32(); if (n > 0) _recordIoEvent('BIO_write', this._buf, Math.min(n, this._len), {}); }
    });
} catch(e) { send({type:'init_error', sym:'BIO_write', msg:e.toString()}); }

// write(fd, buf, count) — shared by files and sockets; only outbound IO for known socket fds.
try {
    var writeFn = Module.findExportByName(null, 'write');
    if (writeFn) Interceptor.attach(writeFn, {
        onEnter: function(args) { this._fd = args[0].toInt32(); this._buf = args[1]; this._len = args[2].toInt32(); },
        onLeave: function(retval) {
            var n = retval.toInt32();
            if (n > 0 && _isSocketFd(this._fd) && !_fdPaths[this._fd]) _recordIoEvent('write', this._buf, Math.min(n, this._len), {fd:this._fd});
        }
    });
} catch(e) { send({type:'init_error', sym:'write', msg:e.toString()}); }

// writev(fd, iov, iovcnt) — scatter/gather; aggregate segments for socket fds.
try {
    var writevFn = Module.findExportByName(null, 'writev');
    if (writevFn) Interceptor.attach(writevFn, {
        onEnter: function(args) { this._fd = args[0].toInt32(); this._iov = args[1]; this._iovcnt = args[2].toInt32(); },
        onLeave: function(retval) {
            var n = retval.toInt32();
            if (n <= 0 || !_isSocketFd(this._fd) || _fdPaths[this._fd]) return;
            _recordIoSegments('writev', _iovSegments(this._iov, this._iovcnt), {fd:this._fd});
        }
    });
} catch(e) { send({type:'init_error', sym:'writev', msg:e.toString()}); }

// sendmsg(fd, msghdr, flags) — socket scatter/gather via msghdr (msg_iov @16, msg_iovlen @24, LP64).
try {
    var sendmsgFn = Module.findExportByName(null, 'sendmsg');
    if (sendmsgFn) Interceptor.attach(sendmsgFn, {
        onEnter: function(args) { this._fd = args[0].toInt32(); this._msg = args[1]; },
        onLeave: function(retval) {
            var n = retval.toInt32();
            if (n <= 0 || !this._msg || this._msg.isNull()) return;
            _markSocketFd(this._fd);
            try {
                var iov = this._msg.add(16).readPointer();
                var iovlen = _readSize(this._msg.add(24));
                _recordIoSegments('sendmsg', _iovSegments(iov, iovlen), {fd:this._fd});
            } catch(e) {}
        }
    });
} catch(e) { send({type:'init_error', sym:'sendmsg', msg:e.toString()}); }

// WSASend(s, lpBuffers, dwBufferCount, ..., lpOverlapped, ...) — aggregate all WSABUF segments.
// WSABUF { ULONG len; CHAR* buf; } → 16 bytes on x64 (4 len + 4 pad + 8 ptr), 8 bytes on x86.
try {
    var wsaSendFn = Module.findExportByName(null, 'WSASend');
    if (wsaSendFn) Interceptor.attach(wsaSendFn, {
        onEnter: function(args) {
            this._socket = args[0].toString();
            this._lpBuffers = args[1];
            this._dwBufferCount = args[2].toInt32();
            this._overlapped = args[5];
        },
        onLeave: function(retval) {
            // 0 = immediate success; SOCKET_ERROR with overlapped = async WSA_IO_PENDING (data already staged).
            var async = this._overlapped && !this._overlapped.isNull();
            if (retval.toInt32() !== 0 && !async) return;
            if (this._dwBufferCount <= 0 || !this._lpBuffers || this._lpBuffers.isNull()) return;
            var ps = Process.pointerSize;
            var stride = ps === 8 ? 16 : 8;
            var bufOffset = ps === 8 ? 8 : 4;
            var segs = [], count = Math.min(this._dwBufferCount, 64);
            for (var i = 0; i < count; i++) {
                try {
                    var wb = this._lpBuffers.add(i * stride);
                    segs.push({buf: wb.add(bufOffset).readPointer(), len: wb.readU32()});
                } catch(e) { break; }
            }
            _recordIoSegments('WSASend', segs, {socket:this._socket, async: async});
        }
    });
} catch(e) { send({type:'init_error', sym:'WSASend', msg:e.toString()}); }

// Hook recv / recvfrom / read to capture inbound data.
// recv/recvfrom are always sockets; read() may be a file — only update _lastRecv for socket fds
// and never for fds known to be config/credential files, to avoid contaminating get_last_recv.
['recv', 'recvfrom', 'read'].forEach(function(sym) {
    try {
        var fn = Module.findExportByName(null, sym);
        if (!fn) return;
        var alwaysSocket = (sym !== 'read');
        Interceptor.attach(fn, {
            onEnter: function(args) {
                this._fd = args[0].toInt32();
                this._buf = args[1];
            },
            onLeave: function(retval) {
                var n = retval.toInt32();
                if (n <= 0) return;
                try {
                    var buf = this._buf;
                    var path = _fdPaths[this._fd];
                    if (buf && !path && (alwaysSocket || _isSocketFd(this._fd))) {
                        _markSocketFd(this._fd);
                        _lastRecv = buf.readByteArray(n);
                    }
                    if (path && buf) _recordFileRead(path, 'read', buf.readByteArray(Math.min(n, 512)));
                } catch(e) {}
            }
        });
    } catch(e) {
        send({type:'init_error', sym: sym, msg: e.toString()});
    }
});

// Hook WSARecv for Windows Winsock packet capture.
try {
    var wsaRecvFn = Module.findExportByName(null, 'WSARecv');
    if (wsaRecvFn) Interceptor.attach(wsaRecvFn, {
        onEnter: function(args) {
            this._lpBuffers = args[1];
            this._dwBufferCount = args[2].toInt32();
            this._lpNumberOfBytesRecvd = args[3];
        },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0 || this._dwBufferCount <= 0) return;
            var n = 0;
            try { if (!this._lpNumberOfBytesRecvd.isNull()) n = this._lpNumberOfBytesRecvd.readU32(); } catch(e) {}
            if (n <= 0) return;
            try {
                var bufOffset = Process.pointerSize === 8 ? 8 : 4;
                var bufPtr = this._lpBuffers.add(bufOffset).readPointer();
                if (bufPtr) _lastRecv = bufPtr.readByteArray(Math.min(n, 65536));
            } catch(e) {}
        }
    });
} catch(e) { send({type:'init_error', sym:'WSARecv', msg:e.toString()}); }

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
    getFileReads: function() { return _fileReads.slice(); },
    resetFileReads: function() { _fileReads = []; return true; },
    getConnectAttempts: function() { return _connectAttempts.slice(); },
    resetConnectAttempts: function() { _connectAttempts = []; _resolvedHosts = {}; _lastResolvedHost = null; _lastResolvedService = null; _lastResolvedTs = 0; _redirectErrors = []; return true; },
    setConnectRedirects: function(rules) {
        if (!Array.isArray(rules)) throw new Error('rules must be an array');
        function _validPort(p) { return Number.isInteger(p) && p >= 1 && p <= 65535; }
        function _validHost(h) {
            if (!h || typeof h !== 'string') return false;
            if (h === '::1' || h.indexOf(':') >= 0) return true; // IPv6 / ::1
            var parts = h.split('.');
            if (parts.length !== 4) return false;
            return parts.every(function(x) { var n = parseInt(x, 10); return String(n) === x && n >= 0 && n <= 255; });
        }
        var valid = [], errors = [];
        rules.forEach(function(rule, i) {
            var lp = parseInt(rule.local_port, 10);
            var op = rule.original_port === undefined || rule.original_port === null ? null : parseInt(rule.original_port, 10);
            var lh = rule.local_host || '127.0.0.1';
            var err = null;
            if (!_validPort(lp)) err = 'invalid local_port: ' + rule.local_port;
            else if (op !== null && !_validPort(op)) err = 'invalid original_port: ' + rule.original_port;
            else if (!_validHost(lh)) err = 'invalid local_host: ' + lh;
            else if (rule.original_ip && typeof rule.original_ip !== 'string') err = 'invalid original_ip';
            if (err) {
                var e = {rule_index: i, error: err, ts: _nowSeconds()};
                errors.push(e); _pushRing(_redirectErrors, e, 64);
                _pushRing(_connectAttempts, {host:null, resolved_ip:null, port:op, family:null, api:'redirect_error', ts:_nowSeconds(), error:err, original_sockaddr_hex:null}, 256);
                return;
            }
            valid.push({
                original_host: rule.original_host || null,
                original_ip: rule.original_ip || null,
                original_port: op,
                local_host: lh,
                local_port: lp
            });
        });
        _connectRedirects = valid;
        return {ok: errors.length === 0, count: _connectRedirects.length, errors: errors};
    },
    getRedirectErrors: function() { return _redirectErrors.slice(); },
    getIoEvents: function() { return _ioEvents.slice(); },
    resetIoEvents: function() { _ioEvents = []; return true; },
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


def _spawn_command_for_target(target: str) -> list[str]:
    if str(target).lower().endswith(('.exe', '.dll')):
        wine = shutil.which('wine64') or shutil.which('wine')
        if not wine:
            raise RuntimeError('Windows PE target requires wine64 or wine in PATH')
        return [wine, target]
    return [target]

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
    global _session, _script, _target_path, _target_env, _spawned_pid, _hooked_addrs, _detach_reason
    target = params.get("target")
    use_desock = params.get("desock", False)
    if not target:
        return {"error": "target required (path or pid)"}
    with _lock:
        _detach_reason = None
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
                pid = frida.spawn(_spawn_command_for_target(target), env=env)
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
                _script = _session.create_script(JS_AGENT)
                _script.load()
                frida.resume(pid)
                time.sleep(2.0)  # allow target init and port binding
            if _script is None:
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
            pid = frida.spawn(_spawn_command_for_target(_target_path), env=env)
            _session = frida.attach(pid)
            _spawned_pid = pid
            _detach_reason = None
            def _on_detach(reason, crash):
                global _detach_reason
                _detach_reason = reason
                sys.stderr.write(f"[frida] detach: reason={reason} crash={crash}\n")
                sys.stderr.flush()
            _session.on('detached', _on_detach)
            _script = _session.create_script(JS_AGENT)
            _script.load()
            frida.resume(pid)
            time.sleep(2.0)
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

def tool_get_file_reads(_params: dict) -> dict:
    with _lock:
        result = _call_rpc("get_file_reads")
    return {"file_reads": result}

def tool_reset_file_reads(_params: dict) -> dict:
    with _lock:
        _call_rpc("reset_file_reads")
    return {"ok": True}

def tool_get_connect_attempts(_params: dict) -> dict:
    with _lock:
        result = _call_rpc("get_connect_attempts")
    return {"connect_attempts": result}

def tool_reset_connect_attempts(_params: dict) -> dict:
    with _lock:
        _call_rpc("reset_connect_attempts")
    return {"ok": True}

def tool_set_connect_redirects(params: dict) -> dict:
    redirects = params.get("redirects", [])
    if not isinstance(redirects, list):
        return {"error": "redirects must be a list"}
    with _lock:
        result = _call_rpc("set_connect_redirects", redirects)
    return result

def tool_get_redirect_errors(_params: dict) -> dict:
    with _lock:
        result = _call_rpc("get_redirect_errors")
    return {"redirect_errors": result}

def tool_get_io_events(_params: dict) -> dict:
    with _lock:
        result = _call_rpc("get_io_events")
    return {"io_events": result}

def tool_reset_io_events(_params: dict) -> dict:
    with _lock:
        _call_rpc("reset_io_events")
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
    "get_file_reads":        tool_get_file_reads,
    "reset_file_reads":      tool_reset_file_reads,
    "get_connect_attempts":  tool_get_connect_attempts,
    "reset_connect_attempts": tool_reset_connect_attempts,
    "set_connect_redirects": tool_set_connect_redirects,
    "get_redirect_errors":   tool_get_redirect_errors,
    "get_io_events":         tool_get_io_events,
    "reset_io_events":       tool_reset_io_events,
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
    {"name": "get_last_comparisons", "description": "Return up to 64 recent failed comparison events (strcmp/memcmp, Windows lstrcmpA/W, _stricmp/_wcsicmp, wcscmp/wcsncmp, etc.). Each entry has {fn, a0, a1} where one side is the probe value and the other is what the binary expected. Use after a harvest probe to discover seeds.",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "reset_comparisons", "description": "Clear the comparison oracle buffer. Call before sending a harvest probe so results are uncontaminated.",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "get_file_reads", "description": "Return up to 64 small reads from config/credential-looking files opened by the target through POSIX/CRT or Windows CreateFileA/W+ReadFile APIs. Entries include {path, fn, size, hex, text}. Use as runtime evidence for file-backed seeds.",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "reset_file_reads", "description": "Clear the file-backed seed oracle buffer. Call before replaying a path expected to load config/credential files.",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "get_connect_attempts", "description": "Client-mode oracle: return observed resolver and connect attempts. Connect entries include {host, resolved_ip, port, family, api, ts, original_sockaddr_hex}; redirect entries additionally preserve original_dst and redirect_dst.",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "reset_connect_attempts", "description": "Clear client-mode resolver/connect attempt evidence before an observe-only pass.",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "set_connect_redirects", "description": "Client-mode redirect: configure in-process sockaddr rewrite for connect/WSAConnect. Each rule has original_port and optional original_host/original_ip, plus local_host/local_port for the fake peer. Ports/hosts are validated; invalid rules are rejected and returned in 'errors'. Original and redirect destinations are recorded as evidence.",
     "inputSchema": {"type":"object","properties":{"redirects":{"type":"array","items":{"type":"object","properties":{"original_host":{"type":"string"},"original_ip":{"type":"string"},"original_port":{"type":"integer"},"local_host":{"type":"string","default":"127.0.0.1"},"local_port":{"type":"integer"}},"required":["original_port","local_port"]}}},"required":["redirects"]}},
    {"name": "get_redirect_errors", "description": "Client-mode oracle: return recorded redirect rule validation and runtime rewrite failures (rule_index, error, ts). Use to confirm whether a redirect was actually applied before claiming fake-peer coverage.",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "get_io_events", "description": "Client-mode oracle: return outbound send/sendto/write/writev/sendmsg/SSL_write/SSL_write_ex/BIO_write/WSASend payload events with hex/text, size, API, and timestamp. Multi-buffer (writev/sendmsg/WSASend) payloads are aggregated.",
     "inputSchema": {"type":"object","properties":{}}},
    {"name": "reset_io_events", "description": "Clear outbound IO event buffer before a client-mode trigger/observe pass.",
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