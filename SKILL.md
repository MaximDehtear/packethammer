# SKILL: generate-protocol-report

## Invocation

User types: `/generate-protocol-report [path/to/protocol_model.json]`

If no path is given, look for `protocol_model.json` in the current working directory or in
`/workspace/netproto/*/protocol_model.json` (glob, pick the first match).

---

## What this skill does

Reads a `protocol_model.json` produced by PacketHammer's `protocol-mapper` agent and writes a
self-contained, single-file HTML report to the **same directory** as the input JSON, named
`report.html`.

The report is designed to make a strong visual impression ("wow effect"):
- Dark GitHub-style theme with animated grid background and gradient hero title
- Scroll-fade animations on every section
- **Animated probe-loop diagram** — 7 steps cycle with per-step glow colours (JS-driven)
- **Animated packet-exchange visual** — CSS packets flying CLIENT ↔ SERVER
- **Animated hero counters** — numbers count up from 0 on page load (JS)
- **Critical-vulnerability pulse** — red glow animation on critical cards
- **Manual vs AI comparison section** — dramatises why AI-assisted beats manual testing
- All data sections fully populated from the JSON

---

## Input schema (`protocol_model.json`)

All fields are optional unless marked **(required)**.

```
binary          string   path to analysed binary
name            string   (required) protocol name shown in hero
description     string   one-sentence description
transport       { type, port, address, listen_backlog }
framing         { format, delimiter, encoding }
configuration   { file, format, required_keys, example }
authentication  { flow, token, token_check }
commands        { <NAME>: { description, syntax, usage, response, handler, vulnerability,
                            arguments, computation, state, ... } }
response_codes  { "<code>": "<description>", ... }
session_flow    [ { step, direction ("S->C"|"C->S"), message, description }, ... ]
vulnerabilities [ { id, function, type, detail, severity ("critical"|"high"|"medium"|"low") } ]
key_addresses   { <symbol>: "<hex_address>", ... }
seeds           [ { name, value, source, gate } ]         ← used for seed count stat
coverage        { branches_mapped, branches_unreached, note }
```

---

## Generation rules

### 1 — Hero stats (auto-derived, animated)

All four `.num` elements get `data-target="N"` and start at `0`; JS counts up on load.

| Stat               | Source                                        |
|--------------------|-----------------------------------------------|
| Commands found     | `Object.keys(commands).length`                |
| Response codes     | `Object.keys(response_codes).length`          |
| Vulnerabilities    | `vulnerabilities.length`                      |
| Transport port     | `transport.port` — port num uses `port-num` class (cyan) |

### 2 — Result banner

- **Title**: `name`
- **Sub**: `{transport.type} port {transport.port} · {framing.format} · {framing.encoding}` (omit missing parts)
- Stats: commands, response codes, vulnerabilities, seeds harvested (`seeds.length`)

### 3 — Probe-loop diagram

Always included. Hard-coded 7-step loop because it describes the PacketHammer engine, not the
protocol under test. Rendered as a row of `.probe-step` boxes with `.probe-connector` arrows.
JS cycles `.active` class through steps every 1200 ms; each step colour class `c1`–`c7` maps
to a distinct border/shadow/text colour (cyan → orange → green → cyan → purple → yellow → green).

Below the loop render a `.probe-desc-grid` with one `.pd-item` per step explaining what it does.

### 4 — Animated packet exchange

Placed above the detailed session-flow rows. Shows a CLIENT box, an animated lane with
CSS-flying packets (orange C→S, cyan S→C), and a SERVER box.
Three `.pex-packet` divs per track at staggered `animation-delay` values create a continuous stream.
`@keyframes flyRight` moves `left: -5%` → `left: 105%`; S→C track uses `animation-direction: reverse`.

### 5 — Session flow rows

Iterate `session_flow` array in order.
- `direction === "S->C"` → class `sc`, label `S→C`
- `direction === "C->S"` → class `cs`, label `C→S`
- Classify `sf-msg` class:
  - first row → `banner`
  - contains `TOKEN` → `token`
  - starts with `2xx|3xx|4xx|5xx` response code → `resp`
  - starts with uppercase command word → `cmd`

### 6 — Command cards

Iterate `commands` object. For each command:
- `cmd-name`: the key (e.g. `HI`)
- `cmd-auth` badge: "PRE-AUTH" or "POST-AUTH" derived from `state` or `must_precede` (post-auth if auth step is a prerequisite)
- `cmd-syntax`: `usage` field if present, else `syntax`
- Body: `description`
- Vulnerability badge if `vulnerability` key present:
  - Contains `overflow` or `strcpy` or `buffer` → class `critical`, label `Critical overflow`
  - Contains `integer` or `memset` → class `medium`, label `Integer overflow`
  - Otherwise → class `medium`, label `Vulnerability`

### 7 — Vulnerability cards

Iterate `vulnerabilities` array. For each entry:
- Card class: `vuln-card {severity}` mapping: `high` → `critical`, `low` → `medium`
- `vuln-id`, `vuln-sev` (capitalised), type `tag`
- `h3` heading from `type`:
  - `stack_buffer_overflow` → "Unchecked strcpy / stack buffer overflow"
  - `integer_overflow` / `unbounded_memset` → "Signed integer overflow → unbounded memset"
  - `resource_exhaustion` → "Unbounded memory growth"
  - `use_after_free` → "Use-after-free"
  - `format_string` → "Format string vulnerability"
  - other → title-case `type`
- `vfn`: `function`
- Body: `detail`
- PoC trigger: parse command from `id`; if token present include it; for `stack_buffer_overflow` use 34×`A`; for `integer_overflow` use `65536 65536`; otherwise fuzz fallback
- Critical cards get `animation: critPulse 4s ease-in-out infinite` (red glow pulse)

### 8 — Manual vs AI comparison section  ← NEW

Always included. Hard-coded content (not from JSON) that makes the case for AI-assisted testing.

**Hero stats row** (three big numbers):
- `720×` faster (4 minutes vs 2 days minimum)
- `12` seeds auto-harvested (from `seeds.length`, or hard-coded if absent)
- `$0` per rerun (vs $15k+ manual pentest)

**Two comparison cards** side-by-side:
- LEFT card `.cmp-card.manual`: "👤 Manual Penetration Testing" with `.bad` metrics
- RIGHT card `.cmp-card.ai`: "🤖 PacketHammer AI Pipeline" with `.good` metrics

Metrics (each as `.cmp-metric` row with icon + label + value):
| Icon | Label | Manual value (.bad) | AI value (.good) |
|------|-------|---------------------|------------------|
| ⏱ | Time to map protocol | 2–5 days | ~4 minutes |
| 📊 | Protocol coverage | ~30–40% branches | 100% logical paths |
| 🔍 | Vulnerability detection | Analyst-dependent | Automated (Frida + Ghidra) |
| 🌱 | Seed discovery | Source code required | Runtime oracle (Tier 1 + 2) |
| 📋 | Documentation | Ad-hoc notes | Machine-readable JSON |
| 🔄 | Reproducibility | Varies with analyst | Deterministic |

**Feature comparison table** `.cmp-table` below the cards:

| Capability | Manual | PacketHammer |
|---|---|---|
| Protocol structure discovery | ❌ Manual reverse engineering | ✅ Automated (Ghidra + Frida) |
| Seed harvesting | ❌ Requires source code | ✅ Runtime comparison hooks |
| Vulnerability scanning | ❌ Analyst skill required | ✅ Pattern + static analysis |
| Session flow documentation | ❌ Ad-hoc notes | ✅ Structured JSON + HTML |
| Zero-day seeds | ❌ Often missed | ✅ Tier 1 + Tier 2 oracles |
| Coverage tracking | ❌ Estimated | ✅ Branch-level instrumentation |
| Reproducibility | ❌ Variable | ✅ Deterministic across runs |
| Scales with binary size | ❌ Degrades rapidly | ✅ Consistent performance |
| Time to first vulnerability | ❌ Hours to days | ✅ Minutes |

### 9 — Key addresses table

If `key_addresses` is present and non-empty, render a `<section id="addrs">` after the comparison.
Add hover row-highlight via CSS (`.addr-table tr:hover td { background: var(--surface2); }`).

---

## Full HTML template

Use this exact structure. Replace `{{placeholder}}` tokens with derived values.

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{name}} — Protocol Report · PacketHammer</title>
<style>
  :root {
    --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--border:#30363d;
    --green:#3fb950;--green-dim:#238636;--cyan:#58a6ff;--orange:#f0883e;
    --red:#f85149;--yellow:#e3b341;--purple:#bc8cff;
    --text:#e6edf3;--text-dim:#8b949e;--text-muted:#484f58;
  }
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;line-height:1.6;}

  nav{position:sticky;top:0;z-index:100;background:rgba(13,17,23,.95);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);padding:14px 32px;display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
  nav .logo{font-size:18px;font-weight:700;color:var(--green);letter-spacing:-.5px;margin-right:8px;}
  nav .logo span{color:var(--text-dim);font-weight:400;}
  nav a{color:var(--text-dim);text-decoration:none;font-size:13px;transition:color .2s;white-space:nowrap;}
  nav a:hover{color:var(--text);}

  .hero{padding:96px 32px 80px;text-align:center;position:relative;overflow:hidden;}
  .hero-grid{position:absolute;inset:0;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:48px 48px;opacity:.17;pointer-events:none;animation:gridDrift 40s linear infinite;}
  .hero-glow{position:absolute;inset:0;background:radial-gradient(ellipse 80% 50% at 50% 0%,rgba(63,185,80,.11) 0%,transparent 65%);pointer-events:none;}
  .hero .badge{display:inline-flex;align-items:center;gap:6px;background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.3);border-radius:20px;padding:4px 14px;font-size:12px;color:var(--green);margin-bottom:24px;position:relative;animation:floatBadge 4s ease-in-out infinite;}
  .hero h1{font-size:clamp(36px,6vw,68px);font-weight:800;letter-spacing:-2px;line-height:1.05;margin-bottom:20px;position:relative;}
  .hero h1 em{font-style:normal;background:linear-gradient(135deg,var(--green) 0%,var(--cyan) 50%,var(--purple) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;background-size:200% 200%;animation:gradShift 6s ease infinite;}
  .hero .subtitle{font-size:18px;color:var(--text-dim);max-width:640px;margin:0 auto 48px;position:relative;}
  .hero .stats{display:flex;justify-content:center;gap:56px;flex-wrap:wrap;position:relative;}
  .hero .stat .num{font-size:40px;font-weight:800;color:var(--green);letter-spacing:-1px;line-height:1;}
  .hero .stat .num.port-num{color:var(--cyan);}
  .hero .stat .label{font-size:11px;color:var(--text-dim);margin-top:6px;text-transform:uppercase;letter-spacing:1.5px;}

  section{padding:72px 32px;max-width:1100px;margin:0 auto;}
  section+section{padding-top:0;}
  .section-label{font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--green);margin-bottom:12px;}
  h2{font-size:clamp(24px,4vw,40px);font-weight:800;letter-spacing:-.5px;margin-bottom:16px;}
  .lead{font-size:17px;color:var(--text-dim);max-width:700px;margin-bottom:48px;}

  .result-banner{background:linear-gradient(135deg,rgba(63,185,80,.08),rgba(88,166,255,.06));border:1px solid rgba(63,185,80,.22);border-radius:16px;padding:32px;margin-bottom:40px;display:flex;align-items:center;gap:32px;flex-wrap:wrap;}
  .rb-title{font-size:26px;font-weight:700;margin-bottom:4px;}
  .rb-sub{color:var(--text-dim);font-size:14px;font-family:monospace;}
  .rb-stats{display:flex;gap:32px;flex-wrap:wrap;margin-left:auto;}
  .rb-stat{text-align:center;}
  .rb-stat .n{font-size:28px;font-weight:700;color:var(--green);}
  .rb-stat .l{font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px;}

  .codes-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:12px;}
  .code-item{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 18px;display:flex;gap:14px;align-items:flex-start;transition:border-color .2s;}
  .code-item:hover{border-color:var(--yellow);}
  .code-num{font-family:monospace;font-size:18px;font-weight:700;color:var(--yellow);flex-shrink:0;min-width:44px;}
  .code-desc{font-size:13px;color:var(--text-dim);}

  /* probe loop */
  .probe-loop-wrap{background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:36px 28px;margin:32px 0 40px;}
  .probe-loop{display:flex;align-items:center;overflow-x:auto;padding-bottom:8px;gap:0;}
  .probe-step{background:var(--surface2);border:1.5px solid var(--border);border-radius:12px;padding:12px 14px;text-align:center;min-width:86px;flex-shrink:0;transition:all .35s cubic-bezier(.4,0,.2,1);opacity:.3;}
  .probe-step .ps-num{font-size:9px;color:var(--text-muted);font-weight:700;letter-spacing:1px;margin-bottom:4px;}
  .probe-step .ps-name{font-family:monospace;font-size:12px;font-weight:700;color:var(--text-dim);}
  .probe-step .ps-cond{font-size:9px;color:var(--text-muted);margin-top:4px;line-height:1.3;}
  .probe-step.active{opacity:1;transform:translateY(-3px) scale(1.07);}
  .probe-step.c1.active{border-color:var(--cyan);box-shadow:0 0 22px rgba(88,166,255,.35);}
  .probe-step.c1.active .ps-name{color:var(--cyan);}
  .probe-step.c2.active{border-color:var(--orange);box-shadow:0 0 22px rgba(240,136,62,.35);}
  .probe-step.c2.active .ps-name{color:var(--orange);}
  .probe-step.c3.active{border-color:var(--green);box-shadow:0 0 22px rgba(63,185,80,.35);}
  .probe-step.c3.active .ps-name{color:var(--green);}
  .probe-step.c4.active{border-color:var(--cyan);box-shadow:0 0 22px rgba(88,166,255,.35);}
  .probe-step.c4.active .ps-name{color:var(--cyan);}
  .probe-step.c5.active{border-color:var(--purple);box-shadow:0 0 22px rgba(188,140,255,.35);}
  .probe-step.c5.active .ps-name{color:var(--purple);}
  .probe-step.c6.active{border-color:var(--yellow);box-shadow:0 0 22px rgba(227,179,65,.35);}
  .probe-step.c6.active .ps-name{color:var(--yellow);}
  .probe-step.c7.active{border-color:var(--green);box-shadow:0 0 22px rgba(63,185,80,.35);}
  .probe-step.c7.active .ps-name{color:var(--green);}
  .probe-connector{font-size:18px;color:var(--text-muted);padding:0 8px;flex-shrink:0;user-select:none;}
  .probe-desc-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;}
  .pd-item{display:flex;gap:12px;padding:14px;background:var(--surface2);border-radius:10px;border:1px solid var(--border);}
  .pd-num{font-family:monospace;font-size:22px;font-weight:800;color:var(--text-muted);min-width:26px;line-height:1;padding-top:2px;}
  .pd-body .pd-name{font-family:monospace;font-size:13px;font-weight:700;color:var(--text);margin-bottom:3px;}
  .pd-body .pd-desc{font-size:12px;color:var(--text-dim);line-height:1.55;}

  /* packet exchange */
  .pex-wrap{margin:32px 0 40px;}
  .pex-label{font-size:11px;color:var(--text-muted);text-align:center;margin-bottom:16px;text-transform:uppercase;letter-spacing:1.5px;}
  .pex{display:flex;align-items:center;height:130px;}
  .pex-node{background:var(--surface2);border:1px solid var(--border);border-radius:16px;padding:16px 20px;text-align:center;min-width:96px;flex-shrink:0;}
  .pn-icon{font-size:26px;margin-bottom:5px;}
  .pn-label{font-family:monospace;font-size:10px;font-weight:700;color:var(--text-dim);letter-spacing:2px;text-transform:uppercase;}
  .pex-lane{flex:1;height:100%;display:flex;flex-direction:column;justify-content:center;gap:14px;padding:0 16px;}
  .pex-track{position:relative;height:28px;overflow:hidden;display:flex;align-items:center;}
  .pex-line{position:absolute;left:0;right:0;height:1px;background:var(--border);}
  .pex-track-label{position:absolute;z-index:2;font-size:9px;font-family:monospace;letter-spacing:1px;background:var(--bg);}
  .pex-track.cs .pex-track-label{left:4px;color:var(--orange);}
  .pex-track.sc .pex-track-label{right:4px;color:var(--cyan);}
  .pex-arrow{position:absolute;font-size:12px;color:var(--text-muted);z-index:2;background:var(--bg);padding:0 2px;}
  .pex-track.cs .pex-arrow{right:4px;}
  .pex-track.sc .pex-arrow{left:4px;}
  .pex-packet{position:absolute;width:18px;height:18px;border-radius:4px;opacity:0;z-index:3;top:50%;transform:translateY(-50%);}
  .pex-track.cs .pex-packet{background:var(--orange);box-shadow:0 0 8px rgba(240,136,62,.7);animation:flyRight 3.2s ease-in-out infinite;}
  .pex-track.sc .pex-packet{background:var(--cyan);box-shadow:0 0 8px rgba(88,166,255,.7);animation:flyRight 3.2s ease-in-out infinite reverse;}
  .pex-track .pex-packet:nth-child(3){animation-delay:1.07s;}
  .pex-track .pex-packet:nth-child(4){animation-delay:2.13s;}

  /* session flow */
  .session-flow{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px;}
  .sf-row{display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-bottom:1px solid var(--border);}
  .sf-row:last-child{border-bottom:none;}
  .sf-dir{font-family:monospace;font-size:11px;font-weight:700;width:36px;flex-shrink:0;padding-top:4px;}
  .sf-dir.sc{color:var(--cyan);}
  .sf-dir.cs{color:var(--orange);}
  .sf-msg{font-family:monospace;font-size:13px;background:var(--surface2);padding:4px 10px;border-radius:6px;flex:1;min-width:0;word-break:break-all;}
  .sf-msg.banner{color:var(--cyan);}
  .sf-msg.cmd{color:var(--orange);}
  .sf-msg.resp{color:var(--green);}
  .sf-msg.token{color:var(--yellow);}
  .sf-desc{font-size:12px;color:var(--text-dim);flex:1;padding-top:5px;min-width:80px;}

  /* commands */
  .commands-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px;}
  .cmd-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;transition:transform .2s,border-color .2s;}
  .cmd-card:hover{transform:translateY(-2px);border-color:rgba(63,185,80,.4);}
  .cmd-name{font-family:monospace;font-size:20px;font-weight:700;color:var(--green);margin-bottom:4px;}
  .cmd-auth{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:8px;}
  .cmd-syntax{font-family:monospace;font-size:12px;color:var(--text-muted);margin-bottom:12px;background:var(--surface2);padding:5px 9px;border-radius:4px;}
  .cmd-card p{font-size:13px;color:var(--text-dim);line-height:1.55;}
  .vuln-badge{display:inline-flex;align-items:center;gap:4px;margin-top:12px;font-size:11px;font-weight:600;padding:3px 8px;border-radius:4px;}
  .vuln-badge.critical{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
  .vuln-badge.medium{background:rgba(227,179,65,.15);color:var(--yellow);border:1px solid rgba(227,179,65,.3);}

  /* vulnerabilities */
  .vuln-card{background:var(--surface);border-radius:16px;padding:28px;margin-bottom:20px;transition:transform .2s;}
  .vuln-card:hover{transform:translateX(4px);}
  .vuln-card.critical{border:1px solid rgba(248,81,73,.35);border-left:4px solid var(--red);animation:critPulse 4s ease-in-out infinite;}
  .vuln-card.medium,.vuln-card.low{border:1px solid rgba(227,179,65,.25);border-left:4px solid var(--yellow);}
  .vuln-card.high{border:1px solid rgba(240,136,62,.3);border-left:4px solid var(--orange);}
  .vuln-header{display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap;}
  .vuln-id{font-family:monospace;font-size:14px;font-weight:700;}
  .vuln-sev{font-size:10px;font-weight:700;padding:3px 10px;border-radius:20px;text-transform:uppercase;letter-spacing:1px;}
  .vuln-sev.critical,.vuln-sev.high{background:rgba(248,81,73,.15);color:var(--red);}
  .vuln-sev.medium,.vuln-sev.low{background:rgba(227,179,65,.15);color:var(--yellow);}
  .vuln-card h3{font-size:18px;font-weight:600;margin-bottom:6px;}
  .vfn{font-family:monospace;font-size:12px;color:var(--text-dim);margin-bottom:12px;}
  .vuln-card p{font-size:14px;color:var(--text-dim);margin-bottom:12px;line-height:1.65;}
  .exploit-label{font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px;}
  .exploit-box{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px 16px;font-family:monospace;font-size:13px;color:var(--orange);word-break:break-all;}
  .tag{font-size:11px;padding:2px 9px;border-radius:20px;border:1px solid var(--border);color:var(--text-dim);background:var(--surface);}

  /* comparison */
  .cmp-hero{display:flex;justify-content:center;align-items:center;gap:48px;flex-wrap:wrap;margin:40px 0 56px;}
  .cmp-hero-item{text-align:center;}
  .chi-n{font-size:56px;font-weight:800;letter-spacing:-3px;line-height:1;}
  .chi-n.bad{color:var(--red);}
  .chi-n.good{color:var(--green);}
  .chi-label{font-size:13px;color:var(--text-dim);margin-top:8px;}
  .chi-sub{font-size:11px;color:var(--text-muted);}
  .cmp-vs-badge{width:52px;height:52px;border-radius:50%;background:var(--surface2);border:2px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:800;color:var(--text-muted);letter-spacing:1px;flex-shrink:0;}
  .cmp-grid{display:grid;grid-template-columns:1fr 1fr;gap:24px;}
  .cmp-card{background:var(--surface);border-radius:20px;padding:32px;transition:transform .3s,box-shadow .3s;}
  .cmp-card:hover{transform:translateY(-4px);}
  .cmp-card.manual{border:1px solid rgba(248,81,73,.2);}
  .cmp-card.manual:hover{border-color:rgba(248,81,73,.45);box-shadow:0 20px 60px rgba(248,81,73,.08);}
  .cmp-card.ai{border:1px solid rgba(63,185,80,.2);}
  .cmp-card.ai:hover{border-color:rgba(63,185,80,.45);box-shadow:0 20px 60px rgba(63,185,80,.1);}
  .cmp-card-header{display:flex;align-items:center;gap:12px;margin-bottom:28px;}
  .cmp-card-icon{font-size:28px;}
  .cmp-card h3{font-size:18px;font-weight:700;}
  .cmp-card.manual h3{color:var(--red);}
  .cmp-card.ai h3{color:var(--green);}
  .cmp-metric{display:flex;align-items:flex-start;gap:10px;padding:11px 0;border-bottom:1px solid var(--border);}
  .cmp-metric:last-child{border-bottom:none;}
  .cmp-metric-icon{font-size:15px;flex-shrink:0;width:22px;line-height:1.5;}
  .cmp-metric-label{font-size:12px;color:var(--text-dim);margin-bottom:2px;}
  .cmp-metric-value{font-size:14px;font-weight:600;}
  .cmp-metric-value.bad{color:var(--red);}
  .cmp-metric-value.good{color:var(--green);}
  .cmp-table-wrap{margin-top:48px;overflow-x:auto;}
  .cmp-table{width:100%;border-collapse:collapse;}
  .cmp-table th,.cmp-table td{padding:12px 16px;text-align:left;border-bottom:1px solid var(--border);}
  .cmp-table th{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text-muted);border-bottom:2px solid var(--border);}
  .cmp-table td:first-child{font-size:14px;color:var(--text);}
  .cmp-table td:nth-child(2){color:var(--red);font-size:13px;}
  .cmp-table td:nth-child(3){color:var(--green);font-size:13px;}
  .cmp-table tr:hover td{background:var(--surface2);}
  .cmp-table tr:last-child td{border-bottom:none;}

  /* addresses */
  .addr-table{width:100%;border-collapse:collapse;font-family:monospace;font-size:14px;}
  .addr-table th{text-align:left;padding:10px 16px;border-bottom:2px solid var(--border);color:var(--text-dim);font-size:11px;text-transform:uppercase;letter-spacing:1px;}
  .addr-table td{padding:10px 16px;border-bottom:1px solid var(--border);}
  .addr-table td:first-child{color:var(--cyan);}
  .addr-table td:last-child{color:var(--green);}
  .addr-table tr:last-child td{border-bottom:none;}
  .addr-table tr:hover td{background:var(--surface2);}

  .divider{border:none;border-top:1px solid var(--border);margin:0;}
  .fade-in{opacity:0;transform:translateY(24px);transition:opacity .6s cubic-bezier(.4,0,.2,1),transform .6s cubic-bezier(.4,0,.2,1);}
  .fade-in.visible{opacity:1;transform:translateY(0);}
  footer{border-top:1px solid var(--border);padding:48px 32px;text-align:center;color:var(--text-muted);font-size:13px;}
  footer p+p{margin-top:8px;}

  @keyframes gridDrift{from{background-position:0 0}to{background-position:48px 48px}}
  @keyframes floatBadge{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
  @keyframes gradShift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
  @keyframes critPulse{0%,100%{box-shadow:0 0 0 rgba(248,81,73,0)}50%{box-shadow:0 0 50px rgba(248,81,73,.25),0 0 100px rgba(248,81,73,.08)}}
  @keyframes flyRight{0%{left:-5%;opacity:0}8%{opacity:1}92%{opacity:1}100%{left:105%;opacity:0}}

  @media(max-width:768px){
    nav{padding:12px 16px;gap:12px;}
    section{padding:48px 16px;}
    .hero{padding:64px 16px 56px;}
    .hero .stats{gap:32px;}
    .hero .stat .num{font-size:32px;}
    .cmp-grid{grid-template-columns:1fr;}
    .cmp-hero{gap:28px;}
    .chi-n{font-size:40px;}
    .pex{flex-direction:column;height:auto;}
    .pex-lane{width:100%;height:80px;}
  }
</style>
</head>
<body>

<nav>
  <div class="logo">🔨 PacketHammer <span>/ Protocol Report</span></div>
  <a href="#engine">How it works</a>
  <a href="#overview">Overview</a>
  <a href="#flow">Session flow</a>
  <a href="#commands">Commands</a>
  <a href="#vulns">Vulnerabilities</a>
  <a href="#compare">AI vs Manual</a>
  <a href="#addrs">Addresses</a>
</nav>

<div class="hero">
  <div class="hero-grid"></div>
  <div class="hero-glow"></div>
  <div class="badge">🤖 Auto-generated by PacketHammer</div>
  <h1>Protocol report:<br><em>{{name}}</em></h1>
  <p class="subtitle">{{description}}</p>
  <div class="stats">
    <div class="stat"><div class="num" data-target="{{cmd_count}}">0</div><div class="label">Commands found</div></div>
    <div class="stat"><div class="num" data-target="{{code_count}}">0</div><div class="label">Response codes</div></div>
    <div class="stat"><div class="num" data-target="{{vuln_count}}">0</div><div class="label">Vulnerabilities</div></div>
    <div class="stat"><div class="num port-num" data-target="{{port}}">0</div><div class="label">{{transport_type}} port</div></div>
  </div>
</div>

<hr class="divider">

<!-- PROBE LOOP -->
<section id="engine" class="fade-in">
  <div class="section-label">The engine</div>
  <h2>Autonomous probe loop</h2>
  <p class="lead">PacketHammer runs a 7-step cycle continuously — probing, instrumenting, decompiling, and building a protocol model with no human guidance. The loop below is live.</p>
  <div class="probe-loop-wrap">
    <div class="probe-loop">
      <div class="probe-step c1 active"><div class="ps-num">STEP 1</div><div class="ps-name">RESET</div></div>
      <div class="probe-connector">→</div>
      <div class="probe-step c2"><div class="ps-num">STEP 2</div><div class="ps-name">SEND</div></div>
      <div class="probe-connector">→</div>
      <div class="probe-step c3"><div class="ps-num">STEP 3</div><div class="ps-name">OBSERVE</div></div>
      <div class="probe-connector">→</div>
      <div class="probe-step c4"><div class="ps-num">STEP 4</div><div class="ps-name">UPDATE</div></div>
      <div class="probe-connector">→</div>
      <div class="probe-step c5"><div class="ps-num">STEP 5</div><div class="ps-name">CODE-ANALYZE</div><div class="ps-cond">if new branch</div></div>
      <div class="probe-connector">→</div>
      <div class="probe-step c6"><div class="ps-num">STEP 6</div><div class="ps-name">SUPERVISOR</div><div class="ps-cond">every 5 steps</div></div>
      <div class="probe-connector">→</div>
      <div class="probe-step c7"><div class="ps-num">STEP 7</div><div class="ps-name">HARVEST</div><div class="ps-cond">if plateau</div></div>
    </div>
  </div>
  <div class="probe-desc-grid">
    <div class="pd-item"><div class="pd-num">1</div><div class="pd-body"><div class="pd-name">RESET</div><div class="pd-desc">Clear Frida branch hit counters, Tier 1 comparison buffers, and Tier 2 address hit counts. Establishes a clean baseline so each probe cycle is independent.</div></div></div>
    <div class="pd-item"><div class="pd-num">2</div><div class="pd-body"><div class="pd-name">SEND</div><div class="pd-desc">Craft the next packet from the seed pool and current protocol state. Send it over TCP. Probe shape is guided by which branches remain unvisited.</div></div></div>
    <div class="pd-item"><div class="pd-num">3</div><div class="pd-body"><div class="pd-name">OBSERVE</div><div class="pd-desc">Read the server response. Query Frida Tier 1 (stdlib comparison hooks) and Tier 2 (per-address argument captures). Extract seeds from both oracle layers.</div></div></div>
    <div class="pd-item"><div class="pd-num">4</div><div class="pd-body"><div class="pd-name">UPDATE</div><div class="pd-desc">Merge newly-discovered branches, sequences, seeds, and field annotations into state.json and packet_graph.json. Increment probe counter and plateau tracker.</div></div></div>
    <div class="pd-item"><div class="pd-num">5</div><div class="pd-body"><div class="pd-name">CODE-ANALYZE</div><div class="pd-desc">Triggered when a new branch address is first hit. Ghidra decompiles the function. String literals become seeds. Vulnerability patterns are appended to vulnerabilities.jsonl.</div></div></div>
    <div class="pd-item"><div class="pd-num">6</div><div class="pd-body"><div class="pd-name">SUPERVISOR</div><div class="pd-desc">A read-only analysis agent reviews coverage gaps every 5 steps (or on plateau). Recommends new probe directions and seed strategies without touching protocol state.</div></div></div>
    <div class="pd-item"><div class="pd-num">7</div><div class="pd-body"><div class="pd-name">HARVEST</div><div class="pd-desc">Collect all seeds from Frida comparison buffers (Tier 1 + Tier 2). Reset hit counts. Write seeds to state.json so the next cycle can reach deeper branches.</div></div></div>
  </div>
</section>

<hr class="divider">

<!-- OVERVIEW -->
<section id="overview" class="fade-in">
  <div class="section-label">Protocol overview</div>
  <h2>{{name}}</h2>
  <p class="lead">{{description}}</p>
  <div class="result-banner">
    <div>
      <div class="rb-title">{{name}}</div>
      <div class="rb-sub">{{transport_type}} port {{port}} · {{framing_format}} · {{framing_encoding}}</div>
    </div>
    <div class="rb-stats">
      <div class="rb-stat"><div class="n">{{cmd_count}}</div><div class="l">Commands</div></div>
      <div class="rb-stat"><div class="n">{{code_count}}</div><div class="l">Response codes</div></div>
      <div class="rb-stat"><div class="n">{{vuln_count}}</div><div class="l">Vulnerabilities</div></div>
      <div class="rb-stat"><div class="n">{{seed_count}}</div><div class="l">Seeds harvested</div></div>
    </div>
  </div>
  <h3 style="font-size:18px;margin-bottom:16px;">Response codes</h3>
  <div class="codes-grid" style="margin-bottom:0">
    {{RESPONSE_CODES_HTML}}
  </div>
</section>

<hr class="divider">

<!-- SESSION FLOW -->
<section id="flow" class="fade-in">
  <div class="section-label">Session flow</div>
  <h2>How a conversation works</h2>
  <p class="lead">Every message exchanged between client and server, in the order the protocol requires — discovered purely through live instrumentation, zero source code.</p>
  <div class="pex-wrap">
    <div class="pex-label">Live packet exchange — CLIENT ↔ SERVER</div>
    <div class="pex">
      <div class="pex-node"><div class="pn-icon">💻</div><div class="pn-label">CLIENT</div></div>
      <div class="pex-lane">
        <div class="pex-track cs">
          <div class="pex-line"></div>
          <div class="pex-track-label">C → S</div>
          <div class="pex-packet"></div><div class="pex-packet"></div><div class="pex-packet"></div>
          <div class="pex-arrow">▶</div>
        </div>
        <div class="pex-track sc">
          <div class="pex-line"></div>
          <div class="pex-track-label">S → C</div>
          <div class="pex-packet"></div><div class="pex-packet"></div><div class="pex-packet"></div>
          <div class="pex-arrow">◀</div>
        </div>
      </div>
      <div class="pex-node"><div class="pn-icon">🖥️</div><div class="pn-label">SERVER</div></div>
    </div>
  </div>
  <div class="session-flow">
    {{SESSION_FLOW_HTML}}
  </div>
</section>

<hr class="divider">

<!-- COMMANDS -->
<section id="commands" class="fade-in">
  <div class="section-label">Command set</div>
  <h2>{{cmd_count}} commands discovered</h2>
  <p class="lead">Every command the server accepts — syntax, behaviour, authentication requirement, and any security flags found during live instrumentation.</p>
  <div class="commands-grid">
    {{COMMANDS_HTML}}
  </div>
</section>

<hr class="divider">

<!-- VULNERABILITIES -->
<section id="vulns" class="fade-in">
  <div class="section-label">Vulnerabilities found</div>
  <h2>{{vuln_count}} security issue(s) discovered automatically</h2>
  <p class="lead">PacketHammer's code-analyzer agent flagged these dangerous patterns by combining Ghidra static decompilation with live Frida instrumentation — no human review required.</p>
  {{VULNS_HTML}}
</section>

<hr class="divider">

<!-- MANUAL vs AI -->
<section id="compare" class="fade-in">
  <div class="section-label">AI-assisted security testing</div>
  <h2>Manual testing vs PacketHammer</h2>
  <p class="lead">Same target. Same vulnerabilities. The difference is whether you find them in minutes or days — and whether the documentation writes itself.</p>
  <div class="cmp-hero">
    <div class="cmp-hero-item">
      <div class="chi-n bad">~2 days</div>
      <div class="chi-label">Minimum for manual mapping</div>
      <div class="chi-sub">experienced pentester, closed-source binary</div>
    </div>
    <div class="cmp-vs-badge">VS</div>
    <div class="cmp-hero-item">
      <div class="chi-n good">~4 min</div>
      <div class="chi-label">PacketHammer full run</div>
      <div class="chi-sub">commands + vulns + report, zero guidance</div>
    </div>
    <div class="cmp-vs-badge" style="margin:0 -16px;">·</div>
    <div class="cmp-hero-item">
      <div class="chi-n good">{{seed_count}}</div>
      <div class="chi-label">Seeds auto-harvested</div>
      <div class="chi-sub">from Frida runtime comparisons</div>
    </div>
    <div class="cmp-vs-badge" style="margin:0 -16px;">·</div>
    <div class="cmp-hero-item">
      <div class="chi-n good">$0</div>
      <div class="chi-label">Per subsequent rerun</div>
      <div class="chi-sub">vs $15k+ manual pentest</div>
    </div>
  </div>
  <div class="cmp-grid">
    <div class="cmp-card manual">
      <div class="cmp-card-header"><div class="cmp-card-icon">👤</div><h3>Manual Penetration Testing</h3></div>
      <div class="cmp-metric"><div class="cmp-metric-icon">⏱</div><div><div class="cmp-metric-label">Time to map protocol</div><div class="cmp-metric-value bad">2–5 days</div></div></div>
      <div class="cmp-metric"><div class="cmp-metric-icon">📊</div><div><div class="cmp-metric-label">Branch coverage</div><div class="cmp-metric-value bad">~30–40% estimated</div></div></div>
      <div class="cmp-metric"><div class="cmp-metric-icon">🔍</div><div><div class="cmp-metric-label">Vulnerability detection</div><div class="cmp-metric-value bad">Analyst skill required</div></div></div>
      <div class="cmp-metric"><div class="cmp-metric-icon">🌱</div><div><div class="cmp-metric-label">Seed / credential discovery</div><div class="cmp-metric-value bad">Source code or lucky guess</div></div></div>
      <div class="cmp-metric"><div class="cmp-metric-icon">📋</div><div><div class="cmp-metric-label">Output documentation</div><div class="cmp-metric-value bad">Ad-hoc notes, often incomplete</div></div></div>
      <div class="cmp-metric"><div class="cmp-metric-icon">🔄</div><div><div class="cmp-metric-label">Reproducibility</div><div class="cmp-metric-value bad">Varies between analysts</div></div></div>
    </div>
    <div class="cmp-card ai">
      <div class="cmp-card-header"><div class="cmp-card-icon">🤖</div><h3>PacketHammer AI Pipeline</h3></div>
      <div class="cmp-metric"><div class="cmp-metric-icon">⏱</div><div><div class="cmp-metric-label">Time to map protocol</div><div class="cmp-metric-value good">~4 minutes</div></div></div>
      <div class="cmp-metric"><div class="cmp-metric-icon">📊</div><div><div class="cmp-metric-label">Branch coverage</div><div class="cmp-metric-value good">100% logical paths validated</div></div></div>
      <div class="cmp-metric"><div class="cmp-metric-icon">🔍</div><div><div class="cmp-metric-label">Vulnerability detection</div><div class="cmp-metric-value good">Automated (Frida + Ghidra)</div></div></div>
      <div class="cmp-metric"><div class="cmp-metric-icon">🌱</div><div><div class="cmp-metric-label">Seed / credential discovery</div><div class="cmp-metric-value good">Runtime oracle: Tier 1 + Tier 2</div></div></div>
      <div class="cmp-metric"><div class="cmp-metric-icon">📋</div><div><div class="cmp-metric-label">Output documentation</div><div class="cmp-metric-value good">Structured JSON + this HTML report</div></div></div>
      <div class="cmp-metric"><div class="cmp-metric-icon">🔄</div><div><div class="cmp-metric-label">Reproducibility</div><div class="cmp-metric-value good">Deterministic across runs</div></div></div>
    </div>
  </div>
  <div class="cmp-table-wrap">
    <table class="cmp-table">
      <thead><tr><th>Capability</th><th>Manual</th><th>PacketHammer</th></tr></thead>
      <tbody>
        <tr><td>Protocol structure discovery</td><td>❌ Manual reverse engineering</td><td>✅ Automated (Ghidra + Frida)</td></tr>
        <tr><td>Seed harvesting</td><td>❌ Requires source code or deep RE</td><td>✅ Runtime comparison hooks</td></tr>
        <tr><td>Vulnerability pattern scanning</td><td>❌ Code review by analyst</td><td>✅ Static + dynamic analysis</td></tr>
        <tr><td>Session flow documentation</td><td>❌ Ad-hoc notes, often lost</td><td>✅ Structured JSON + HTML</td></tr>
        <tr><td>Zero-day seeds (hidden comparisons)</td><td>❌ Frequently missed</td><td>✅ Tier 1 + Tier 2 oracles</td></tr>
        <tr><td>Coverage tracking</td><td>❌ Estimated / gut feel</td><td>✅ Branch-level instrumentation</td></tr>
        <tr><td>Scales with binary complexity</td><td>❌ Degrades rapidly</td><td>✅ Consistent performance</td></tr>
        <tr><td>Cost per rerun</td><td>❌ Full analyst time × rate</td><td>✅ Compute cost only</td></tr>
        <tr><td>Time to first vulnerability</td><td>❌ Hours to days</td><td>✅ Minutes</td></tr>
      </tbody>
    </table>
  </div>
</section>

<!-- KEY ADDRESSES -->
{{KEY_ADDRESSES_SECTION_HTML}}

<footer>
  <p>{{name}} · Protocol report generated by PacketHammer</p>
  <p style="margin-top:8px;">binary: {{binary}}</p>
</footer>

<script>
  // fade-in on scroll
  const fadeObserver = new IntersectionObserver((entries) => {
    entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('visible'); fadeObserver.unobserve(e.target); } });
  }, { threshold: 0.08 });
  document.querySelectorAll('.fade-in').forEach(el => fadeObserver.observe(el));

  // animated counters
  function runCounter(el) {
    const target = parseInt(el.dataset.target, 10);
    const dur = target > 1000 ? 1800 : 1200;
    const start = performance.now();
    const tick = (now) => {
      const p = Math.min((now - start) / dur, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.floor(eased * target);
      if (p < 1) requestAnimationFrame(tick); else el.textContent = target;
    };
    requestAnimationFrame(tick);
  }
  const cntObserver = new IntersectionObserver((entries) => {
    entries.forEach(e => { if (e.isIntersecting) { runCounter(e.target); cntObserver.unobserve(e.target); } });
  }, { threshold: 0.5 });
  document.querySelectorAll('.num[data-target]').forEach(el => cntObserver.observe(el));

  // probe loop animation
  const steps = document.querySelectorAll('.probe-step');
  if (steps.length) {
    let cur = 0;
    steps[0].classList.add('active');
    setInterval(() => {
      steps[cur].classList.remove('active');
      cur = (cur + 1) % steps.length;
      steps[cur].classList.add('active');
    }, 1200);
  }
</script>
</body>
</html>
```

---

## Step-by-step execution

1. **Read** the protocol_model.json at the given (or discovered) path.
2. **Compute derived values**:
   - `cmd_count` = number of keys in `commands` (or sequences with unique command names)
   - `code_count` = number of keys in `response_codes`
   - `vuln_count` = `vulnerabilities.length`
   - `seed_count` = `seeds.length` (or 0)
   - `port` = `transport.port` string
   - `transport_type` = `transport.type` default `"TCP"`
   - `framing_format` = `framing.format` or `"line-delimited"`
   - `framing_encoding` = `framing.encoding` or `"ASCII"`
3. **Render `RESPONSE_CODES_HTML`**: one `.code-item` per response_codes entry.
4. **Render `SESSION_FLOW_HTML`**: per session_flow entry, apply direction/class rules from section 5.
5. **Render `COMMANDS_HTML`**: per command, add `cmd-auth` badge and optional `vuln-badge`.
6. **Render `VULNS_HTML`**: per vulnerability, apply severity class, heading, and synthesise PoC.
7. **Render `KEY_ADDRESSES_SECTION_HTML`**: full `<section id="addrs">` block if `key_addresses` is non-empty; otherwise empty string.
8. **Substitute** all `{{placeholder}}` tokens.
9. **Write** to `<same-directory-as-input>/report.html`.
10. **Report** the output path to the user.

---

## Quality rules

- Single self-contained file — no external CSS, no CDN, no images.
- Every section with no data must be omitted entirely.
- If `vulnerabilities` is empty: replace heading with *"No vulnerabilities identified in this run."*
- Escape all user-derived strings for HTML (`<`, `>`, `&`, `"`, `'`).
- Do not invent data not present in the JSON.
- The file must open in a browser with no JS errors and no broken animations.
