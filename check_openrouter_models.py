#!/usr/bin/env python3
"""
Check whether OpenRouter models can answer a minimal chat completion request.

Usage:
  OPENROUTER_API_KEY=sk-or-... ./check_openrouter_models.py
  OPENROUTER_API_KEY=sk-or-... ./check_openrouter_models.py --free --limit 20
  OPENROUTER_API_KEY=sk-or-... ./check_openrouter_models.py --model openai/gpt-4.1-mini
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Iterable


OPENROUTER_API_URL = "https://openrouter.ai/api/v1"

# Keep this list small enough for a quick smoke test. Use --all or --free to
# load the current model list from OpenRouter before checking inference.
DEFAULT_MODELS = [
    "openai/gpt-4.1-mini",
    "openai/gpt-4o-mini",
    "anthropic/claude-3.5-haiku",
    "google/gemini-2.5-flash",
    "google/gemini-2.0-flash-001",
    "meta-llama/llama-3.3-70b-instruct",
    "mistralai/mistral-small-3.1-24b-instruct",
    "deepseek/deepseek-chat",
    "qwen/qwen-2.5-72b-instruct",
]


@dataclass(frozen=True)
class CheckResult:
    model: str
    ok: bool
    status: int | None
    latency_seconds: float
    message: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check inference availability for OpenRouter models."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--all",
        action="store_true",
        help="Fetch and check all text-capable models from OpenRouter.",
    )
    source.add_argument(
        "--free",
        action="store_true",
        help="Fetch and check models whose IDs end with ':free'.",
    )
    parser.add_argument(
        "--model",
        action="append",
        dest="models",
        help="Model ID to check. Can be passed multiple times.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum number of models to check after model selection.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=45.0,
        help="HTTP timeout per inference request in seconds.",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.0,
        help="Delay between requests in seconds.",
    )
    parser.add_argument(
        "--output-json",
        help="Optional path to write full results as JSON.",
    )
    parser.add_argument(
        "--referer",
        default=os.getenv("OPENROUTER_HTTP_REFERER", "https://localhost"),
        help="Value for OpenRouter-optional HTTP-Referer header.",
    )
    parser.add_argument(
        "--title",
        default=os.getenv("OPENROUTER_APP_TITLE", "OpenRouter Model Checker"),
        help="Value for OpenRouter-optional X-Title header.",
    )
    return parser.parse_args()


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    payload: dict[str, object] | None = None,
    timeout: float = 45.0,
) -> tuple[int, dict[str, object]]:
    body = None
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=body,
        headers=request_headers,
        method=method,
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        response_body = response.read().decode("utf-8")
        data = json.loads(response_body) if response_body else {}
        return response.status, data


def load_models(args: argparse.Namespace) -> list[str]:
    if args.models:
        return dedupe(args.models)

    if not args.all and not args.free:
        return DEFAULT_MODELS[:]

    status, data = request_json(
        f"{OPENROUTER_API_URL}/models",
        timeout=max(args.timeout, 10.0),
    )
    if status != 200:
        raise RuntimeError(f"OpenRouter /models returned HTTP {status}")

    models: list[str] = []
    for item in data.get("data", []):
        if not isinstance(item, dict):
            continue
        model_id = item.get("id")
        if not isinstance(model_id, str):
            continue
        if args.free and not model_id.endswith(":free"):
            continue
        if supports_text_input(item):
            models.append(model_id)

    return dedupe(models)


def supports_text_input(model: dict[str, object]) -> bool:
    architecture = model.get("architecture")
    if not isinstance(architecture, dict):
        return True
    input_modalities = architecture.get("input_modalities")
    if not isinstance(input_modalities, list):
        return True
    return "text" in input_modalities


def dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def check_model(
    model: str,
    *,
    api_key: str,
    timeout: float,
    referer: str,
    title: str,
) -> CheckResult:
    payload: dict[str, object] = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": "Reply with exactly: ok",
            }
        ],
        "max_tokens": 8,
        "temperature": 0,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": referer,
        "X-Title": title,
    }

    started = time.monotonic()
    try:
        status, data = request_json(
            f"{OPENROUTER_API_URL}/chat/completions",
            method="POST",
            headers=headers,
            payload=payload,
            timeout=timeout,
        )
    except urllib.error.HTTPError as exc:
        latency = time.monotonic() - started
        message = read_error_message(exc)
        return CheckResult(model, False, exc.code, latency, message)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        latency = time.monotonic() - started
        return CheckResult(model, False, None, latency, str(exc))

    latency = time.monotonic() - started
    choices = data.get("choices")
    if status == 200 and isinstance(choices, list) and choices:
        return CheckResult(model, True, status, latency, "inference ok")

    return CheckResult(model, False, status, latency, compact_json(data))


def read_error_message(exc: urllib.error.HTTPError) -> str:
    try:
        raw = exc.read().decode("utf-8")
    except OSError:
        return exc.reason
    if not raw:
        return exc.reason
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw[:300]
    return compact_json(data)


def compact_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))[:500]


def print_result(result: CheckResult) -> None:
    status = result.status if result.status is not None else "-"
    marker = "OK" if result.ok else "FAIL"
    print(
        f"{marker:4} {result.model:55} "
        f"http={status!s:>3} latency={result.latency_seconds:6.2f}s "
        f"{result.message}"
    )


def main() -> int:
    args = parse_args()
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("ERROR: set OPENROUTER_API_KEY before running this script.", file=sys.stderr)
        return 2

    try:
        models = load_models(args)
    except Exception as exc:
        print(f"ERROR: failed to load model list: {exc}", file=sys.stderr)
        return 2

    if args.limit > 0:
        models = models[: args.limit]

    if not models:
        print("ERROR: no models selected.", file=sys.stderr)
        return 2

    results: list[CheckResult] = []
    print(f"Checking {len(models)} model(s) via OpenRouter chat completions...")
    for index, model in enumerate(models, start=1):
        print(f"[{index}/{len(models)}] ", end="", flush=True)
        result = check_model(
            model,
            api_key=api_key,
            timeout=args.timeout,
            referer=args.referer,
            title=args.title,
        )
        results.append(result)
        print_result(result)
        if args.sleep > 0 and index < len(models):
            time.sleep(args.sleep)

    ok_count = sum(result.ok for result in results)
    fail_count = len(results) - ok_count
    print(f"\nSummary: {ok_count} OK, {fail_count} FAIL")

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as file:
            json.dump(
                [result.__dict__ for result in results],
                file,
                ensure_ascii=False,
                indent=2,
            )
            file.write("\n")
        print(f"Wrote JSON results to {args.output_json}")

    return 0 if ok_count > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
