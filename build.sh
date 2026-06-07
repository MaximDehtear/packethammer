#!/usr/bin/env bash
set -euo pipefail

# Переходим в папку со скриптом
cd "$(dirname "$0")"

IMAGE_NAME="packethammer"
TAG="latest"

echo "▶ Сборка ${IMAGE_NAME}:${TAG} ..."
# OpenRouter key is passed at build time from the host env (never committed to git).
# Set it first:  export OPENROUTER_API_KEY=sk-or-...
docker build \
    --build-arg OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}" \
    -t "${IMAGE_NAME}:${TAG}" .
echo "✔ Готово."
