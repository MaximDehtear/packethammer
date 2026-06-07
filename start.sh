#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

IMAGE_NAME="packethammer"
TAG="latest"
CONTAINER_NAME="packethammer"
WORKSPACE_DIR="$(pwd)/workspace"

mkdir -p "${WORKSPACE_DIR}/netproto"
mkdir -p "${WORKSPACE_DIR}/logs"
touch "${WORKSPACE_DIR}/netproto/knowledge.jsonl" 2>/dev/null || true

echo "▶ Запуск ${CONTAINER_NAME} ... (интерактивный TUI)"
echo "  ⌘ Маппинг: ${WORKSPACE_DIR} → /workspace"
echo "  ℹ Для автономного прогона см. README раздел 'Autonomous run' (PH_MODE/PH_TARGET/PH_PROMPT)."

# PH_INTERACTIVE=1 forces the legacy interactive shell instead of the autonomous runner.
docker run -it --rm \
    --name "${CONTAINER_NAME}" \
    --network host \
    --add-host host.docker.internal:host-gateway \
    -e PH_INTERACTIVE=1 \
    -v "${WORKSPACE_DIR}:/workspace" \
    "${IMAGE_NAME}:${TAG}"

# Fix ownership of any files written by root inside the container
docker run --rm \
    -v "${WORKSPACE_DIR}:/workspace" \
    "${IMAGE_NAME}:${TAG}" \
    chown -R "$(id -u):$(id -g)" /workspace 2>/dev/null || true
