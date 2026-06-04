#!/usr/bin/env bash
set -euo pipefail

# Переходим в папку со скриптом
cd "$(dirname "$0")"

IMAGE_NAME="packethammer"
TAG="latest"

echo "▶ Сборка ${IMAGE_NAME}:${TAG} ..."
docker build -t "${IMAGE_NAME}:${TAG}" .
echo "✔ Готово."
