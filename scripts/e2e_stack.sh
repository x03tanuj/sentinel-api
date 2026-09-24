#!/usr/bin/env bash
set -euo pipefail

# SentinelAPI E2E Stack Manager
# Starts stack, waits for healthchecks, and resets target API state

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

ACTION="${1:-start}"

if [ "${ACTION}" = "secure" ]; then
    echo "[*] Switching target_api to SECURE=true..."
    export SECURE=true
    docker compose up -d --build target_api
elif [ "${ACTION}" = "vulnerable" ]; then
    echo "[*] Switching target_api to SECURE=false..."
    export SECURE=false
    docker compose up -d --build target_api
elif [ "${ACTION}" = "reset" ]; then
    echo "[*] Resetting target_api state..."
    curl -s -f -X POST http://127.0.0.1:9000/_reset > /dev/null || true
    echo "[+] Target API reset complete."
    exit 0
elif [ "${ACTION}" = "stop" ]; then
    echo "[*] Stopping SentinelAPI stack..."
    docker compose down
    exit 0
else
    echo "[*] Starting full SentinelAPI stack..."
    docker compose up -d
fi

echo "[*] Waiting for target_api (9000)..."
until curl -s -f http://127.0.0.1:9000/health > /dev/null 2>&1; do
    sleep 0.5
done
echo "[+] target_api is healthy."

echo "[*] Resetting target_api state..."
curl -s -f -X POST http://127.0.0.1:9000/_reset > /dev/null || true
echo "[+] target_api reset to clean baseline."

echo "[*] Waiting for scanner backend (8000)..."
until curl -s -f http://127.0.0.1:8000/health > /dev/null 2>&1; do
    sleep 0.5
done
echo "[+] scanner backend is healthy."

echo "[*] Waiting for frontend proxy (8080)..."
until curl -s -f http://127.0.0.1:8080/api/health > /dev/null 2>&1; do
    sleep 0.5
done
echo "[+] frontend is serving and reverse proxying /api/health successfully."
echo "[+] E2E Stack ready."
