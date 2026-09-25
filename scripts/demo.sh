#!/usr/bin/env bash
# ==============================================================================
# SentinelAPI Live Hackathon Demo Script
#
# Idempotent orchestration script for running a complete live demonstration:
# 1. Spins up Docker Compose services (scanner, target_api, frontend)
# 2. Waits for health check readiness
# 3. Resets sandbox database state
# 4. Executes real-time scan against the vulnerable target (displaying findings)
# 5. Displays the live Dashboard URL for jury inspection
# 6. Flips SECURE=true, resets state, and re-scans (demonstrating clean pass)
# 7. Restores vulnerable mode and resets data for live UI click-through demo
# ==============================================================================

set -euo pipefail

# Visual Banner Formatting
BOLD="\033[1m"
GREEN="\033[32m"
BLUE="\033[34m"
CYAN="\033[36m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

function banner() {
    echo -e "\n${BOLD}${CYAN}================================================================================${RESET}"
    echo -e "${BOLD}${CYAN}  $1${RESET}"
    echo -e "${BOLD}${CYAN}================================================================================${RESET}\n"
}

function subhead() {
    echo -e "${BOLD}${YELLOW}>>> $1${RESET}"
}

# Ensure script runs from project root
cd "$(dirname "$0")/.."

banner "SENTINELAPI // HACKATHON LIVE DEMO RUNNER"
echo -e "Auditing authorization, object-level boundaries (BOLA), and privilege escalation (BFLA)\n"

# Step 1: Detect AI configuration & bring up containers
subhead "[1/6] Launching Docker services (scanner, target_api, frontend)..."

# Ensure .env exists
if [ ! -f .env ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
fi

# Detect whether real LLM key is set
AI_ARGS=""
if grep -qE '^LLM_API_KEY=.{10,}' .env 2>/dev/null && ! grep -q 'your_groq_api_key_here' .env; then
    echo -e "${GREEN}✓ Real LLM key detected in .env. AI Analyst features enabled.${RESET}"
    AI_ARGS="--ai"
else
    echo -e "${YELLOW}ℹ AI key not configured or set to placeholder. Scanner running in autonomous core mode.${RESET}"
fi

docker compose up -d --build scanner target_api frontend

# Step 2: Health check polling
subhead "[2/6] Waiting for service health checks..."
MAX_TRIES=30
for i in $(seq 1 $MAX_TRIES); do
    if curl -s -f http://127.0.0.1:8000/health >/dev/null 2>&1 && \
       curl -s -f http://127.0.0.1:9000/health >/dev/null 2>&1 && \
       curl -s -f http://127.0.0.1:8080/ >/dev/null 2>&1; then
        echo -e "${GREEN}✓ All services are healthy (Scanner: 8000, Target API: 9000, Web UI: 8080)${RESET}"
        break
    fi
    if [ "$i" -eq "$MAX_TRIES" ]; then
        echo -e "${RED}❌ Timed out waiting for services to start.${RESET}"
        docker compose logs
        exit 1
    fi
    echo "Waiting for services... ($i/$MAX_TRIES)"
    sleep 2
done

# Step 3: Reset target database state
subhead "[3/6] Resetting target sandbox data to clean seed baseline..."
curl -s -X POST http://127.0.0.1:9000/_reset >/dev/null
echo -e "${GREEN}✓ Target API database reset (orders, users, inventory restored)${RESET}"

# Step 4: Run vulnerable scan
banner "[4/6] EXECUTING SCAN AGAINST VULNERABLE TARGET (SECURE=false)"
echo -e "${BLUE}Scanning ShopSentinel Retail Store (http://target_api:9000)...${RESET}\n"

docker compose exec -T scanner python -m app.cli scan \
    --spec http://target_api:9000/openapi.json \
    --base-url http://target_api:9000 \
    --identity userA,user,userA,passA123 \
    --identity userB,user,userB,passB123 \
    --identity admin,admin,admin,admin123 \
    --budget 50 \
    --json-out /tmp/demo_vuln_findings.json \
    $AI_ARGS

echo -e "\n${BOLD}${GREEN}✓ Vulnerability scan complete! High & Critical authorization flaws detected.${RESET}"

# Step 5: Test quality gate & flip to secure mode
banner "[5/6] TESTING SECURE HARDENING MODE (SECURE=true)"
subhead "Re-deploying Target API with SECURE=true (Zero-Trust authorization barriers active)..."
SECURE=true docker compose up -d target_api
sleep 3
curl -s -X POST http://127.0.0.1:9000/_reset >/dev/null

echo -e "\n${BLUE}Re-running scan against hardened target...${RESET}\n"
docker compose exec -T scanner python -m app.cli scan \
    --spec http://target_api:9000/openapi.json \
    --base-url http://target_api:9000 \
    --identity userA,user,userA,passA123 \
    --identity userB,user,userB,passB123 \
    --identity admin,admin,admin,admin123 \
    --budget 50 \
    --json-out /tmp/demo_secure_findings.json \
    $AI_ARGS

echo -e "\n${BOLD}${GREEN}✓ Hardened scan complete: 0 authorization vulnerabilities detected (Clean Pass).${RESET}"

# Step 6: Restore vulnerable environment for live UI click-through
banner "[6/6] RESTORING DEMO ENVIRONMENT FOR LIVE DASHBOARD INSPECTION"
subhead "Resetting Target API to vulnerable mode so UI demo is ready..."
SECURE=false docker compose up -d target_api
sleep 2
curl -s -X POST http://127.0.0.1:9000/_reset >/dev/null

echo -e "${GREEN}✓ Target API restored to vulnerable mode with fresh seed data.${RESET}"
echo -e "\n${BOLD}${GREEN}================================================================================${RESET}"
echo -e "${BOLD}${GREEN}  DEMO READY! ACCESS THE SENTINELAPI DASHBOARD AT:${RESET}"
echo -e "${BOLD}${CYAN}  👉  http://localhost:8080/scans/new${RESET}"
echo -e "${BOLD}${GREEN}================================================================================${RESET}\n"
echo -e "Suggested next steps for live demonstration:"
echo -e "1. Select any sample target radio button (ShopSentinel :9000, MedPulse :9001, ApexBank :9002)"
echo -e "2. Check authorization confirmation and click 'Launch Security Audit'"
echo -e "3. Watch real-time execution telemetry on the live scan stepper"
echo -e "4. Inspect CRITICAL findings in the differential inspector and test the generated cURL PoC\n"
