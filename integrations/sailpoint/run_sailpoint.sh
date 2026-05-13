#!/usr/bin/env bash
# run_sailpoint.sh — Run the SailPoint ISC → Veza OAA integration
#
# Launches the integration under nohup so that SSH session timeouts or
# disconnections do not kill the process mid-run.  All stdout and stderr
# are captured to a timestamped log file in the shared logs/ directory.
#
# Usage:
#   ./run_sailpoint.sh [extra sailpoint.py flags ...]
#
# Examples:
#   ./run_sailpoint.sh
#   ./run_sailpoint.sh --dry-run --save-json
#   ./run_sailpoint.sh --log-level DEBUG

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS_DIR="$(dirname "${SCRIPT_DIR}")/logs"
PYTHON="${SCRIPT_DIR}/venv/bin/python3"
MAIN="${SCRIPT_DIR}/sailpoint.py"
ENV_FILE="${SCRIPT_DIR}/.env"
PID_FILE="${SCRIPT_DIR}/sailpoint.pid"

GREEN="\033[0;32m"; BLUE="\033[0;34m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; RESET="\033[0m"
info() { echo -e "${BLUE}[INFO]  $*${RESET}"; }
ok()   { echo -e "${GREEN}[OK]    $*${RESET}"; }
warn() { echo -e "${YELLOW}[WARN]  $*${RESET}"; }
die()  { echo -e "${RED}[FATAL] $*${RESET}" >&2; exit 1; }

# ── Pre-flight checks ─────────────────────────────────────────────────────────
[[ ! -f "${PYTHON}" ]]   && die "Virtual environment not found at ${PYTHON}. Run install_sailpoint.sh first."
[[ ! -f "${MAIN}" ]]     && die "sailpoint.py not found at ${MAIN}."
[[ ! -f "${ENV_FILE}" ]] && die ".env file not found at ${ENV_FILE}. Please create it first (see .env.example)."

mkdir -p "${LOGS_DIR}"

# ── Check if already running ──────────────────────────────────────────────────
if [[ -f "${PID_FILE}" ]]; then
    OLD_PID="$(cat "${PID_FILE}")"
    if kill -0 "${OLD_PID}" 2>/dev/null; then
        warn "Integration is already running (PID ${OLD_PID})."
        warn "To stop it:  kill ${OLD_PID}"
        warn "To force-stop:  kill -9 ${OLD_PID}"
        exit 1
    else
        # Stale PID file — clean it up
        rm -f "${PID_FILE}"
    fi
fi

# ── Launch with nohup ─────────────────────────────────────────────────────────
TIMESTAMP="$(date +%d%m%Y-%H%M)"
NOHUP_LOG="${LOGS_DIR}/sailpoint_run_${TIMESTAMP}.log"

info "Starting SailPoint → Veza OAA integration ..."
info "Output log → ${NOHUP_LOG}"

# shellcheck disable=SC2086
nohup "${PYTHON}" -u "${MAIN}" \
    --env-file "${ENV_FILE}" \
    "$@" \
    > "${NOHUP_LOG}" 2>&1 &

PID=$!
echo "${PID}" > "${PID_FILE}"

ok "Integration started — PID ${PID}"
echo ""
echo "  Monitor progress in real time:"
echo "    tail -f ${NOHUP_LOG}"
echo ""
echo "  Check if still running:"
echo "    ps -p ${PID} -o pid,etime,comm"
echo ""
echo "  The process will continue running even if this SSH session disconnects."
echo ""
