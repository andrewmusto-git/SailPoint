#!/usr/bin/env bash
# preflight_sailpoint.sh — Pre-deployment validation for SailPoint ISC → Veza OAA integration
#
# Derived from sailpoint.py — validates every prerequisite before running the integration.
#
# Usage:
#   ./preflight_sailpoint.sh          # interactive numbered menu
#   ./preflight_sailpoint.sh --all    # run all checks non-interactively; exit 0 = pass, 1 = fail

set -uo pipefail

# ── Color output ──────────────────────────────────────────────────────────────
GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; RESET="\033[0m"
pass()  { echo -e "${GREEN}  ✓ $*${RESET}";   TESTS_PASSED=$((TESTS_PASSED + 1)); }
fail()  { echo -e "${RED}  ✗ $*${RESET}" >&2; TESTS_FAILED=$((TESTS_FAILED + 1)); }
warn()  { echo -e "${YELLOW}  ⚠ $*${RESET}";   TESTS_WARNING=$((TESTS_WARNING + 1)); }
info()  { echo -e "${BLUE}  ℹ $*${RESET}"; }

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNING=0

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_SCRIPT="${SCRIPT_DIR}/sailpoint.py"
VENV_PYTHON="${SCRIPT_DIR}/venv/bin/python3"
ENV_FILE="${SCRIPT_DIR}/.env"
LOG_FILE="${SCRIPT_DIR}/preflight_$(date +%Y%m%d_%H%M%S).log"

# Redirect all output to log in addition to terminal
exec > >(tee -a "${LOG_FILE}") 2>&1

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   SailPoint ISC → Veza OAA  —  Pre-flight Validation     ║"
echo "╚══════════════════════════════════════════════════════════╝"
info "Log file: ${LOG_FILE}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# CHECK FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

check_system_requirements() {
    echo "──────────────────────────────────────────"
    echo "  [1] System Requirements"
    echo "──────────────────────────────────────────"

    # Python 3.9+
    if command -v python3 &>/dev/null; then
        PY_VER="$(python3 --version 2>&1)"
        PY_MINOR="$(python3 -c 'import sys; print(sys.version_info.minor)')"
        PY_MAJOR="$(python3 -c 'import sys; print(sys.version_info.major)')"
        if [[ "${PY_MAJOR}" -ge 3 && "${PY_MINOR}" -ge 9 ]]; then
            pass "Python version: ${PY_VER}"
        else
            fail "Python 3.9+ required. Found: ${PY_VER}"
        fi
    else
        fail "python3 not found"
    fi

    # pip3
    if python3 -m pip --version &>/dev/null; then
        pass "pip3: $(python3 -m pip --version | awk '{print $2}')"
    else
        fail "pip3 not available (python3 -m pip)"
    fi

    # curl
    if command -v curl &>/dev/null; then
        pass "curl: $(curl --version | head -1)"
    else
        warn "curl not found — optional but useful for connectivity testing"
    fi

    # jq
    if command -v jq &>/dev/null; then
        pass "jq: $(jq --version)"
    else
        warn "jq not found — optional but useful for payload inspection"
    fi
}

check_python_dependencies() {
    echo ""
    echo "──────────────────────────────────────────"
    echo "  [2] Python Dependencies"
    echo "──────────────────────────────────────────"

    # Prefer venv python if available
    PY="${VENV_PYTHON}"
    if [[ ! -x "${PY}" ]]; then
        warn "venv not found at ${VENV_PYTHON}; using system python3"
        PY="python3"
    else
        pass "Virtual environment found: ${SCRIPT_DIR}/venv"
    fi

    for pkg in oaaclient dotenv requests urllib3; do
        # Map package name to importable module name
        case "${pkg}" in
            oaaclient) mod="oaaclient" ;;
            dotenv)    mod="dotenv" ;;
            *)         mod="${pkg}" ;;
        esac
        if "${PY}" -c "import ${mod}" 2>/dev/null; then
            ver="$("${PY}" -c "import importlib.metadata; print(importlib.metadata.version('${pkg}'))" 2>/dev/null || echo "unknown")"
            pass "${pkg}: ${ver}"
        else
            fail "Python package '${pkg}' is not installed. Run: ${PY} -m pip install -r requirements.txt"
        fi
    done
}

check_configuration() {
    echo ""
    echo "──────────────────────────────────────────"
    echo "  [3] Configuration (.env)"
    echo "──────────────────────────────────────────"

    if [[ ! -f "${ENV_FILE}" ]]; then
        fail ".env file not found at ${ENV_FILE}"
        info "Copy .env.example to .env and fill in your credentials"
        return
    fi
    pass ".env file exists: ${ENV_FILE}"

    # Check permissions (should be 600)
    perms="$(stat -c "%a" "${ENV_FILE}" 2>/dev/null || stat -f "%Lp" "${ENV_FILE}" 2>/dev/null || echo "unknown")"
    if [[ "${perms}" == "600" ]]; then
        pass ".env permissions: 600"
    else
        warn ".env permissions are ${perms} (recommend 600): chmod 600 ${ENV_FILE}"
    fi

    # Source and validate required env vars
    # shellcheck disable=SC1090
    set -a; source "${ENV_FILE}"; set +a

    _check_var() {
        local var_name="$1"
        local is_secret="${2:-false}"
        local val="${!var_name:-}"
        if [[ -z "${val}" ]]; then
            fail "${var_name} is not set in .env"
        elif echo "${val}" | grep -qiE '^your_|^your-'; then
            fail "${var_name} still contains a placeholder value"
        else
            if [[ "${is_secret}" == "true" ]]; then
                masked="$(echo "${val}" | head -c 6)****"
                pass "${var_name}: ${masked}"
            else
                pass "${var_name}: ${val}"
            fi
        fi
    }

    _check_var "SAILPOINT_TENANT"
    _check_var "SAILPOINT_CLIENT_ID"
    _check_var "SAILPOINT_CLIENT_SECRET" true
    _check_var "VEZA_URL"
    _check_var "VEZA_API_KEY" true
}

check_network_connectivity() {
    echo ""
    echo "──────────────────────────────────────────"
    echo "  [4] Network Connectivity"
    echo "──────────────────────────────────────────"

    # shellcheck disable=SC1090
    [[ -f "${ENV_FILE}" ]] && { set -a; source "${ENV_FILE}"; set +a; }

    TENANT="${SAILPOINT_TENANT:-}"
    SP_BASE_URL="${SAILPOINT_URL:-}"
    if [[ -z "${SP_BASE_URL}" && -n "${TENANT}" ]]; then
        SP_BASE_URL="https://${TENANT}.api.identitynow.com"
    fi

    VEZA_HOST="${VEZA_URL:-}"

    if [[ -n "${SP_BASE_URL}" ]]; then
        SP_HOST="$(echo "${SP_BASE_URL}" | sed 's|https\?://||' | cut -d/ -f1)"
        if command -v curl &>/dev/null; then
            start_time="$(date +%s%N)"
            http_code="$(curl -o /dev/null -s -w "%{http_code}" --max-time 10 "${SP_BASE_URL}/v3/access-profiles?limit=1" -H "Accept: application/json" 2>/dev/null || echo "000")"
            end_time="$(date +%s%N)"
            latency_ms=$(( (end_time - start_time) / 1000000 ))
            if [[ "${http_code}" =~ ^(200|401|403)$ ]]; then
                pass "SailPoint API reachable (${SP_HOST}) — HTTP ${http_code} — ${latency_ms}ms"
            else
                fail "SailPoint API not reachable (${SP_HOST}) — HTTP ${http_code}"
            fi
        else
            warn "curl not available; skipping SailPoint HTTP reachability check"
        fi
    else
        fail "Cannot check SailPoint connectivity — SAILPOINT_TENANT or SAILPOINT_URL is not set"
    fi

    if [[ -n "${VEZA_HOST}" ]]; then
        VEZA_DOMAIN="$(echo "${VEZA_HOST}" | sed 's|https\?://||' | cut -d/ -f1)"
        if command -v curl &>/dev/null; then
            http_code="$(curl -o /dev/null -s -w "%{http_code}" --max-time 10 "${VEZA_HOST}" 2>/dev/null || echo "000")"
            if [[ "${http_code}" =~ ^(200|301|302|401|403)$ ]]; then
                pass "Veza URL reachable (${VEZA_DOMAIN}) — HTTP ${http_code}"
            else
                fail "Veza URL not reachable (${VEZA_DOMAIN}) — HTTP ${http_code}"
            fi
        else
            warn "curl not available; skipping Veza HTTPS reachability check"
        fi
    else
        fail "Cannot check Veza connectivity — VEZA_URL is not set"
    fi
}

check_api_authentication() {
    echo ""
    echo "──────────────────────────────────────────"
    echo "  [5] API Authentication"
    echo "──────────────────────────────────────────"

    # shellcheck disable=SC1090
    [[ -f "${ENV_FILE}" ]] && { set -a; source "${ENV_FILE}"; set +a; }

    TENANT="${SAILPOINT_TENANT:-}"
    SP_BASE="${SAILPOINT_URL:-}"
    [[ -z "${SP_BASE}" && -n "${TENANT}" ]] && SP_BASE="https://${TENANT}.api.identitynow.com"
    CLIENT_ID="${SAILPOINT_CLIENT_ID:-}"
    CLIENT_SECRET="${SAILPOINT_CLIENT_SECRET:-}"

    if [[ -z "${SP_BASE}" || -z "${CLIENT_ID}" || -z "${CLIENT_SECRET}" ]]; then
        fail "SailPoint credentials not set — skipping auth test"
        return
    fi

    if ! command -v curl &>/dev/null; then
        warn "curl not available; skipping SailPoint auth test"
    else
        info "Testing SailPoint OAuth2 token endpoint ..."
        TOKEN_RESP="$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time 15 \
            -X POST "${SP_BASE}/oauth/token" \
            -d "grant_type=client_credentials" \
            -d "client_id=${CLIENT_ID}" \
            -d "client_secret=${CLIENT_SECRET}" 2>/dev/null || echo "000")"
        if [[ "${TOKEN_RESP}" == "200" ]]; then
            pass "SailPoint OAuth2 token endpoint returned HTTP 200"
        else
            fail "SailPoint OAuth2 token request failed — HTTP ${TOKEN_RESP}"
            info "Check CLIENT_ID, CLIENT_SECRET, and that your PAT has CLIENT_CREDENTIALS grant type"
        fi
    fi

    # Veza API key test
    VEZA_HOST="${VEZA_URL:-}"
    VEZA_KEY="${VEZA_API_KEY:-}"
    if [[ -z "${VEZA_HOST}" || -z "${VEZA_KEY}" ]]; then
        fail "Veza credentials not set — skipping Veza auth test"
        return
    fi
    if ! command -v curl &>/dev/null; then
        warn "curl not available; skipping Veza auth test"
    else
        info "Testing Veza API key ..."
        VEZA_RESP="$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time 15 \
            -H "Authorization: Bearer ${VEZA_KEY}" \
            "${VEZA_HOST}/api/v1/providers" 2>/dev/null || echo "000")"
        if [[ "${VEZA_RESP}" == "200" ]]; then
            pass "Veza API key valid — /api/v1/providers returned HTTP 200"
        elif [[ "${VEZA_RESP}" == "401" ]]; then
            fail "Veza API key is invalid or expired — HTTP 401"
        elif [[ "${VEZA_RESP}" == "403" ]]; then
            fail "Veza API key lacks required permissions — HTTP 403"
        else
            fail "Veza API connectivity issue — HTTP ${VEZA_RESP}"
        fi
    fi
}

check_veza_endpoint_access() {
    echo ""
    echo "──────────────────────────────────────────"
    echo "  [6] Veza Endpoint Access"
    echo "──────────────────────────────────────────"

    # shellcheck disable=SC1090
    [[ -f "${ENV_FILE}" ]] && { set -a; source "${ENV_FILE}"; set +a; }

    VEZA_HOST="${VEZA_URL:-}"
    VEZA_KEY="${VEZA_API_KEY:-}"

    if [[ -z "${VEZA_HOST}" || -z "${VEZA_KEY}" ]]; then
        fail "VEZA_URL or VEZA_API_KEY not set — skipping"
        return
    fi

    if ! command -v curl &>/dev/null; then
        warn "curl not available; skipping Veza endpoint access test"
        return
    fi

    info "Testing Veza Query API read access ..."
    QUERY_RESP="$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 15 \
        -X POST "${VEZA_HOST}/api/v1/query" \
        -H "Authorization: Bearer ${VEZA_KEY}" \
        -H "Content-Type: application/json" \
        -d '{"node_type":"EffectivePermission","limit":1}' 2>/dev/null || echo "000")"

    if [[ "${QUERY_RESP}" =~ ^(200|201)$ ]]; then
        pass "Veza Query API access confirmed — HTTP ${QUERY_RESP}"
    elif [[ "${QUERY_RESP}" == "403" ]]; then
        fail "Veza API key does not have Query API read permissions — HTTP 403"
    else
        warn "Veza Query API returned HTTP ${QUERY_RESP} — may be acceptable depending on permissions"
    fi
}

check_deployment_structure() {
    echo ""
    echo "──────────────────────────────────────────"
    echo "  [7] Deployment Structure"
    echo "──────────────────────────────────────────"

    info "Running as user: $(id -un) ($(id -u))"

    if [[ -f "${PY_SCRIPT}" && -r "${PY_SCRIPT}" ]]; then
        pass "sailpoint.py exists and is readable"
    else
        fail "sailpoint.py not found or not readable at ${PY_SCRIPT}"
    fi

    # Check logs/ directory
    LOG_DIR="${SCRIPT_DIR}/logs"
    if [[ -d "${LOG_DIR}" ]]; then
        if [[ -w "${LOG_DIR}" ]]; then
            pass "logs/ directory is writable"
        else
            fail "logs/ directory exists but is not writable: ${LOG_DIR}"
        fi
    else
        if mkdir -p "${LOG_DIR}" 2>/dev/null; then
            pass "logs/ directory created: ${LOG_DIR}"
        else
            fail "Could not create logs/ directory: ${LOG_DIR} — check permissions"
        fi
    fi

    # Check --help works
    PY="${VENV_PYTHON}"
    [[ ! -x "${PY}" ]] && PY="python3"
    if "${PY}" "${PY_SCRIPT}" --help &>/dev/null; then
        pass "sailpoint.py --help executes without errors"
    else
        fail "sailpoint.py --help failed — check Python dependencies"
    fi
}

print_summary() {
    echo ""
    echo "══════════════════════════════════════════"
    echo "  Summary"
    echo "══════════════════════════════════════════"
    echo -e "  ${GREEN}Passed : ${TESTS_PASSED}${RESET}"
    echo -e "  ${RED}Failed : ${TESTS_FAILED}${RESET}"
    echo -e "  ${YELLOW}Warnings: ${TESTS_WARNING}${RESET}"
    echo ""
    info "Full log: ${LOG_FILE}"
    echo ""
    if [[ ${TESTS_FAILED} -gt 0 ]]; then
        echo -e "${RED}  Pre-flight FAILED. Resolve the above failures before deploying.${RESET}"
        return 1
    else
        echo -e "${GREEN}  Pre-flight PASSED. Ready to deploy.${RESET}"
        return 0
    fi
}

# ── Utilities ─────────────────────────────────────────────────────────────────
show_config() {
    echo ""
    echo "──────────────────────────────────────────"
    echo "  Current Configuration"
    echo "──────────────────────────────────────────"
    if [[ -f "${ENV_FILE}" ]]; then
        # shellcheck disable=SC1090
        set -a; source "${ENV_FILE}"; set +a
        info "SAILPOINT_TENANT    : ${SAILPOINT_TENANT:-<not set>}"
        info "SAILPOINT_URL       : ${SAILPOINT_URL:-<not set>}"
        info "SAILPOINT_CLIENT_ID : ${SAILPOINT_CLIENT_ID:-<not set>}"
        info "SAILPOINT_CLIENT_SECRET : ****"
        info "VEZA_URL            : ${VEZA_URL:-<not set>}"
        info "VEZA_API_KEY        : ****"
        info "PROVIDER_NAME       : ${PROVIDER_NAME:-SailPoint (default)}"
        info "DATASOURCE_NAME     : ${DATASOURCE_NAME:-<tenant name> (default)}"
    else
        warn "No .env file found at ${ENV_FILE}"
    fi
}

generate_env_template() {
    TARGET="${SCRIPT_DIR}/.env.example.generated"
    cat >"${TARGET}" <<'EOF'
# SailPoint ISC → Veza OAA Integration — generated .env template
SAILPOINT_TENANT=your-tenant-name
SAILPOINT_CLIENT_ID=your_client_id_here
SAILPOINT_CLIENT_SECRET=your_client_secret_here
VEZA_URL=https://your-org.veza.com
VEZA_API_KEY=your_veza_api_key_here
# PROVIDER_NAME=SailPoint
# DATASOURCE_NAME=sailpoint-prod
EOF
    pass "Generated .env template → ${TARGET}"
}

install_dependencies() {
    PY="${VENV_PYTHON}"
    [[ ! -x "${PY}" ]] && PY="python3"
    info "Installing dependencies via: ${PY} -m pip install -r requirements.txt"
    "${PY}" -m pip install -r "${SCRIPT_DIR}/requirements.txt"
    pass "Dependencies installed"
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

if [[ "${1:-}" == "--all" ]]; then
    # Non-interactive: run all checks
    check_system_requirements
    check_python_dependencies
    check_configuration
    check_network_connectivity
    check_api_authentication
    check_veza_endpoint_access
    check_deployment_structure
    print_summary
    exit $?
fi

# Interactive menu
while true; do
    echo ""
    echo "  Select a check to run:"
    echo "  1) System requirements (Python, pip, curl, jq)"
    echo "  2) Python dependencies (oaaclient, requests, dotenv, urllib3)"
    echo "  3) Configuration (.env file, required variables)"
    echo "  4) Network connectivity (SailPoint API + Veza HTTPS)"
    echo "  5) API authentication (SailPoint OAuth2 + Veza API key)"
    echo "  6) Veza endpoint access (Query API read permissions)"
    echo "  7) Deployment structure (script exists, logs/ writable)"
    echo "  8) Run ALL checks"
    echo "  ─────────────────────────────────────────────────"
    echo "  9) Show current configuration"
    echo " 10) Generate .env template"
    echo " 11) Install Python dependencies"
    echo "  0) Exit"
    echo ""
    IFS= read -r -p "Choice: " choice </dev/tty
    case "${choice}" in
        1) check_system_requirements ;;
        2) check_python_dependencies ;;
        3) check_configuration ;;
        4) check_network_connectivity ;;
        5) check_api_authentication ;;
        6) check_veza_endpoint_access ;;
        7) check_deployment_structure ;;
        8)
            TESTS_PASSED=0; TESTS_FAILED=0; TESTS_WARNING=0
            check_system_requirements
            check_python_dependencies
            check_configuration
            check_network_connectivity
            check_api_authentication
            check_veza_endpoint_access
            check_deployment_structure
            print_summary
            ;;
        9)  show_config ;;
        10) generate_env_template ;;
        11) install_dependencies ;;
        0)  info "Exiting."; exit 0 ;;
        *)  warn "Invalid choice: ${choice}" ;;
    esac
done
