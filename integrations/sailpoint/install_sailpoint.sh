#!/usr/bin/env bash
# install_sailpoint.sh — One-command installer for SailPoint ISC → Veza OAA integration
#
# Usage (interactive):
#   curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/YOUR_REPO/main/integrations/sailpoint/install_sailpoint.sh | bash
#
# Usage (non-interactive / CI):
#   SAILPOINT_TENANT=mycompany SAILPOINT_CLIENT_ID=... SAILPOINT_CLIENT_SECRET=... \
#   VEZA_URL=https://myorg.veza.com VEZA_API_KEY=... \
#   bash install_sailpoint.sh --non-interactive

set -uo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/YOUR_ORG/YOUR_REPO"
BRANCH="main"
INTEGRATION_SUBDIR="integrations/sailpoint"
SLUG="sailpoint"
INSTALL_BASE="/opt/VEZA"
SERVICE_DIR="${INSTALL_BASE}/${SLUG}-veza"
SCRIPTS_DIR="${SERVICE_DIR}/scripts"
LOGS_DIR="${SERVICE_DIR}/logs"
MIN_PYTHON_MINOR=9   # Python 3.9+

# ── Flags ─────────────────────────────────────────────────────────────────────
NON_INTERACTIVE=false
OVERWRITE_ENV=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --non-interactive) NON_INTERACTIVE=true ;;
        --overwrite-env)   OVERWRITE_ENV=true ;;
        --install-dir)     INSTALL_BASE="$2"; SERVICE_DIR="${INSTALL_BASE}/${SLUG}-veza"; SCRIPTS_DIR="${SERVICE_DIR}/scripts"; LOGS_DIR="${SERVICE_DIR}/logs"; shift ;;
        --repo-url)        REPO_URL="$2"; shift ;;
        --branch)          BRANCH="$2"; shift ;;
        *) warn "Unknown flag: $1" ;;
    esac
    shift 2>/dev/null || true
done

# ── Colors and helpers ────────────────────────────────────────────────────────
GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; RESET="\033[0m"
die()  { echo -e "${RED}[FATAL] $*${RESET}" >&2; exit 1; }
info() { echo -e "${BLUE}[INFO]  $*${RESET}"; }
warn() { echo -e "${YELLOW}[WARN]  $*${RESET}"; }
ok()   { echo -e "${GREEN}[OK]    $*${RESET}"; }

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   SailPoint ISC → Veza OAA  —  Installer                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Detect OS ─────────────────────────────────────────────────────────────────
OS_ID=""
if [[ -f /etc/os-release ]]; then
    OS_ID="$(. /etc/os-release && echo "${ID:-}")"
fi

PKG_MGR=""
if command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
elif command -v apt-get &>/dev/null; then
    PKG_MGR="apt-get"
fi

[[ -z "${PKG_MGR}" ]] && die "No supported package manager found (dnf/yum/apt-get)."
info "Package manager: ${PKG_MGR}  |  OS ID: ${OS_ID:-unknown}"

# ── Install system packages (one at a time with pre-check) ────────────────────
_install_pkg() {
    local pkg="$1"
    info "Installing system package: ${pkg}"
    case "${PKG_MGR}" in
        dnf|yum) "${PKG_MGR}" install -y "${pkg}" >/dev/null ;;
        apt-get) apt-get install -y "${pkg}" >/dev/null ;;
    esac
}

# git
command -v git &>/dev/null || _install_pkg git

# curl — skip on Amazon Linux when curl-minimal is already present
if ! command -v curl &>/dev/null; then
    if [[ "${OS_ID}" == "amzn" ]]; then
        warn "Skipping curl install on Amazon Linux (curl-minimal conflict). curl already satisfies requirements."
    else
        _install_pkg curl
    fi
fi

# python3
command -v python3 &>/dev/null || _install_pkg python3

# pip
python3 -m pip --version &>/dev/null || _install_pkg python3-pip

# python3-venv — amazon linux 2023 / RHEL 9+ have venv built-in
if ! python3 -m venv --help &>/dev/null; then
    case "${PKG_MGR}" in
        dnf|yum) _install_pkg python3-virtualenv ;;
        apt-get) _install_pkg python3-venv ;;
    esac
fi

ok "System dependencies satisfied"

# ── Check Python version ──────────────────────────────────────────────────────
PY_MINOR="$(python3 -c 'import sys; print(sys.version_info.minor)')"
PY_MAJOR="$(python3 -c 'import sys; print(sys.version_info.major)')"
if [[ "${PY_MAJOR}" -lt 3 ]] || [[ "${PY_MAJOR}" -eq 3 && "${PY_MINOR}" -lt ${MIN_PYTHON_MINOR} ]]; then
    die "Python 3.${MIN_PYTHON_MINOR}+ is required. Found: $(python3 --version)"
fi
ok "Python version: $(python3 --version)"

# ── Check for sudo / root ─────────────────────────────────────────────────────
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    SUDO="sudo"
else
    SUDO=""
fi

# ── Create directory layout ───────────────────────────────────────────────────
info "Creating install directories under ${SERVICE_DIR} ..."
${SUDO} mkdir -p "${SCRIPTS_DIR}" "${LOGS_DIR}"
${SUDO} chmod 755 "${SERVICE_DIR}" "${LOGS_DIR}"
${SUDO} chmod 700 "${SCRIPTS_DIR}"
ok "Directories created"

# ── Clone repository and copy integration files ───────────────────────────────
info "Cloning integration files from ${REPO_URL} (branch: ${BRANCH}) ..."
tmp_dir="$(mktemp -d)"
GIT_TERMINAL_PROMPT=0 git clone \
    --branch "${BRANCH}" \
    --depth 1 \
    --single-branch \
    "${REPO_URL}" "${tmp_dir}" || die "git clone failed. Check REPO_URL and network connectivity."

if [[ ! -d "${tmp_dir}/${INTEGRATION_SUBDIR}" ]]; then
    die "Integration sub-directory '${INTEGRATION_SUBDIR}' not found in cloned repo."
fi

${SUDO} cp -f "${tmp_dir}/${INTEGRATION_SUBDIR}/"*.py      "${SCRIPTS_DIR}/"
${SUDO} cp -f "${tmp_dir}/${INTEGRATION_SUBDIR}/requirements.txt" "${SCRIPTS_DIR}/"
rm -rf "${tmp_dir}"
ok "Integration files installed to ${SCRIPTS_DIR}"

# ── Create virtual environment and install dependencies ───────────────────────
info "Creating Python virtual environment ..."
python3 -m venv "${SCRIPTS_DIR}/venv"
ok "Virtual environment created"

info "Installing Python dependencies ..."
"${SCRIPTS_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${SCRIPTS_DIR}/venv/bin/pip" install --quiet -r "${SCRIPTS_DIR}/requirements.txt"
ok "Python dependencies installed"

# ── Generate .env file ────────────────────────────────────────────────────────
ENV_FILE="${SCRIPTS_DIR}/.env"

if [[ -f "${ENV_FILE}" ]] && [[ "${OVERWRITE_ENV}" == "false" ]]; then
    warn ".env file already exists at ${ENV_FILE}. Skipping generation (use --overwrite-env to replace)."
else
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        # Non-interactive: read values from environment variables
        SP_TENANT="${SAILPOINT_TENANT:-}"
        SP_CLIENT_ID="${SAILPOINT_CLIENT_ID:-}"
        SP_CLIENT_SECRET="${SAILPOINT_CLIENT_SECRET:-}"
        VEZA_URL_VAL="${VEZA_URL:-}"
        VEZA_KEY_VAL="${VEZA_API_KEY:-}"

        [[ -z "${SP_TENANT}" ]]       && die "SAILPOINT_TENANT env var is required in non-interactive mode"
        [[ -z "${SP_CLIENT_ID}" ]]    && die "SAILPOINT_CLIENT_ID env var is required in non-interactive mode"
        [[ -z "${SP_CLIENT_SECRET}" ]] && die "SAILPOINT_CLIENT_SECRET env var is required in non-interactive mode"
        [[ -z "${VEZA_URL_VAL}" ]]    && die "VEZA_URL env var is required in non-interactive mode"
        [[ -z "${VEZA_KEY_VAL}" ]]    && die "VEZA_API_KEY env var is required in non-interactive mode"
    else
        # Interactive: prompt the user — must use /dev/tty when piped via curl | bash
        echo ""
        info "Please enter your SailPoint and Veza credentials."
        echo ""

        IFS= read -r -p "SailPoint tenant name (e.g. mycompany): " SP_TENANT </dev/tty
        IFS= read -r -p "SailPoint OAuth2 Client ID: " SP_CLIENT_ID </dev/tty
        IFS= read -r -s -p "SailPoint OAuth2 Client Secret: " SP_CLIENT_SECRET </dev/tty; echo >/dev/tty
        IFS= read -r -p "Veza URL (e.g. https://myorg.veza.com): " VEZA_URL_VAL </dev/tty
        IFS= read -r -s -p "Veza API Key: " VEZA_KEY_VAL </dev/tty; echo >/dev/tty
    fi

    info "Writing .env file ..."
    ${SUDO} tee "${ENV_FILE}" >/dev/null <<EOF
# SailPoint ISC → Veza OAA Integration — generated by installer
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

# SailPoint Configuration
SAILPOINT_TENANT=${SP_TENANT}
SAILPOINT_CLIENT_ID=${SP_CLIENT_ID}
SAILPOINT_CLIENT_SECRET=${SP_CLIENT_SECRET}

# Veza Configuration
VEZA_URL=${VEZA_URL_VAL}
VEZA_API_KEY=${VEZA_KEY_VAL}

# OAA Provider Settings (optional)
# PROVIDER_NAME=SailPoint
# DATASOURCE_NAME=${SP_TENANT}
EOF
    ${SUDO} chmod 600 "${ENV_FILE}"
    ok ".env created with permissions 600"
fi

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Installation Complete                                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
ok "Install path : ${SERVICE_DIR}"
ok "Script       : ${SCRIPTS_DIR}/sailpoint.py"
ok "Config       : ${ENV_FILE}"
ok "Logs         : ${LOGS_DIR}/"
echo ""
info "Next steps:"
echo "  1. Review and verify ${ENV_FILE}"
echo "  2. Run a dry-run to validate connectivity:"
echo ""
echo "     cd ${SCRIPTS_DIR}"
echo "     ./venv/bin/python3 sailpoint.py --env-file .env --dry-run --save-json"
echo ""
echo "  3. Once satisfied, run the full integration:"
echo ""
echo "     ./venv/bin/python3 sailpoint.py --env-file .env"
echo ""
info "To schedule with cron (daily at 02:00):"
echo "  sudo tee /etc/cron.d/sailpoint-veza >/dev/null <<'CRON'"
echo "  0 2 * * * ${SLUG}-veza cd ${SCRIPTS_DIR} && ./venv/bin/python3 sailpoint.py --env-file .env >> ${LOGS_DIR}/cron.log 2>&1"
echo "  CRON"
