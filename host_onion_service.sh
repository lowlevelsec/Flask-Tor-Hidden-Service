#!/usr/bin/env bash
# Install and run Flask Onion Vault behind a Tor v3 Onion Service.
# Supported: Debian/Ubuntu with systemd and amd64/arm64.
# Run from the project root: sudo bash ./host_onion_service.sh

set -Eeuo pipefail
IFS=$'\n\t'

readonly APP_NAME="flask-onion-vault"
readonly APP_USER="flask-onion-vault"
readonly APP_GROUP="flask-onion-vault"
readonly APP_DIR="/opt/${APP_NAME}"
readonly STATE_DIR="/var/lib/${APP_NAME}"
readonly CONFIG_DIR="/etc/${APP_NAME}"
readonly ENV_FILE="${CONFIG_DIR}/${APP_NAME}.env"
readonly SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
readonly TOR_HS_DIR="/var/lib/tor/${APP_NAME}"
readonly TORRC="/etc/tor/torrc"
readonly TOR_REPO_KEY_FINGERPRINT="A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89"
readonly TOR_REPO_KEY_URL="https://deb.torproject.org/torproject.org/${TOR_REPO_KEY_FINGERPRINT}.asc"
readonly TOR_REPO_KEYRING="/usr/share/keyrings/deb.torproject.org-keyring.gpg"
readonly TOR_REPO_FILE="/etc/apt/sources.list.d/tor.sources"
readonly TOR_BACKEND="127.0.0.1:5000"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
TOR_UNIT=""

log() {
    printf '\n\033[1;36m[+]\033[0m %s\n' "$*"
}

warn() {
    printf '\n\033[1;33m[!]\033[0m %s\n' "$*" >&2
}

fatal() {
    printf '\n\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2
    exit 1
}

on_error() {
    local exit_code=$?
    printf '\n\033[1;31m[ERROR]\033[0m Failed on line %s (exit code %s).\n' "${BASH_LINENO[0]:-unknown}" "$exit_code" >&2
    if [[ -n "${TOR_UNIT}" ]] && command -v journalctl >/dev/null 2>&1; then
        warn "Recent Tor logs (${TOR_UNIT}):"
        journalctl -u "$TOR_UNIT" -n 30 --no-pager 2>/dev/null || true
    fi
    exit "$exit_code"
}
trap on_error ERR

require_root() {
    [[ "${EUID}" -eq 0 ]] || fatal "Run as root: sudo bash ./host_onion_service.sh"
}

check_platform() {
    [[ -r /etc/os-release ]] || fatal "Cannot identify the operating system (/etc/os-release missing)."
    # shellcheck disable=SC1091
    source /etc/os-release

    case "${ID:-}" in
        debian|ubuntu) ;;
        *) fatal "Unsupported distribution: ${ID:-unknown}. This installer supports Debian and Ubuntu only." ;;
    esac

    command -v apt-get >/dev/null 2>&1 || fatal "apt-get is required."
    command -v systemctl >/dev/null 2>&1 || fatal "systemd/systemctl is required."

    local architecture
    architecture="$(dpkg --print-architecture)"
    case "$architecture" in
        amd64|arm64) ;;
        *) fatal "Tor Project's Debian repository supports amd64 and arm64 only; detected: ${architecture}. Install Tor manually for this architecture." ;;
    esac

    [[ -n "${VERSION_CODENAME:-}" ]] || fatal "Could not determine distribution codename from /etc/os-release."
}

install_os_dependencies() {
    log "Installing OS packages and the official Tor Project APT repository"
    export DEBIAN_FRONTEND=noninteractive

    apt-get update
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        apt-transport-https

    if [[ ! -e "$TOR_REPO_KEYRING" ]]; then
        local key_tmp fingerprint
        key_tmp="$(mktemp)"
        curl --fail --silent --show-error --location "$TOR_REPO_KEY_URL" --output "$key_tmp"

        fingerprint="$(gpg --show-keys --with-colons "$key_tmp" 2>/dev/null | awk -F: '$1 == "fpr" { print toupper($10); exit }')"
        [[ "$fingerprint" == "$TOR_REPO_KEY_FINGERPRINT" ]] || {
            rm -f "$key_tmp"
            fatal "Tor Project signing-key fingerprint mismatch. Refusing to install the key."
        }

        install -d -m 0755 /usr/share/keyrings
        gpg --dearmor --yes --output "$TOR_REPO_KEYRING" "$key_tmp"
        chmod 0644 "$TOR_REPO_KEYRING"
        rm -f "$key_tmp"
    else
        # Refuse to trust a pre-existing keyring that is not the expected Tor key.
        local installed_fingerprint
        installed_fingerprint="$(gpg --show-keys --with-colons "$TOR_REPO_KEYRING" 2>/dev/null | awk -F: '$1 == "fpr" { print toupper($10); exit }')"
        [[ "$installed_fingerprint" == "$TOR_REPO_KEY_FINGERPRINT" ]] || fatal "Existing Tor APT keyring has an unexpected fingerprint: ${installed_fingerprint:-unreadable}. Review it manually."
    fi

    if [[ ! -e "$TOR_REPO_FILE" ]]; then
        cat > "$TOR_REPO_FILE" <<REPO
Types: deb
URIs: https://deb.torproject.org/torproject.org/
Suites: ${VERSION_CODENAME}
Components: main
Architectures: $(dpkg --print-architecture)
Signed-By: ${TOR_REPO_KEYRING}
REPO
        chmod 0644 "$TOR_REPO_FILE"
    else
        warn "$TOR_REPO_FILE already exists; leaving the existing APT source untouched."
    fi

    apt-get update
    apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        tor \
        deb.torproject.org-keyring

    python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer is required; found " + sys.version.split()[0])
print("Python", sys.version.split()[0])
PY
}

create_service_account() {
    log "Creating the dedicated unprivileged application account"

    if ! getent group "$APP_GROUP" >/dev/null; then
        groupadd --system "$APP_GROUP"
    fi

    if ! id "$APP_USER" >/dev/null 2>&1; then
        useradd --system \
            --gid "$APP_GROUP" \
            --home-dir "$STATE_DIR" \
            --no-create-home \
            --shell /usr/sbin/nologin \
            "$APP_USER"
    fi

    # Do not silently accept an existing account with an unexpected primary group.
    local actual_group
    actual_group="$(id -gn "$APP_USER")"
    [[ "$actual_group" == "$APP_GROUP" ]] || fatal "User ${APP_USER} already exists with primary group ${actual_group}; expected ${APP_GROUP}. Review manually."
}

install_application() {
    log "Installing the application into ${APP_DIR}"

    [[ -f "${SCRIPT_DIR}/flask_server.py" ]] || fatal "flask_server.py not found next to this script. Run it from the extracted project directory."
    [[ -f "${SCRIPT_DIR}/requirements-production.txt" ]] || fatal "requirements-production.txt is missing."
    [[ -f "${SCRIPT_DIR}/requirements.txt" ]] || fatal "requirements.txt is missing."
    [[ -d "${SCRIPT_DIR}/templates" && -d "${SCRIPT_DIR}/static" ]] || fatal "The templates/ or static/ directory is missing."

    install -d -o root -g root -m 0755 "$APP_DIR"
    install -m 0644 "${SCRIPT_DIR}/flask_server.py" "$APP_DIR/flask_server.py"
    install -m 0644 "${SCRIPT_DIR}/requirements.txt" "$APP_DIR/requirements.txt"
    install -m 0644 "${SCRIPT_DIR}/requirements-production.txt" "$APP_DIR/requirements-production.txt"

    rm -rf "${APP_DIR}/static" "${APP_DIR}/templates"
    cp -a "${SCRIPT_DIR}/static" "${APP_DIR}/static"
    cp -a "${SCRIPT_DIR}/templates" "${APP_DIR}/templates"
    chown -R root:root "${APP_DIR}/static" "${APP_DIR}/templates"
    find "${APP_DIR}/static" "${APP_DIR}/templates" -type d -exec chmod 0755 {} +
    find "${APP_DIR}/static" "${APP_DIR}/templates" -type f -exec chmod 0644 {} +

    # Flask's instance_path is created at application import time. It is writable
    # for that purpose only; the actual DB and uploads live under /var/lib.
    install -d -o "$APP_USER" -g "$APP_GROUP" -m 0700 "${APP_DIR}/instance"
    install -d -o "$APP_USER" -g "$APP_GROUP" -m 0700 "$STATE_DIR"

    if [[ ! -x "${APP_DIR}/.venv/bin/python" ]]; then
        python3 -m venv "${APP_DIR}/.venv"
    fi

    "${APP_DIR}/.venv/bin/python" -m pip install --upgrade pip
    "${APP_DIR}/.venv/bin/python" -m pip install --requirement "${APP_DIR}/requirements-production.txt"

    chown -R root:root "${APP_DIR}/.venv"
    chmod 0755 "$APP_DIR"
}

configure_environment() {
    log "Creating the private application environment file"
    install -d -o root -g root -m 0755 "$CONFIG_DIR"

    if [[ ! -e "$ENV_FILE" ]]; then
        local secret_key
        secret_key="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
        cat > "$ENV_FILE" <<ENV
SECRET_KEY=${secret_key}
SESSION_COOKIE_SECURE=false
ENABLE_HSTS=false
DATABASE_PATH=${STATE_DIR}/sql_database.db
UPLOAD_FOLDER=${STATE_DIR}/uploads
ENV
        chmod 0600 "$ENV_FILE"
        chown root:root "$ENV_FILE"
    else
        warn "Preserving existing ${ENV_FILE}; review its values before deployment."
        chmod 0600 "$ENV_FILE"
        chown root:root "$ENV_FILE"
    fi

    # Fail early if the environment file does not contain a sufficiently long key.
    local configured_secret
    configured_secret="$(sed -n 's/^SECRET_KEY=//p' "$ENV_FILE" | tail -n 1)"
    [[ "${#configured_secret}" -ge 32 ]] || fatal "SECRET_KEY is missing or shorter than 32 characters in ${ENV_FILE}."
}

configure_tor() {
    log "Configuring the Tor v3 Onion Service"

    id debian-tor >/dev/null 2>&1 || fatal "The debian-tor service account was not created by the Tor package."
    [[ -f "$TORRC" ]] || fatal "Tor configuration file not found: ${TORRC}"

    install -d -o debian-tor -g debian-tor -m 0700 "$TOR_HS_DIR"

    local marker_start marker_end temp_file backup_file
    marker_start="# BEGIN managed ${APP_NAME}"
    marker_end="# END managed ${APP_NAME}"
    temp_file="$(mktemp)"

    python3 - "$TORRC" "$temp_file" "$marker_start" "$marker_end" "$TOR_HS_DIR" "$TOR_BACKEND" <<'PY'
from pathlib import Path
import re
import sys

source, destination, marker_start, marker_end, hs_dir, backend = sys.argv[1:]
path = Path(source)
text = path.read_text(encoding="utf-8") if path.exists() else ""
lines = text.splitlines()

start_positions = [i for i, line in enumerate(lines) if line.strip() == marker_start]
end_positions = [i for i, line in enumerate(lines) if line.strip() == marker_end]
if len(start_positions) != len(end_positions) or len(start_positions) > 1:
    raise SystemExit("Malformed or duplicated managed block in torrc; refusing to modify it.")
if start_positions:
    start, end = start_positions[0], end_positions[0]
    if end <= start:
        raise SystemExit("Managed torrc markers are out of order; refusing to modify it.")
    lines = lines[:start] + lines[end + 1:]

for line in lines:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        continue
    match = re.match(r"(?i)^HiddenServiceDir\s+(\S+)", stripped)
    if match and str(Path(match.group(1))) == str(Path(hs_dir)):
        raise SystemExit(
            f"{hs_dir} is already configured outside this script's managed torrc block. "
            "Review /etc/tor/torrc manually; refusing to create a duplicate."
        )

block = [
    marker_start,
    f"HiddenServiceDir {hs_dir}/",
    f"HiddenServicePort 80 {backend}",
    marker_end,
]
result = "\n".join(lines).rstrip() + "\n\n" + "\n".join(block) + "\n"
Path(destination).write_text(result, encoding="utf-8")
PY

    if ! cmp -s "$TORRC" "$temp_file"; then
        backup_file="${TORRC}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
        cp -a "$TORRC" "$backup_file"
        cat "$temp_file" > "$TORRC"
        chown root:root "$TORRC"
        chmod 0644 "$TORRC"
        log "Backed up the previous torrc to ${backup_file}"
    fi
    rm -f "$temp_file"

    tor --verify-config -f "$TORRC"

    if systemctl cat tor@default.service >/dev/null 2>&1; then
        TOR_UNIT="tor@default.service"
    elif systemctl cat tor.service >/dev/null 2>&1; then
        TOR_UNIT="tor.service"
    else
        fatal "Could not locate tor@default.service or tor.service."
    fi
}

install_systemd_service() {
    log "Installing the hardened Gunicorn systemd service"

    cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=Flask Onion Vault (Gunicorn)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_GROUP}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
Environment=HOME=${STATE_DIR}
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONUNBUFFERED=1
ExecStart=${APP_DIR}/.venv/bin/gunicorn --workers 2 --bind 127.0.0.1:5000 --umask 0077 --timeout 60 --graceful-timeout 30 --error-logfile - flask_server:app
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGQUIT
UMask=0077

NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictSUIDSGID=true
RestrictRealtime=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET
CapabilityBoundingSet=
AmbientCapabilities=
StateDirectory=${APP_NAME}
StateDirectoryMode=0700
ReadWritePaths=${APP_DIR}/instance

[Install]
WantedBy=multi-user.target
UNIT
    chmod 0644 "$SERVICE_FILE"

    # Ensure Tor starts after the local backend service on future boots.
    local dropin_dir
    dropin_dir="/etc/systemd/system/${TOR_UNIT}.d"
    install -d -m 0755 "$dropin_dir"
    cat > "${dropin_dir}/${APP_NAME}.conf" <<UNIT
[Unit]
Wants=${APP_NAME}.service
After=${APP_NAME}.service
UNIT
    chmod 0644 "${dropin_dir}/${APP_NAME}.conf"

    systemctl daemon-reload
    systemctl enable --now "${APP_NAME}.service"
}

create_first_account_if_requested() {
    local user_count secret_key answer
    user_count="$("${APP_DIR}/.venv/bin/python" - "${STATE_DIR}/sql_database.db" <<'PYCOUNT'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    print(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0])
PYCOUNT
)"

    [[ "$user_count" =~ ^[0-9]+$ ]] || fatal "Could not determine whether an initial login account exists."
    if [[ "$user_count" -gt 0 ]]; then
        log "An application account already exists; skipping initial account creation."
        return
    fi

    if [[ -t 0 ]]; then
        printf '\nNo login account exists yet. '
        read -r -p "Create the first account now? [Y/n] " answer
        case "${answer,,}" in
            n|no) ;;
            *)
                secret_key="$(sed -n 's/^SECRET_KEY=//p' "$ENV_FILE" | tail -n 1)"
                runuser -u "$APP_USER" -- env \
                    SECRET_KEY="$secret_key" \
                    DATABASE_PATH="${STATE_DIR}/sql_database.db" \
                    UPLOAD_FOLDER="${STATE_DIR}/uploads" \
                    "${APP_DIR}/.venv/bin/flask" --app flask_server create-user
                ;;
        esac
    else
        warn "No login account exists. Create one interactively after deployment with the command shown in the README."
    fi
}

start_services_and_publish_address() {
    log "Starting the application and Tor"
    systemctl restart "${APP_NAME}.service"
    systemctl enable "$TOR_UNIT"
    systemctl restart "$TOR_UNIT"

    systemctl is-active --quiet "${APP_NAME}.service" || fatal "The Gunicorn application service did not become active. Inspect: journalctl -u ${APP_NAME}.service"
    systemctl is-active --quiet "$TOR_UNIT" || fatal "Tor did not become active. Inspect: journalctl -u ${TOR_UNIT}"

    create_first_account_if_requested

    log "Checking the local Flask login endpoint"
    local http_code
    http_code="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' --max-time 5 http://127.0.0.1:5000/login)"
    [[ "$http_code" == "200" ]] || fatal "The local application health check returned HTTP ${http_code}, expected 200."

    log "Waiting for Tor to create the Onion Service hostname"
    local hostname_file="${TOR_HS_DIR}/hostname"
    local attempt
    for attempt in $(seq 1 60); do
        if [[ -s "$hostname_file" ]]; then
            break
        fi
        sleep 1
    done

    [[ -s "$hostname_file" ]] || {
        journalctl -u "$TOR_UNIT" -n 80 --no-pager || true
        fatal "Tor did not create ${hostname_file}. Check Tor logs and directory permissions."
    }

    local onion_address
    onion_address="$(tr -d '\r\n' < "$hostname_file")"
    [[ "$onion_address" =~ ^[a-z2-7]{56}\.onion$ ]] || fatal "Tor produced an unexpected hostname format; refusing to publish it."

    install -d -o root -g root -m 0755 "$CONFIG_DIR"
    printf '%s\n' "$onion_address" > "${CONFIG_DIR}/ONION_ADDRESS.txt"
    chown root:root "${CONFIG_DIR}/ONION_ADDRESS.txt"
    chmod 0644 "${CONFIG_DIR}/ONION_ADDRESS.txt"

    printf '\n\033[1;32m==============================================\033[0m\n'
    printf '\033[1;32m Flask Onion Vault is running\033[0m\n'
    printf '\033[1;32m==============================================\033[0m\n'
    printf 'Onion address : \033[1;36mhttp://%s\033[0m\n' "$onion_address"
    printf 'Address file  : %s/ONION_ADDRESS.txt\n' "$CONFIG_DIR"
    printf 'App service   : systemctl status %s\n' "$APP_NAME"
    printf 'Tor service   : systemctl status %s\n' "$TOR_UNIT"
    printf 'App logs      : journalctl -u %s -f\n' "$APP_NAME"
    printf 'Tor logs      : journalctl -u %s -f\n' "$TOR_UNIT"
    printf '\nThe Onion Service private keys remain in %s and are not copied.\n' "$TOR_HS_DIR"
    printf 'Do not publish, copy or commit that directory.\n'
    printf '\nNo public firewall ports were opened. Gunicorn listens only on 127.0.0.1:5000.\n'
}

main() {
    require_root
    check_platform
    install_os_dependencies
    create_service_account
    install_application
    configure_environment
    configure_tor
    install_systemd_service
    start_services_and_publish_address
}

main "$@"
