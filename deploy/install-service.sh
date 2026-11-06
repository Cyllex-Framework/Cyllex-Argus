#!/usr/bin/env bash
# Install Argus as a systemd service. Needs sudo. Tested on Debian 12 and Ubuntu 24.04.
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/argus}"
HOME_DIR="${HOME_DIR:-/var/lib/argus}"
USER_NAME="${USER_NAME:-argus}"
ENV_FILE="${ENV_FILE:-/etc/argus/env}"
UNIT_SRC="$(cd "$(dirname "$0")" && pwd)/argus.service"
UNIT_DEST="/etc/systemd/system/argus.service"

if [[ $EUID -ne 0 ]]; then
    echo "This script needs sudo." >&2
    exit 1
fi

if [[ ! -f "$UNIT_SRC" ]]; then
    echo "argus.service not found next to this script: $UNIT_SRC" >&2
    exit 1
fi

if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
    echo "No venv found at $INSTALL_DIR/.venv — run \`uv sync\` inside $INSTALL_DIR first." >&2
    exit 1
fi

# Dedicated user that owns the install + home. Already-exists is fine.
if ! id "$USER_NAME" &>/dev/null; then
    useradd --system --home-dir "$HOME_DIR" --shell /sbin/nologin --no-create-home "$USER_NAME"
    echo "Created system user: $USER_NAME"
fi

mkdir -p "$HOME_DIR"
chown -R "$USER_NAME:$USER_NAME" "$HOME_DIR"
chown -R "$USER_NAME:$USER_NAME" "$INSTALL_DIR"

# EnvironmentFile for the admin password. If it does not exist, write a template so systemd
# does not refuse to start.
if [[ ! -f "$ENV_FILE" ]]; then
    mkdir -p "$(dirname "$ENV_FILE")"
    cat >"$ENV_FILE" <<'EOF'
# Argus runtime environment — edit before enabling the service.
# At minimum set ARGUS_ADMIN_PASSWORD so the web login screen works.
ARGUS_ADMIN_USERNAME=admin
ARGUS_ADMIN_PASSWORD=change-me-before-starting
EOF
    chmod 600 "$ENV_FILE"
    chown root:root "$ENV_FILE"
    echo "Wrote $ENV_FILE — edit it (chmod 600) and set ARGUS_ADMIN_PASSWORD before starting."
fi

install -m 644 "$UNIT_SRC" "$UNIT_DEST"
systemctl daemon-reload
systemctl enable argus

cat <<EOF

argus.service installed. Next steps:
  1. edit $ENV_FILE and set a real ARGUS_ADMIN_PASSWORD
  2. sudo systemctl start argus
  3. sudo systemctl status argus
  4. journalctl -u argus -f    # tail the live log

Argus runs on http://127.0.0.1:8765 (loopback). Put nginx or caddy in front
with TLS to expose it on the LAN.

To uninstall:
  sudo systemctl disable --now argus
  sudo rm /etc/systemd/system/argus.service /etc/argus/env
  sudo userdel argus     # optional — removes the service account
  sudo rm -rf /var/lib/argus   # optional — removes the knowledge base
EOF
