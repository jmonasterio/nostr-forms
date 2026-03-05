#!/bin/bash
# Install nostr-form-rs on Debian/Ubuntu.
# Run from the repository root: sudo bash deploy/install.sh
set -euo pipefail

BINARY=nostr-form-rs
BIN_DEST=/usr/local/bin/$BINARY
CONF_DIR=/etc/nostr-form-rs
DATA_DIR=/var/lib/nostr-form-rs
WEB_DIR=/var/www/nostr-form-rs
SERVICE_SRC=deploy/nostr-form-rs.service
SERVICE_DEST=/etc/systemd/system/nostr-form-rs.service

echo "=== Installing $BINARY ==="

# ── Preflight ────────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root or with sudo." >&2
    exit 1
fi

if [ ! -f Cargo.toml ]; then
    echo "ERROR: Run from the repository root." >&2
    exit 1
fi

# ── Build ─────────────────────────────────────────────────────────────────────
echo "Building release binary (requires Rust toolchain)..."
if ! command -v cargo &>/dev/null; then
    echo "ERROR: cargo not found. Install Rust: https://rustup.rs" >&2
    exit 1
fi

# Build as the invoking user, not root.
SUDO_USER_HOME=$(eval echo "~${SUDO_USER:-$USER}")
sudo -u "${SUDO_USER:-$USER}" cargo build --release
BUILT=target/release/$BINARY

if [ ! -f "$BUILT" ]; then
    echo "ERROR: Build succeeded but binary not found at $BUILT" >&2
    exit 1
fi

# ── System user ───────────────────────────────────────────────────────────────
if ! id -u $BINARY &>/dev/null; then
    echo "Creating system user $BINARY..."
    useradd --system --no-create-home --shell /usr/sbin/nologin $BINARY
fi

# ── Directories ───────────────────────────────────────────────────────────────
echo "Creating directories..."
mkdir -p "$CONF_DIR" "$DATA_DIR" "$WEB_DIR/admin"
chown "$BINARY:$BINARY" "$DATA_DIR"
chown www-data:www-data "$WEB_DIR"

# ── Binary ────────────────────────────────────────────────────────────────────
echo "Installing binary -> $BIN_DEST"
install -m 0755 -o root -g root "$BUILT" "$BIN_DEST"

# ── Web assets ────────────────────────────────────────────────────────────────
echo "Installing web assets -> $WEB_DIR"
cp -r web/admin/. "$WEB_DIR/admin/"
cp web/forms.js    "$WEB_DIR/forms.js"
chown -R www-data:www-data "$WEB_DIR"

# ── Default config (non-destructive) ──────────────────────────────────────────
if [ ! -f "$CONF_DIR/config.json" ]; then
    echo "Writing default config -> $CONF_DIR/config.json"
    cat > "$CONF_DIR/config.json" << 'EOF'
{
  "relay_url": "ws://127.0.0.1:8080",
  "database_path": "/var/lib/nostr-form-rs/forms.db",
  "api_bind_addr": "127.0.0.1:8081",
  "default_pow_difficulty": 16,
  "bootstrap_admin_pubkey": null
}
EOF
fi
chown root:"$BINARY" "$CONF_DIR/config.json"
chmod 640 "$CONF_DIR/config.json"

# ── Systemd service ───────────────────────────────────────────────────────────
echo "Installing systemd service -> $SERVICE_DEST"
install -m 0644 -o root -g root "$SERVICE_SRC" "$SERVICE_DEST"
systemctl daemon-reload
systemctl enable nostr-form-rs

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "=== Installation complete ==="
echo ""
echo "Before starting the service:"
echo "  1. Set bootstrap_admin_pubkey in $CONF_DIR/config.json"
echo "     (your 64-char hex Nostr pubkey — grants first admin login)"
echo ""
echo "  2. Configure nginx/caddy to proxy /api/ to 127.0.0.1:8081"
echo "     and serve the admin UI from $WEB_DIR"
echo "     Example: sudo cp deploy/nginx.conf /etc/nginx/conf.d/nostr-form-rs.conf"
echo ""
echo "  3. Start the service:"
echo "     sudo systemctl start nostr-form-rs"
echo "     sudo systemctl status nostr-form-rs"
