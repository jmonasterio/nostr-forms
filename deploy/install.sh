#!/bin/bash
# Install script for nostr-form-rs on Debian/Ubuntu
set -e

echo "=== Installing nostr-form-rs ==="

# Create user if not exists
if ! id -u nostr-form-rs >/dev/null 2>&1; then
    echo "Creating nostr-form-rs user..."
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin nostr-form-rs
fi

# Create directories
echo "Creating directories..."
sudo mkdir -p /etc/nostr-form-rs
sudo mkdir -p /var/lib/nostr-form-rs
sudo mkdir -p /var/www/nostr-form-rs

# Set ownership
sudo chown nostr-form-rs:nostr-form-rs /var/lib/nostr-form-rs
sudo chown www-data:www-data /var/www/nostr-form-rs

# Copy config if not exists
if [ ! -f /etc/nostr-form-rs/config.json ]; then
    echo "Creating default config..."
    sudo tee /etc/nostr-form-rs/config.json << 'EOF'
{
  "relay_url": "ws://127.0.0.1:8080",
  "database_path": "/var/lib/nostr-form-rs/forms.db",
  "api_bind_addr": "127.0.0.1:8081",
  "default_pow_difficulty": 16,
  "bootstrap_admin_pubkey": null
}
EOF
fi

# Install systemd service
echo "Installing systemd service..."
sudo cp nostr-form-rs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nostr-form-rs

echo ""
echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "1. Edit /etc/nostr-form-rs/config.json"
echo "   - Set bootstrap_admin_pubkey to your Nostr pubkey"
echo "   - Adjust relay_url if needed"
echo ""
echo "2. Copy the binary:"
echo "   sudo cp nostr-form-rs /usr/local/bin/"
echo "   sudo chmod +x /usr/local/bin/nostr-form-rs"
echo ""
echo "3. Copy web assets:"
echo "   sudo cp -r web/* /var/www/nostr-form-rs/"
echo ""
echo "4. Start the service:"
echo "   sudo systemctl start nostr-form-rs"
echo "   sudo systemctl status nostr-form-rs"
echo ""
echo "5. Configure nginx/caddy to proxy /api to 127.0.0.1:8081"
echo "   and serve /var/www/nostr-form-rs for static files"
