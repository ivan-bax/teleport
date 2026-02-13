#!/usr/bin/env bash
#
# Install or upgrade Teleport SAML OSS
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/ivan-bax/teleport/feature/saml-oss/install-teleport-saml.sh | sudo bash
#   curl -sL ... | sudo bash -s -- --version v18.6.8
#   curl -sL ... | sudo bash -s -- --uninstall
#
set -euo pipefail

REPO="ivan-bax/teleport"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/teleport"
DATA_DIR="/var/lib/teleport"
SERVICE_NAME="teleport"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Parse args ---
VERSION=""
UNINSTALL=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --uninstall) UNINSTALL=true; shift ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Uninstall ---
if $UNINSTALL; then
    info "Uninstalling Teleport SAML OSS..."
    systemctl stop teleport 2>/dev/null || true
    systemctl disable teleport 2>/dev/null || true
    rm -f /etc/systemd/system/teleport.service
    systemctl daemon-reload 2>/dev/null || true
    rm -f "$INSTALL_DIR/teleport" "$INSTALL_DIR/tctl" "$INSTALL_DIR/tsh" "$INSTALL_DIR/tbot"
    info "Binaries removed. Config ($CONFIG_DIR) and data ($DATA_DIR) left intact."
    exit 0
fi

# --- Check root ---
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
    exit 1
fi

# --- Check arch ---
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *) error "Unsupported architecture: $ARCH"; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [[ "$OS" != "linux" ]]; then
    error "Unsupported OS: $OS (only linux is supported)"
    exit 1
fi

# --- Detect version ---
if [[ -z "$VERSION" ]]; then
    info "Detecting latest version..."
    VERSION=$(curl -sL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"saml-oss-\(v[^"]*\)".*/\1/')
    if [[ -z "$VERSION" ]]; then
        error "Could not detect latest version"
        exit 1
    fi
fi
info "Version: $VERSION"

# --- Check current version ---
if command -v teleport &>/dev/null; then
    CURRENT=$(teleport version 2>/dev/null | grep -oP 'v\d+\.\d+\.\d+' | head -1 || echo "unknown")
    info "Current version: $CURRENT"
    if [[ "$CURRENT" == "$VERSION" ]]; then
        info "Already at $VERSION. Use --version to force a specific version."
        exit 0
    fi
fi

# --- Download ---
TARBALL="teleport-saml-oss-${VERSION}-linux-${ARCH}.tar.gz"
RELEASE_TAG="saml-oss-${VERSION}"
URL="https://github.com/$REPO/releases/download/$RELEASE_TAG/$TARBALL"

info "Downloading $URL..."
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

if ! curl -fSL "$URL" -o "$TMP/$TARBALL"; then
    error "Download failed. Check that version $VERSION exists at:"
    error "  https://github.com/$REPO/releases"
    exit 1
fi

# --- Verify checksum ---
CHECKSUM_URL="https://github.com/$REPO/releases/download/$RELEASE_TAG/checksums.txt"
if curl -fsSL "$CHECKSUM_URL" -o "$TMP/checksums.txt" 2>/dev/null; then
    cd "$TMP"
    if sha256sum -c checksums.txt --status 2>/dev/null; then
        info "Checksum verified."
    else
        warn "Checksum verification failed — proceeding anyway."
    fi
    cd - >/dev/null
fi

# --- Extract ---
info "Extracting binaries..."
tar xzf "$TMP/$TARBALL" -C "$TMP"

# --- Stop service if running ---
if systemctl is-active --quiet teleport 2>/dev/null; then
    info "Stopping teleport service..."
    systemctl stop teleport
    RESTART=true
else
    RESTART=false
fi

# --- Install binaries ---
for bin in teleport tctl tsh tbot; do
    if [[ -f "$TMP/$bin" ]]; then
        install -m 755 "$TMP/$bin" "$INSTALL_DIR/$bin"
        info "Installed $INSTALL_DIR/$bin"
    fi
done

# --- Create directories ---
mkdir -p "$CONFIG_DIR" "$DATA_DIR"

# --- Create systemd service ---
if [[ ! -f /etc/systemd/system/teleport.service ]]; then
    info "Creating systemd service..."
    cat > /etc/systemd/system/teleport.service <<'EOF'
[Unit]
Description=Teleport SAML OSS
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/teleport start -c /etc/teleport/teleport.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable teleport
    info "Service created and enabled."
fi

# --- Restart if was running ---
if $RESTART; then
    info "Restarting teleport service..."
    systemctl start teleport
    sleep 2
    if systemctl is-active --quiet teleport; then
        info "Teleport is running."
    else
        warn "Teleport may not have started correctly. Check: journalctl -u teleport"
    fi
else
    if [[ ! -f "$CONFIG_DIR/teleport.yaml" ]]; then
        warn "No config found at $CONFIG_DIR/teleport.yaml"
        warn "Create one, then start with: systemctl start teleport"
    else
        info "Start with: systemctl start teleport"
    fi
fi

info "Done! Teleport SAML OSS $VERSION installed."
echo ""
echo "  teleport version    — check version"
echo "  systemctl status teleport — check service"
echo "  tctl status         — check cluster status"
