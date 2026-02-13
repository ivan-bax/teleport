#!/usr/bin/env bash
#
# update-saml-fork.sh — Rebase SAML OSS patches onto a new Teleport release
#
# Usage:
#   ./update-saml-fork.sh v18.7.0
#   ./update-saml-fork.sh              # auto-detects latest release
#
# What it does:
#   1. Fetches the latest tags from upstream (gravitational/teleport)
#   2. Creates a new branch from the target release tag
#   3. Cherry-picks the SAML OSS commits onto it
#   4. Rebuilds the teleport binary with patched web assets
#   5. Pushes the updated branch to your fork
#
# Prerequisites:
#   - Go installed at /usr/local/go/bin/go
#   - git remotes: origin=gravitational/teleport, myfork=ivan-bax/teleport
#   - brotli tool helper at /tmp/brotli_tool.go (or install brotli CLI)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GO_BIN="${GO_BIN:-/usr/local/go/bin/go}"
FORK_REMOTE="${FORK_REMOTE:-myfork}"
UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-origin}"
BRANCH_NAME="feature/saml-oss"

# The SAML commits to cherry-pick (update these if you amend them)
SAML_COMMITS=(
    "90b0f980f9"  # Enable SAML authentication in Teleport OSS
    "c22f30c513"  # Add test SAML configuration
)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Determine target version ---
if [[ $# -ge 1 ]]; then
    TARGET_TAG="$1"
else
    info "No version specified. Fetching latest release tag..."
    git fetch "$UPSTREAM_REMOTE" --tags --quiet
    # Get the latest v* tag that looks like a release (vX.Y.Z, no -rc, -alpha, etc.)
    TARGET_TAG=$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*' --sort=-version:refname \
        | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
        | head -1)
    if [[ -z "$TARGET_TAG" ]]; then
        error "Could not determine latest release tag."
        exit 1
    fi
    info "Latest release: $TARGET_TAG"
    read -rp "Rebase onto $TARGET_TAG? [Y/n] " confirm
    if [[ "$confirm" =~ ^[Nn] ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# --- Validate tag exists ---
info "Fetching tags from $UPSTREAM_REMOTE..."
git fetch "$UPSTREAM_REMOTE" --tags --quiet

if ! git rev-parse "$TARGET_TAG" >/dev/null 2>&1; then
    error "Tag $TARGET_TAG not found. Available recent tags:"
    git tag -l 'v18.*' --sort=-version:refname | head -10
    exit 1
fi

# --- Get current version for comparison ---
CURRENT_BASE=$(git log --oneline "$BRANCH_NAME" | grep "^[a-f0-9]* Release " | head -1 | sed 's/.*Release //' | sed 's/ .*//')
info "Current base: ${CURRENT_BASE:-unknown}"
info "Target base:  $TARGET_TAG"

# --- Save current branch ---
ORIGINAL_BRANCH=$(git branch --show-current)

# --- Create new branch from target tag ---
TEMP_BRANCH="${BRANCH_NAME}-${TARGET_TAG}"
info "Creating branch $TEMP_BRANCH from $TARGET_TAG..."
git checkout -b "$TEMP_BRANCH" "$TARGET_TAG"

# --- Cherry-pick SAML commits ---
info "Cherry-picking SAML OSS commits..."
FAILED=0
for commit in "${SAML_COMMITS[@]}"; do
    SUBJECT=$(git log --oneline -1 "$commit" 2>/dev/null | cut -d' ' -f2-)
    info "  Applying: $SUBJECT"
    if ! git cherry-pick "$commit" --no-edit 2>/dev/null; then
        warn "  Conflict in commit $commit. Resolve manually, then run:"
        warn "    git cherry-pick --continue"
        warn "    # then re-run this script's remaining steps manually"
        FAILED=1
        break
    fi
done

if [[ $FAILED -eq 1 ]]; then
    error "Cherry-pick had conflicts. Resolve them, then:"
    echo ""
    echo "  git cherry-pick --continue"
    echo "  git branch -m $BRANCH_NAME ${BRANCH_NAME}-old-$(date +%Y%m%d)"
    echo "  git branch -m $TEMP_BRANCH $BRANCH_NAME"
    echo "  git push $FORK_REMOTE $BRANCH_NAME --force-with-lease"
    echo ""
    exit 1
fi

# --- Update branch name ---
info "Updating branch name..."
OLD_BRANCH="${BRANCH_NAME}-old-$(date +%Y%m%d)"
git branch -m "$BRANCH_NAME" "$OLD_BRANCH" 2>/dev/null || true
git branch -m "$TEMP_BRANCH" "$BRANCH_NAME"

# --- Build (optional) ---
read -rp "Build the teleport binary now? [Y/n] " build_confirm
if [[ ! "$build_confirm" =~ ^[Nn] ]]; then
    info "Building teleport binary..."

    # Patch web assets if brotli tool is available
    if [[ -f /tmp/brotli_tool.go ]] && [[ -f /tmp/patch_app.go ]] && [[ -f /tmp/patch_editor.go ]]; then
        info "Patching web assets..."
        PATH="/usr/local/go/bin:$PATH" "$GO_BIN" run /tmp/brotli_tool.go d webassets/teleport/app/app.js.br /tmp/app.js
        PATH="/usr/local/go/bin:$PATH" "$GO_BIN" run /tmp/patch_app.go
        PATH="/usr/local/go/bin:$PATH" "$GO_BIN" run /tmp/patch_editor.go
        PATH="/usr/local/go/bin:$PATH" "$GO_BIN" run /tmp/brotli_tool.go c /tmp/app_patched2.js webassets/teleport/app/app.js.br
        info "Web assets patched."
    else
        warn "Brotli/patch tools not found in /tmp. Skipping web asset patching."
        warn "The binary will work but the Auth Connectors management UI won't show SAML connectors."
    fi

    PATH="/usr/local/go/bin:$PATH" CGO_ENABLED=1 "$GO_BIN" build -tags "webassets_embed" -o build/teleport ./tool/teleport
    info "Binary built: build/teleport"
fi

# --- Push ---
read -rp "Push $BRANCH_NAME to $FORK_REMOTE? [Y/n] " push_confirm
if [[ ! "$push_confirm" =~ ^[Nn] ]]; then
    info "Pushing to $FORK_REMOTE..."
    git push "$FORK_REMOTE" "$BRANCH_NAME" --force-with-lease
    info "Pushed successfully."
fi

# --- Cleanup ---
if git rev-parse --verify "$OLD_BRANCH" >/dev/null 2>&1; then
    read -rp "Delete old branch $OLD_BRANCH? [Y/n] " del_confirm
    if [[ ! "$del_confirm" =~ ^[Nn] ]]; then
        git branch -D "$OLD_BRANCH"
    fi
fi

echo ""
info "Done! $BRANCH_NAME is now based on $TARGET_TAG"
info "SAML commits:"
for commit in "${SAML_COMMITS[@]}"; do
    echo "  $(git log --oneline -1 "$commit")"
done
