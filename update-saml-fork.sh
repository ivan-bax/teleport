#!/usr/bin/env bash
#
# update-saml-fork.sh — Rebase OSS customization patches onto a new Teleport release
#
# Usage:
#   ./update-saml-fork.sh v18.7.0
#   ./update-saml-fork.sh              # auto-detects latest release
#
# What it does:
#   1. Fetches the latest tags from upstream (gravitational/teleport)
#   2. Creates a new branch from the target release tag
#   3. Cherry-picks all custom commits (SAML, device trust, CI, web UI)
#   4. Pushes the updated branch to your fork
#
# Prerequisites:
#   - git remotes: origin=gravitational/teleport, myfork=ivan-bax/teleport
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd /home/ivan/personal-projects/teleport

FORK_REMOTE="${FORK_REMOTE:-myfork}"
UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-origin}"
BRANCH_NAME="feature/saml-oss"

# All custom commits to cherry-pick, in order (update these if you amend them)
CUSTOM_COMMITS=(
    # SAML support
    "bafedd0d0d"  # Enable SAML authentication in Teleport OSS
    "fae973635b"  # Add test SAML configuration

    # CI/CD and build
    "d295c5641d"  # Add script to rebase SAML patches onto new Teleport releases
    "47f1db3585"  # Add CI/CD pipeline to build Docker image with SAML support
    "ccbcb01035"  # Fix Dockerfile chmod outside RUN instruction
    "e8c1e5fe1d"  # Fix version detection in CI workflow
    "2e9cf2086d"  # Rebuild web UI from source instead of patching compiled bundle
    "fcf3bf8f38"  # Fix Dockerfile to build web UI from source correctly
    "0723de7d0f"  # Add binary releases and install script
    "a9785bfe85"  # Fix CI disk space: free runner space and strip Go debug symbols
    "91482ff163"  # Fix release workflow version detection and binary extraction

    # Web UI
    "f75778af80"  # Add SAML connector editor to web UI

    # Device trust
    "a705b744f7"  # Enable device trust registration in Teleport OSS
    "7848d3993e"  # Fix device authentication to return real augmented certificates
    "e424c25af0"  # Disable global device trust mode at proxy transport level
    "47566f2fb4"  # Add second factor and webauthn config to test SAML config
    "d2094c259c"  # Enable trusted devices UI in Teleport OSS
    "249e4e1871"  # Fix device enrollment not setting owner field

    # Documentation
    "980d083c78"  # add documentation on releases

    # Role options
    "3883cf48aa"  # Remove enterprise restriction for pin_source_ip role option

    # Access requests
    "79305995b2"  # Enable access requests feature in Teleport OSS
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
CURRENT_BASE=$(git log --oneline "$BRANCH_NAME" | grep "^[a-f0-9]* Release " | head -1 | sed 's/.*Release //' | sed 's/ .*//' || true)
info "Current base: ${CURRENT_BASE:-unknown}"
info "Target base:  $TARGET_TAG"

# --- Save current branch ---
ORIGINAL_BRANCH=$(git branch --show-current)

# --- Create new branch from target tag ---
TEMP_BRANCH="${BRANCH_NAME}-${TARGET_TAG}"
info "Creating branch $TEMP_BRANCH from $TARGET_TAG..."
git checkout -b "$TEMP_BRANCH" "$TARGET_TAG"

# --- Cherry-pick custom commits ---
info "Cherry-picking ${#CUSTOM_COMMITS[@]} custom commits..."
FAILED=0
for commit in "${CUSTOM_COMMITS[@]}"; do
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
info "Custom commits applied (${#CUSTOM_COMMITS[@]}):"
for commit in "${CUSTOM_COMMITS[@]}"; do
    echo "  $(git log --oneline -1 "$commit")"
done
