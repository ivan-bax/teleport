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
# SHAs below are from feature/saml-oss after the v18.9.0 rebase (2026-06-19).
CUSTOM_COMMITS=(
    # SAML support
    "7b1f4b113f1"  # Enable SAML authentication in Teleport OSS
    "46c6efa2270"  # Add test SAML configuration

    # CI/CD and build
    "d12754090a5"  # Add script to rebase SAML patches onto new Teleport releases
    "09b73a9664b"  # Add CI/CD pipeline to build Docker image with SAML support
    "48c227fc4a6"  # Fix Dockerfile chmod outside RUN instruction
    "5213f797188"  # Fix version detection in CI workflow
    "1fe2c9f802f"  # Rebuild web UI from source instead of patching compiled bundle
    "742e7736109"  # Fix Dockerfile to build web UI from source correctly
    "5a2c70884e7"  # Add binary releases and install script
    "7431d928726"  # Fix CI disk space: free runner space and strip Go debug symbols
    "a39ed493c55"  # Fix release workflow version detection and binary extraction

    # Web UI
    "e7452939003"  # Add SAML connector editor to web UI

    # Device trust
    "735423967f1"  # Enable device trust registration in Teleport OSS
    "acab4a144d7"  # Fix device authentication to return real augmented certificates
    "29f9b7f3e74"  # Disable global device trust mode at proxy transport level
    "92409da7382"  # Add second factor and webauthn config to test SAML config
    "8bfdda29052"  # Enable trusted devices UI in Teleport OSS
    "cc21a8fe583"  # Fix device enrollment not setting owner field

    # Documentation
    "170e382f4af"  # add documentation on releases

    # Role options
    "5bd0f466fc9"  # Remove enterprise restriction for pin_source_ip role option

    # Access requests
    "91dbcce2d49"  # Enable access requests feature in Teleport OSS
    "48d8f266abd"  # add more views to access request view
    "11d18e6b0c8"  # Fix access request build: wrap ResourceIDs as ResourceAccessIDs
    "670997efa53"  # Fix access requests web UI for v18.9.0 design system API

    # Fork-specific CI cleanup
    "bc3ddda3e4c"  # remove unused ci/cd and update to make work for this fork

    # Login rules
    "9c0d12a8c5c"  # Enable login rules feature in Teleport OSS

    # Access monitoring rules
    "b5d8bafb94b"  # Add access monitoring rules UI and web API for OSS

    # Cross-origin logout
    "2ab65289b45"  # Add cross-origin logout endpoint with origin allowlist
    "95b0271e8ca"  # Use DELETE for the cross-origin logout endpoint

    # v18.9.0 build fixes
    "86de258eb49"  # Fix Docker web build for v18.9.0 (Vite 8, removed .npmrc/web-patches)
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
