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
    "7921199ade2"  # Enable SAML authentication in Teleport OSS
    "188bb3f1afb"  # Add test SAML configuration

    # CI/CD and build
    "13fd84966ed"  # Add script to rebase SAML patches onto new Teleport releases
    "a7ab96e2cdc"  # Add CI/CD pipeline to build Docker image with SAML support
    "287ddf10674"  # Fix Dockerfile chmod outside RUN instruction
    "571e792056c"  # Fix version detection in CI workflow
    "a9aeb3098a2"  # Rebuild web UI from source instead of patching compiled bundle
    "cdddcb25d02"  # Fix Dockerfile to build web UI from source correctly
    "f7fd4d21400"  # Add binary releases and install script
    "531f3b9792e"  # Fix CI disk space: free runner space and strip Go debug symbols
    "c9a0999718e"  # Fix release workflow version detection and binary extraction

    # Web UI
    "3b6ab7a485b"  # Add SAML connector editor to web UI

    # Device trust
    "a6138c8771a"  # Enable device trust registration in Teleport OSS
    "54881f14ead"  # Fix device authentication to return real augmented certificates
    "6c300d10281"  # Disable global device trust mode at proxy transport level
    "b18144ccc10"  # Add second factor and webauthn config to test SAML config
    "0c14cf8df25"  # Enable trusted devices UI in Teleport OSS
    "22a1827ce1c"  # Fix device enrollment not setting owner field

    # Documentation
    "812c4ee7999"  # add documentation on releases

    # Role options
    "e95fc7ba822"  # Remove enterprise restriction for pin_source_ip role option

    # Access requests
    "0cec1bba59d"  # Enable access requests feature in Teleport OSS
    "6d72489be73"  # add more views to access request view
    "91ac8f12eb4"  # Fix access request build: wrap ResourceIDs as ResourceAccessIDs

    # Fork-specific CI cleanup
    "3c9ca8cfd6b"  # remove unused ci/cd and update to make work for this fork

    # Login rules
    "46fca13be59"  # Enable login rules feature in Teleport OSS

    # Access monitoring rules
    "75a57a739a5"  # Add access monitoring rules UI and web API for OSS

    # Cross-origin logout
    "312ff710389"  # Add cross-origin logout endpoint with origin allowlist
    "69e53a15a5b"  # Use DELETE for the cross-origin logout endpoint

    # v18.9.0 build fixes
    "e62f526f8e8"  # Fix access requests web UI for v18.9.0 design system API
    "f54ac047a87"  # Fix Docker web build for v18.9.0 (Vite 8, removed .npmrc/web-patches)
    "fcb0990a680"  # chore: update CUSTOM_COMMITS for v18.9.0 rebase

    # SAML audit log fix
    "3bef5a9db52"  # fix the saml issue of don't getting the real ip in the audit logs

    # Documentation
    "baa015cef3e"  # docs: rewrite README as fork front-door

    # v18.10.0 build fixes
    "d2265a76132"  # Fix Docker web build for v18.10.0: bump wasm-bindgen CLI to 0.2.122
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
