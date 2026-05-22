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
# SHAs below are from feature/saml-oss after the v18.8.1 rebase (2026-05-22).
CUSTOM_COMMITS=(
    # SAML support
    "1be9ecf5566"  # Enable SAML authentication in Teleport OSS
    "7d7006ea056"  # Add test SAML configuration

    # CI/CD and build
    "254bb2e6481"  # Add script to rebase SAML patches onto new Teleport releases
    "d08e45236e8"  # Add CI/CD pipeline to build Docker image with SAML support
    "60ae95862b9"  # Fix Dockerfile chmod outside RUN instruction
    "44e7b6f944f"  # Fix version detection in CI workflow
    "77e473fc0f7"  # Rebuild web UI from source instead of patching compiled bundle
    "ce5075a5597"  # Fix Dockerfile to build web UI from source correctly
    "1aba7f56524"  # Add binary releases and install script
    "6ebfe2c3997"  # Fix CI disk space: free runner space and strip Go debug symbols
    "f474c927a83"  # Fix release workflow version detection and binary extraction

    # Web UI
    "ac090da58a6"  # Add SAML connector editor to web UI

    # Device trust
    "1570838ac11"  # Enable device trust registration in Teleport OSS
    "34b70eedd15"  # Fix device authentication to return real augmented certificates
    "c982a7abd86"  # Disable global device trust mode at proxy transport level
    "37aff4e20a2"  # Add second factor and webauthn config to test SAML config
    "a79c6699ba1"  # Enable trusted devices UI in Teleport OSS
    "0125ee7030a"  # Fix device enrollment not setting owner field

    # Documentation
    "ddf159914ff"  # add documentation on releases

    # Role options
    "41214210af7"  # Remove enterprise restriction for pin_source_ip role option

    # Access requests
    "815036b73fc"  # Enable access requests feature in Teleport OSS
    "091318f2c41"  # add more views to access request view
    "050c760488f"  # Fix access request build: wrap ResourceIDs as ResourceAccessIDs

    # Fork-specific CI cleanup
    "5205fd035b4"  # remove unused ci/cd and update to make work for this fork
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
