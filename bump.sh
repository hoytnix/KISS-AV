#!/usr/bin/env bash

set -euo pipefail

# -----------------------------------------------------------------------------
# Bump Script for KISS AV (Cargo.toml, packager.json, README.md)
# Usage: ./bump.sh [patch|minor|major]
# -----------------------------------------------------------------------------

TYPE="${1:-patch}"

if [[ ! "$TYPE" =~ ^(patch|minor|major)$ ]]; then
  echo "Error: Invalid argument '$TYPE'."
  echo "Usage: $0 [patch|minor|major]"
  exit 1
fi

# Ensure working tree is clean
if [[ -n $(git status --porcelain) ]]; then
  echo "Error: Working directory is not clean. Commit or stash changes first."
  exit 1
fi

# Extract current version from Cargo.toml
CURRENT_VERSION=$(sed -n -E 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)"/\1/p' Cargo.toml | head -n 1)

if [[ -z "$CURRENT_VERSION" ]]; then
  echo "Error: Could not extract version from Cargo.toml."
  exit 1
fi

# Parse semver components
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

# Calculate new semver
case "$TYPE" in
  patch)
    PATCH=$((PATCH + 1))
    ;;
  minor)
    MINOR=$((MINOR + 1))
    PATCH=0
    ;;
  major)
    MAJOR=$((MAJOR + 1))
    MINOR=0
    PATCH=0
    ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"

echo "Bumping version: $CURRENT_VERSION -> $NEW_VERSION ($TYPE)"

# Detect OS for sed in-place compatibility (macOS vs Linux)
if [[ "$OSTYPE" == "darwin"* ]]; then
  SED_INPLACE=(-i '')
else
  SED_INPLACE=(-i)
fi

# 1. Update Cargo.toml (only package version)
sed "${SED_INPLACE[@]}" -E "0,/^version = \"[0-9]+\.[0-9]+\.[0-9]+\"/s//version = \"${NEW_VERSION}\"/" Cargo.toml

# 2. Update Cargo.lock to match Cargo.toml version
cargo check

# 3. Update packager.json if it exists
if [[ -f "packager.json" ]]; then
  sed "${SED_INPLACE[@]}" -E "s/\"version\": \"[0-9]+\.[0-9]+\.[0-9]+\"/\"version\": \"${NEW_VERSION}\"/" packager.json
fi

# 4. Update README.md (handles both v1.2.13 and standalone 1.2.13)
if [[ -f "README.md" ]]; then
  sed "${SED_INPLACE[@]}" -E "s/${CURRENT_VERSION}/${NEW_VERSION}/g" README.md
fi

echo "Updated files:"
git status --short