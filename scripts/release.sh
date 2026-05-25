#!/usr/bin/env bash
# Cut a release: validate state, sync internal/version/VERSION with the
# debian/changelog head, commit, tag. Does NOT push — leaves that to the
# operator.
#
# Usage: scripts/release.sh <version>     # e.g. scripts/release.sh 0.2.0
#
# Workflow:
#   1. vim debian/changelog            # add a new stanza for X.Y.Z
#   2. scripts/release.sh X.Y.Z        # validates + tags
#   3. git push origin master vX.Y.Z   # (when ready)
#
# The changelog is the structural gate — you cannot tag a version that
# doesn't have a corresponding stanza in debian/changelog.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: scripts/release.sh <version>   (e.g. 0.2.0)" >&2
    exit 64
fi

VERSION="$1"
TAG="v${VERSION}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null && pwd)"
cd "$ROOT"

fail() { echo "error: $*" >&2; exit 1; }

# Gate 6 — semver (cheapest check first, fails fast on typos)
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    fail "<version> must be plain semver X.Y.Z (got: $VERSION)"
fi

# Gate 1a — on master
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BRANCH" != "master" ]]; then
    fail "must be on master to release (currently on: $BRANCH)"
fi

# Gate 1b — not behind origin/master (fetch first to make this meaningful)
echo "+ fetching origin/master..."
git fetch origin master --quiet
if [[ "$(git rev-list --count HEAD..origin/master)" != "0" ]]; then
    fail "branch is behind origin/master — pull first"
fi

# Gate 2 — working tree clean except possibly debian/changelog and VERSION
# (those two are what *this* script may commit; everything else must already
# be either committed or untracked-and-irrelevant — porcelain shows both).
ALLOWED='^(debian/changelog|internal/version/VERSION)$'
DIRTY="$(git status --porcelain | sed 's/^...//' | { grep -vE "$ALLOWED" || true; })"
if [[ -n "$DIRTY" ]]; then
    echo "error: working tree has uncommitted/untracked changes outside the release-managed files:" >&2
    echo "$DIRTY" | sed 's/^/  /' >&2
    exit 1
fi

# Gate 4 — tag must not already exist
if git rev-parse "$TAG" >/dev/null 2>&1; then
    fail "tag $TAG already exists"
fi

# Gate 5 — debian/changelog head matches the requested version
if ! command -v dpkg-parsechangelog >/dev/null; then
    fail "dpkg-parsechangelog not found (install dpkg-dev)"
fi
CHANGELOG_VERSION="$(dpkg-parsechangelog -l debian/changelog -SVersion)"
if [[ "$CHANGELOG_VERSION" != "$VERSION" ]]; then
    echo "error: debian/changelog head version is '$CHANGELOG_VERSION', requested release '$VERSION'." >&2
    echo "  → add a new stanza for $VERSION to debian/changelog and try again." >&2
    exit 1
fi

# Gate 3 — tests pass (slowest gate, last)
echo "+ running tests..."
if ! go test ./... ; then
    fail "tests failed"
fi

# All gates passed. Preview what we're about to release.
echo
echo "About to release $TAG. Changelog stanza:"
echo "----------------------------------------"
dpkg-parsechangelog -l debian/changelog -SChanges
echo "----------------------------------------"
echo

# Sync VERSION (idempotent — writing same value is fine)
echo "+ writing internal/version/VERSION = $VERSION"
echo "$VERSION" > internal/version/VERSION

# Commit if there's anything to commit; otherwise re-running after a partial
# failure (e.g. tag step) just proceeds straight to tagging.
git add internal/version/VERSION debian/changelog
if ! git diff --cached --quiet; then
    echo "+ committing chore: release $TAG"
    git commit -m "chore: release $TAG"
else
    echo "+ nothing to commit (VERSION and changelog already up to date)"
fi

echo "+ tagging $TAG"
git tag -a "$TAG" -m "Release $TAG"

echo
echo "Released $TAG locally. Push with:"
echo "    git push origin master $TAG"
