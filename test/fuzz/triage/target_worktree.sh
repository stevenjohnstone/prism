#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ -z "${1:-}" ]; then
  echo "Usage: target_worktree.sh <git-rev> [worktree-dir]" >&2
  exit 2
fi

REV="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
WORKTREE_DIR="${2:-$REPO_ROOT/build/.fuzz-target-worktree}"

if ! SHA="$(git -C "$REPO_ROOT" rev-parse --verify "${REV}^{commit}" 2>/dev/null)"; then
  echo "target_worktree.sh: unknown git revision '$REV'" >&2
  exit 2
fi

git -C "$REPO_ROOT" worktree prune >&2

if [ -d "$WORKTREE_DIR" ] && git -C "$WORKTREE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$WORKTREE_DIR" checkout --detach --force "$SHA" >&2
  git -C "$WORKTREE_DIR" clean -fdq >&2
else
  rm -rf "$WORKTREE_DIR"
  mkdir -p "$(dirname "$WORKTREE_DIR")"
  git -C "$REPO_ROOT" worktree prune >&2
  git -C "$REPO_ROOT" worktree add --detach "$WORKTREE_DIR" "$SHA" >&2
fi

cd "$WORKTREE_DIR" && pwd

