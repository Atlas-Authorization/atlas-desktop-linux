#!/bin/bash
# Removes the Atlas step from the PAM stacks (restores the saved original when the file is otherwise unchanged).
#   atlas-pam-uninstall [--services "sshd sudo login"] [--stage DIR] [--dry-run]
# With no --services it cleans every file in /etc/pam.d that mentions pam_atlas.so. Safe to run twice.
set -euo pipefail
DRY=0; STAGE=""; SERVICES=""
while [ $# -gt 0 ]; do case "$1" in
  --dry-run) DRY=1;; --stage) STAGE="$2"; shift;; --services) SERVICES="$2"; shift;;
  *) echo "unknown option $1" >&2; exit 2;; esac; shift; done
PAMDIR="$STAGE/etc/pam.d"; BACKUP="$STAGE/var/lib/atlas/pam-backup"; MOD="pam_atlas.so"
die() { echo "atlas-pam-uninstall: $*" >&2; exit 1; }
note() { echo "atlas-pam-uninstall: $*"; }
[ -n "$STAGE" ] || [ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || die "must run as root (or use --dry-run / --stage)"
[ -n "$SERVICES" ] || SERVICES=$(cd "$PAMDIR" && grep -l "$MOD" -- * 2>/dev/null | tr '\n' ' ' || true)
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
rc_all=0
for s in $SERVICES; do
  f="$PAMDIR/$s"
  [ -f "$f" ] || continue
  grep -qE "^[^#]*pam_atlas\.so" "$f" || { note "$s: not installed"; continue; }
  awk -v m="$MOD" '!($0 !~ /^[ \t]*#/ && index($0, m) > 0)' "$f" > "$TMP/$s.stripped"
  if [ -f "$BACKUP/$s.original" ] && cmp -s "$TMP/$s.stripped" "$BACKUP/$s.original"; then how="restored the original"; else how="removed the Atlas line"; fi
  if [ "$DRY" = 1 ]; then note "[dry-run] $s: would have $how"; continue; fi
  if cp -p "$f" "$PAMDIR/.$s.atlas-new" && cat "$TMP/$s.stripped" > "$PAMDIR/.$s.atlas-new" && mv -f "$PAMDIR/.$s.atlas-new" "$f" && ! grep -qE "^[^#]*pam_atlas\.so" "$f"; then
    note "$s: $how"
  else
    rm -f "$PAMDIR/.$s.atlas-new"; echo "atlas-pam-uninstall: could not clean $f; edit it by hand and delete the $MOD line" >&2; rc_all=1
  fi
done
exit $rc_all
