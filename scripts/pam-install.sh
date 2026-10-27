#!/bin/bash
# Puts the Atlas step into the PAM stacks of the services you name. By default it only PRINTS what it would change.
#   atlas-pam-install [--apply] [--services "sshd sudo login"] [--no-password "sshd"] [--allow-no-break-glass]
#                     [--stage DIR] [--helper PATH]
#
# The edit is one line, `auth required pam_atlas.so`, inserted after the last auth line of the service file (after its
# `@include common-auth` on Debian/Ubuntu). A file is edited only when its stack has the expected shape:
#   - no `auth sufficient` line in the file or in the file it includes (a success there would end the stack before Atlas runs);
#   - the insertion point is ahead of the first `account` line.
# Otherwise nothing is written and the reason is printed; edit that file by hand (README, "Distributions with sufficient").
# With --apply every file is checked first, each write is atomic and read back, the first original of each file is kept in
# /var/lib/atlas/pam-backup and never overwritten, and if anything fails every file already changed is put back.
# The kill switch `touch /etc/atlas/pam-disabled` (as root) turns the module into a pass-through without touching /etc/pam.d.
# --stage DIR treats DIR as the filesystem root (tests, image builds) and needs no root.
set -euo pipefail

APPLY=0; SERVICES="sshd sudo login"; NOPW=""; NOBG=0; STAGE=""; HELPER=/usr/libexec/atlas/atlas-pam-helper
while [ $# -gt 0 ]; do case "$1" in
  --apply) APPLY=1;; --services) SERVICES="$2"; shift;; --no-password) NOPW="$2"; shift;;
  --allow-no-break-glass) NOBG=1;; --stage) STAGE="$2"; shift;; --helper) HELPER="$2"; shift;;
  *) echo "unknown option $1" >&2; exit 2;; esac; shift; done

PAMDIR="$STAGE/etc/pam.d"; BACKUP="$STAGE/var/lib/atlas/pam-backup"
MOD="pam_atlas.so"
die() { echo "atlas-pam-install: $*" >&2; exit 1; }
note() { echo "atlas-pam-install: $*"; }
[ -n "$STAGE" ] || [ "$APPLY" = 0 ] || [ "$(id -u)" = 0 ] || die "--apply must run as root"
for s in $SERVICES; do case "$s" in *[!A-Za-z0-9._-]*|"") die "bad service name $s";; esac; done

# ---- preflight --------------------------------------------------------------------------------------------------------
if [ -x "$HELPER" ]; then
  extra=(); [ "$NOBG" = 1 ] && extra+=(--allow-no-break-glass)
  [ -n "$STAGE" ] && extra+=(--config "$STAGE/etc/atlas/desktop.json" --state-dir "$STAGE/var/lib/atlas")
  "$HELPER" check ${extra[@]+"${extra[@]}"} >/dev/null || die "preflight failed (see above); nothing was changed"
else
  die "helper $HELPER not found"
fi

# Prints the new file on stdout. Return: 0 edited, 10 already installed, 1 unrecognised layout (reason on stderr).
edit_file() { # $1=service
  local f="$PAMDIR/$1" extra=""
  case " $NOPW " in *" $1 "*) extra=" no_password";; esac
  [ -f "$f" ] && [ ! -L "$f" ] || { echo "$f: missing or a symlink" >&2; return 1; }
  grep -q $'\r' "$f" && { echo "$f: CRLF line endings" >&2; return 1; }
  grep -qE "^[^#]*pam_atlas\.so" "$f" && return 10
  # Included files that carry auth lines.
  local inc; inc=$(grep -v '^[[:space:]]*#' "$f" | awk '$1=="@include"{print $2} $1=="auth"&&($2=="include"||$2=="substack"){print $3}')
  local i
  for i in $inc; do
    case "$i" in *[!A-Za-z0-9._-]*) continue;; esac
    if [ -f "$PAMDIR/$i" ] && grep -v '^[[:space:]]*#' "$PAMDIR/$i" | awk '$1=="auth"&&$2=="sufficient"{f=1} END{exit !f}'; then
      echo "$f includes $i, which has an 'auth sufficient' line: a success there ends the stack before Atlas runs" >&2; return 1
    fi
  done
  awk -v line="auth       required       $MOD$extra" '
    { rows[NR] = $0 }
    END {
      last = 0; acct = 0
      for (i = 1; i <= NR; i++) {
        s = rows[i]; if (s ~ /^[ \t]*#/ || s ~ /^[ \t]*$/) continue
        split(s, w, /[ \t]+/); k = (w[1] == "") ? 2 : 1
        if (w[k] == "auth" && w[k+1] == "sufficient") { print "an auth sufficient line ends the stack before Atlas runs: " s > "/dev/stderr"; exit 1 }
        if (w[k] == "auth" || w[k] == "-auth" || (w[k] == "@include" && w[k+1] ~ /auth/)) last = i
        if ((w[k] == "account" || w[k] == "-account") && !acct) acct = i
      }
      if (last == 0) { print "no auth line or @include to follow" > "/dev/stderr"; exit 1 }
      if (acct && acct < last) { print "auth lines after the first account line (unrecognised layout)" > "/dev/stderr"; exit 1 }
      for (i = 1; i <= NR; i++) { print rows[i]; if (i == last) print line }
    }' "$f"
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CHANGED=""; ALREADY=""; SKIPPED=""
for s in $SERVICES; do
  f="$PAMDIR/$s"
  [ -e "$f" ] || { note "$s: no $f on this system, skipped"; continue; }
  rc=0; edit_file "$s" > "$TMP/$s.new" 2> "$TMP/$s.err" || rc=$?
  case $rc in
    0) CHANGED="$CHANGED $s";;
    10) ALREADY="$ALREADY $s"; note "$s: already installed";;
    *) SKIPPED="$SKIPPED $s"; note "$s: NOT changed: $(cat "$TMP/$s.err")";;
  esac
done

if [ "$APPLY" = 0 ]; then
  for s in $CHANGED; do note "$s: would become:"; diff "$PAMDIR/$s" "$TMP/$s.new" | sed 's/^/    /' || true; done
  note "nothing written. Review the above, keep a root shell open, then run again with --apply."
  note "To do it by hand, add this line after the password check in each service file under /etc/pam.d:"
  note "    auth       required       $MOD"
  [ -z "$SKIPPED" ] || exit 1
  exit 0
fi
[ -z "$SKIPPED" ] || die "unrecognised layout for:$SKIPPED. Nothing was changed. Use --services to leave them out, or edit them by hand."
[ -n "$CHANGED$ALREADY" ] || die "none of the requested services exists in $PAMDIR"

mkdir -p "$BACKUP"
for s in $CHANGED; do
  [ -f "$BACKUP/$s.original" ] || cp -p "$PAMDIR/$s" "$BACKUP/$s.original"
  cp -p "$PAMDIR/$s" "$TMP/$s.undo"
done
APPLIED=""
rollback() {
  echo "atlas-pam-install: FAILED, restoring every file already changed" >&2
  for s in $APPLIED; do
    cat "$TMP/$s.undo" > "$PAMDIR/.$s.atlas-restore" && mv -f "$PAMDIR/.$s.atlas-restore" "$PAMDIR/$s" || echo "RESTORE FAILED for $PAMDIR/$s; original is at $BACKUP/$s.original" >&2
  done
  exit 1
}
for s in $CHANGED; do
  # Same mode and owner as the original: copy it, then overwrite the contents.
  if cp -p "$PAMDIR/$s" "$PAMDIR/.$s.atlas-new" && cat "$TMP/$s.new" > "$PAMDIR/.$s.atlas-new" && mv -f "$PAMDIR/.$s.atlas-new" "$PAMDIR/$s"; then
    APPLIED="$APPLIED $s"
  else
    rm -f "$PAMDIR/.$s.atlas-new"; rollback
  fi
done
for s in $CHANGED $ALREADY; do
  [ "$(grep -cE "^[^#]*pam_atlas\.so" "$PAMDIR/$s")" = 1 ] || { APPLIED="$CHANGED"; rollback; }
done
note "installed for:$CHANGED$ALREADY"
note "originals kept in $BACKUP; undo with atlas-pam-uninstall"
note "NEXT: keep this root shell open and test sudo / ssh from a second one before you close it."
case " $CHANGED$ALREADY " in *" sshd "*)
  note "sshd: Atlas runs in the PAM auth stack, which sshd uses for password and keyboard-interactive logins. For key-only logins use"
  note "      'AuthenticationMethods publickey,keyboard-interactive' with 'UsePAM yes' and 'KbdInteractiveAuthentication yes', and install with --no-password sshd.";; esac
exit 0
