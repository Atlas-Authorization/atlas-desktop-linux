#!/bin/bash
# Tests of atlas-pam-install / atlas-pam-uninstall against a staged filesystem (no root, nothing real is touched).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; SCRIPTS="$HERE/../../scripts"
fails=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1  [$2]"; fi; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
printf '#!/bin/sh\nexit 0\n' > "$T/helper-ok"; printf '#!/bin/sh\necho "check failed: no break-glass" >&2\nexit 1\n' > "$T/helper-bad"; chmod +x "$T/helper-ok" "$T/helper-bad"

new_stage() {
  S="$(mktemp -d "$T/stage.XXXXXX")"; mkdir -p "$S/etc/pam.d" "$S/etc/atlas" "$S/var/lib/atlas"
  cat > "$S/etc/pam.d/common-auth" <<'X'
auth	[success=1 default=ignore]	pam_unix.so nullok
auth	requisite			pam_deny.so
auth	required			pam_permit.so
auth	optional			pam_cap.so
X
  cat > "$S/etc/pam.d/sshd" <<'X'
# PAM configuration for the Secure Shell service
@include common-auth
account    required     pam_nologin.so
@include common-account
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
@include common-session
@include common-password
X
  cat > "$S/etc/pam.d/sudo" <<'X'
#%PAM-1.0
session    required   pam_env.so readenv=1 user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive
X
  cat > "$S/etc/pam.d/login" <<'X'
auth       optional   pam_faildelay.so  delay=3000000
auth       requisite  pam_nologin.so
@include common-auth
auth       optional   pam_group.so
account    required   pam_access.so
@include common-account
X
  # RHEL style: sufficient pam_unix ends the stack before our line could run.
  cat > "$S/etc/pam.d/system-auth" <<'X'
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok
auth        required      pam_deny.so
X
  cat > "$S/etc/pam.d/su-rhel" <<'X'
auth		include		system-auth
account		include		system-auth
X
  chmod 640 "$S/etc/pam.d/sshd"
}
inst() { "$SCRIPTS/pam-install.sh" --stage "$S" --helper "$T/helper-ok" "$@"; }
uninst() { "$SCRIPTS/pam-uninstall.sh" --stage "$S" "$@"; }
n_lines() { grep -cE '^[^#]*pam_atlas\.so' "$S/etc/pam.d/$1"; }

new_stage
cp -r "$S" "$T/pristine"
inst --services "sshd sudo login" >/dev/null
check "default run only prints: nothing written" 'diff -r "$S/etc/pam.d" "$T/pristine/etc/pam.d" >/dev/null'
inst --services "sshd sudo login" | grep -q 'would become' && ok "dry output shows the diff" || bad "dry output shows the diff"

inst --apply --services "sshd sudo login" >/dev/null
check "sshd edited exactly once" '[ "$(n_lines sshd)" = 1 ]'
check "atlas line follows common-auth in sshd" 'awk "/common-auth/{a=NR} /pam_atlas/{b=NR} END{exit !(b==a+1)}" "$S/etc/pam.d/sshd"'
check "atlas line is ahead of account in sshd" 'awk "/pam_atlas/{b=NR} /^account/{c=NR; if(!d)d=NR} END{exit !(b<d)}" "$S/etc/pam.d/sshd"'
check "sudo and login edited once" '[ "$(n_lines sudo)" = 1 ] && [ "$(n_lines login)" = 1 ]'
check "login line goes after the last auth line" 'awk "/pam_group/{a=NR} /pam_atlas/{b=NR} END{exit !(b==a+1)}" "$S/etc/pam.d/login"'
check "file mode preserved (640)" '[ "$(stat -c %a "$S/etc/pam.d/sshd")" = 640 ]'
check "originals backed up" '[ -f "$S/var/lib/atlas/pam-backup/sshd.original" ] && cmp -s "$S/var/lib/atlas/pam-backup/sshd.original" "$T/pristine/etc/pam.d/sshd"'
inst --apply --services "sshd sudo login" >/dev/null
check "second install is a no-op" '[ "$(n_lines sshd)" = 1 ]'
check "backup keeps the FIRST original" 'cmp -s "$S/var/lib/atlas/pam-backup/sshd.original" "$T/pristine/etc/pam.d/sshd"'

uninst >/dev/null
check "uninstall restores the exact originals" 'diff -r "$S/etc/pam.d" "$T/pristine/etc/pam.d" >/dev/null'
uninst >/dev/null
check "uninstall twice is fine" '[ "$(n_lines sshd)" = 0 ]'

# no_password argument for key-only ssh
inst --apply --services sshd --no-password sshd >/dev/null
check "no_password argument written" 'grep -q "pam_atlas.so no_password" "$S/etc/pam.d/sshd"'
uninst >/dev/null

# A file changed by someone else after install: only our line is removed.
inst --apply --services sudo >/dev/null
echo "# local change" >> "$S/etc/pam.d/sudo"
uninst >/dev/null
check "uninstall keeps unrelated edits" 'grep -q "local change" "$S/etc/pam.d/sudo" && [ "$(n_lines sudo)" = 0 ]'

# sufficient layouts are refused, and nothing changes (all-or-nothing)
new_stage; cp -r "$S" "$T/pristine2"
inst --apply --services "sshd su-rhel" >"$T/err" 2>&1; rc=$?
check "sufficient via include is refused" '[ $rc -ne 0 ] && grep -q sufficient "$T/err"'
check "refusal leaves every file untouched" 'diff -r "$S/etc/pam.d" "$T/pristine2/etc/pam.d" >/dev/null'

# preflight failure blocks everything
new_stage
"$SCRIPTS/pam-install.sh" --stage "$S" --helper "$T/helper-bad" --apply --services sshd >/dev/null 2>&1; rc=$?
check "failed preflight changes nothing" '[ $rc -ne 0 ] && [ "$(n_lines sshd)" = 0 ]'

# bad names
inst --apply --services "../etc/passwd" >/dev/null 2>&1; rc=$?
check "path-like service name refused" '[ $rc -ne 0 ]'

[ "$fails" = 0 ] && echo "install script tests passed" || { echo "$fails failure(s)"; exit 1; }
