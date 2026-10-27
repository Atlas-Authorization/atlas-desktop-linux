#!/bin/sh
# Runs INSIDE a distro container right after the package was installed. $1 = package format (deb|rpm|apk), $2 = module dir.
set -u
FMT=$1; PAMDIR=$2
fails=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1  [$2]"; fi; }

remove_pkg() {
  case "$FMT" in deb) dpkg -r atlas-desktop-mfa;; rpm) rpm -e atlas-desktop-mfa;; apk) apk del atlas-desktop-mfa;; esac
}
installed() {
  case "$FMT" in deb) dpkg -s atlas-desktop-mfa >/dev/null 2>&1;; rpm) rpm -q atlas-desktop-mfa >/dev/null 2>&1;; apk) apk info -e atlas-desktop-mfa >/dev/null 2>&1;; esac
}

check "module installed in $PAMDIR, root-owned, 0755" '[ "$(stat -c "%a %U" "$PAMDIR/pam_atlas.so")" = "755 root" ]'
check "helper root-owned and not writable by others" '[ "$(stat -c "%a %U" /usr/libexec/atlas/atlas-pam-helper)" = "755 root" ]'
check "state dir is 0700" '[ "$(stat -c %a /var/lib/atlas)" = 700 ]'
check "install changed no PAM file" '! grep -rqE "^[^#]*pam_atlas" /etc/pam.d'
check "helper without config refuses" '[ "$(printf "BEGIN alice sshd\n" | /usr/libexec/atlas/atlas-pam-helper serve)" = "DENY Atlas is not configured" ]'
check "installer preflight refuses an unenrolled machine" '! atlas-pam-install --apply --services sudo >/dev/null 2>&1'
check "installer defaults to printing only" 'atlas-pam-install >/dev/null 2>&1; ! grep -rqE "^[^#]*pam_atlas" /etc/pam.d'
check "helper is a static binary" '! ldd /usr/libexec/atlas/atlas-pam-helper 2>&1 | grep -qE "=> /"'
[ "$FMT" = apk ] || check "sync timer/unit shipped" '[ -f /usr/lib/systemd/system/atlas-sync.timer ]'
[ "$FMT" != apk ] || check "hourly job shipped" '[ -x /etc/periodic/hourly/atlas-sync ]'

# Removal is refused while a PAM file still names the module.
echo "auth required pam_atlas.so" > /etc/pam.d/atlas-pkg-test
remove_pkg >/dev/null 2>&1
check "removal refused while pam.d still uses the module" 'installed && [ -f "$PAMDIR/pam_atlas.so" ]'
rm -f /etc/pam.d/atlas-pkg-test
remove_pkg >/dev/null 2>&1
check "removal succeeds once pam.d is clean" '! installed && [ ! -f "$PAMDIR/pam_atlas.so" ] && [ ! -f /usr/libexec/atlas/atlas-pam-helper ]'

[ "$fails" = 0 ] && echo "package tests passed" || { echo "$fails failure(s)"; exit 1; }
