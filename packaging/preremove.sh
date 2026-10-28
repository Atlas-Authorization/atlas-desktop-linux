#!/bin/sh
# Removing the module while a PAM stack still names it would make every login on that service fail, root included.
# So removal is refused until the stacks are clean. Upgrades pass ($1 = upgrade on deb, 1 on rpm).
case "${1:-}" in upgrade|failed-upgrade|deconfigure|1) exit 0;; esac
[ "${ATLAS_FORCE_REMOVE:-}" = 1 ] && exit 0
refs=$(grep -lE '^[^#]*pam_atlas\.so' /etc/pam.d/* 2>/dev/null | tr '\n' ' ')
if [ -n "$refs" ]; then
  case "${1:-}" in
    [0-9]*.*)  # apk passes the version and ignores a failing pre-deinstall: it cannot veto, so clean the stacks rather than leave them naming a missing module
      echo "atlas: apk cannot refuse a removal; removing the Atlas step from: $refs" >&2
      atlas-pam-uninstall >&2 || true
      refs=$(grep -lE '^[^#]*pam_atlas\.so' /etc/pam.d/* 2>/dev/null | tr '\n' ' ')
      [ -z "$refs" ] || echo "atlas: could not clean $refs; edit by hand and delete the pam_atlas.so line before the next login" >&2
      exit 0;;
  esac
  echo "atlas: refusing to remove: these PAM files still use pam_atlas.so: $refs" >&2
  echo "atlas: run 'atlas-pam-uninstall' first (or set ATLAS_FORCE_REMOVE=1 if you have already fixed them by hand)." >&2
  exit 1
fi
if [ -d /run/systemd/system ]; then
  systemctl disable --now atlas-sync.timer >/dev/null 2>&1 || true
fi
exit 0
