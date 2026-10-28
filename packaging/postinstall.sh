#!/bin/sh
# Never edits /etc/pam.d. It only enables the sync timer when systemd is there and says what to do next.
chmod 700 /var/lib/atlas 2>/dev/null || true
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable atlas-sync.timer >/dev/null 2>&1 || true
fi
cat <<'MSG'
Atlas desktop MFA is installed but NOT active: no PAM stack has been changed.
  1. atlas-enroll --instance-url https://AUTH_HOST --publishable-key pk_... --instance-id ins_... --code dsk_... --break-glass YOUR_ADMIN
  2. atlas-pam-install                 (prints the exact change; add --apply when you are happy)
  Keep a root shell open while you test. Kill switch: touch /etc/atlas/pam-disabled
MSG
exit 0
