# Rolling back

A PAM mistake can lock everyone out. In order of speed:

1. **Kill switch (no editing).** As root: `touch /etc/atlas/pam-disabled`. `pam_atlas.so` then returns "ignore" and the stack behaves
   as if it were not there. It only counts when the file is a regular file, owned by root and not writable by group or others.
   Remove the file to switch Atlas back on.
2. **Undo the edit.** `atlas-pam-uninstall` restores each service file from `/var/lib/atlas/pam-backup/<service>.original`
   when nothing else changed in it, otherwise it deletes just the `pam_atlas.so` line.
3. **By hand.** Delete the `auth required pam_atlas.so` line from the files in `/etc/pam.d/`. The first original of each edited
   file is in `/var/lib/atlas/pam-backup/`.
4. **Locked out of everything.** Boot to single-user/rescue mode (or mount the disk elsewhere) and do step 3, or `touch /etc/atlas/pam-disabled` on the mounted root.

Always keep one root shell open while you change or test a stack, and test `sudo` and `ssh` from a second terminal before closing it.
The package refuses to uninstall while a PAM file still names the module (it would break logins); remove the lines first.

A **break-glass account** (`atlas-enroll --break-glass NAME`) skips the Atlas step but still needs its password. The installer refuses to run without one.

## Offline use

An enrolled machine keeps a sealed offline bundle (valid for the policy's grace period, default 72 hours). While the server is
unreachable a user enters the offline PIN (if the policy needs one) and the 6-digit code from their authenticator app. Five wrong answers
lock offline unlock for 15 minutes; a code can be used once; a clock moved back is refused.
