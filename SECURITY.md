# Security notes and platform limits

What this protects: an attacker with a stolen password cannot log in to sshd, sudo, su, login or the display manager on an enrolled
machine without approving a push (number matching) or entering the user's authenticator code.

What it does not do, honestly:

- **The device key is a software key.** It lives in `/var/lib/atlas/device.key` (root-only, mode 0600, directory 0700) because Linux has no
  per-machine hardware key store that every machine offers. Anyone who becomes root on the machine can copy it and impersonate the
  device to Atlas (but still cannot answer a push or produce a code for the user). Sealing the key to a TPM 2.0
  (`tpm2_createprimary` + a persistent non-exportable ES256 key, used through `/dev/tpmrm0` with `tpm2-tss`) would close that; it needs a TPM on
  every machine, a `tpm2-tss` dependency in the helper and a recovery story for firmware resets, so it is not in this release.
- **Root is the trust boundary.** A root attacker can disable the module (`pam.d`, the kill switch) or replace the helper. The module refuses
  a helper that is not root-owned or sits in a directory others can write.
- **A user with local root can skip MFA for themselves.** That is true of every PAM-based product.
- **Key-only ssh (`publickey` alone) never runs the PAM auth stack.** Use `AuthenticationMethods publickey,keyboard-interactive` and
  `no_password`, or the module is not consulted.
- **No passkey/security-key factor on Linux yet.** The factors are push, TOTP and offline unlock; `passkey` is filtered out of what the gate offers.
- **Screen savers and polkit** prompts use their own PAM services (`xscreensaver`, `polkit-1`, `gdm-password`); add the line to those files to cover them.

Hardening in place: fail-closed on every error and timeout; the module sanitises user and service names before they reach the helper; the helper
re-validates every line (length, charset) and prints nothing from the network unfiltered; secrets (codes, PINs) are wiped after use and never logged;
all state files are re-checked for ownership and mode on every read; offline attempts are serialised with a file lock so two concurrent logins cannot
share one code or dodge the failure counter; HTTPS only, no redirects, 15 s timeout; the helper environment is `PATH` only.

Report vulnerabilities to security@atlasauth.net.
