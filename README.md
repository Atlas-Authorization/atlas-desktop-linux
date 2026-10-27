# Atlas desktop MFA for Linux

A PAM module (`pam_atlas.so`) and a small agent that add a second factor to Linux logins: **sshd, sudo, su, login, GDM and LightDM**.
The factors are the ones Atlas offers on Windows and macOS: push with number matching, the user's authenticator code (TOTP), and an
offline unlock (PIN plus code) for when the machine cannot reach Atlas. The agent speaks the same protocol as the Windows and
macOS agents, so one policy (`/v1/desktop_mfa/policy`) and one enrolment-code flow cover all three.

```
auth  required  pam_unix.so      # your existing password check (sets the password as PAM_AUTHTOK)
auth  required  pam_atlas.so     # Atlas: runs only after the password was accepted; a wrong password never sends a push
```

## Install

Packages for Debian/Ubuntu (`.deb`), Fedora/RHEL/Rocky (`.rpm`) and Alpine (`.apk`), amd64 and arm64, are attached to each release.

```sh
sudo dpkg -i atlas-desktop-mfa_*.deb          # or: sudo rpm -i atlas-desktop-mfa-*.rpm  /  sudo apk add --allow-untrusted atlas-desktop-mfa-*.apk
```

Installing changes **nothing** in `/etc/pam.d`.

1. In the Atlas dashboard (Desktop MFA) turn the policy on and create an enrolment code for the user. Pick or create a dedicated local admin
   to be the **break-glass account**.
2. Enrol (as root):
   ```sh
   sudo atlas-enroll --instance-url https://auth.example.com --publishable-key pk_live_... --instance-id ins_... \
        --code dsk_... --break-glass emergency-admin [--users alice,bob]
   ```
   It creates the device key, asks for an offline PIN (6-12 digits), prints the offline authenticator URI once, and syncs.
3. Preview, then apply (keep a root shell open):
   ```sh
   sudo atlas-pam-install --services "sshd sudo login"            # prints the diff only
   sudo atlas-pam-install --services "sshd sudo login" --apply
   ```
   The installer checks the config, the device key and the break-glass account first; edits a service file only when its stack has the
   expected shape; keeps the first original in `/var/lib/atlas/pam-backup`; verifies every write and restores everything if one fails.
4. Test `sudo` and `ssh` from a second terminal before closing the root shell.

Undo: `sudo atlas-pam-uninstall`, or `touch /etc/atlas/pam-disabled` (kill switch). See `ROLLBACK.md`.

### Distributions where the password check is `sufficient`

Fedora/RHEL put `auth sufficient pam_unix.so` in `system-auth`; a success there ends the stack, so Atlas never runs. The installer detects this
and refuses to touch such a service. Use an authselect custom profile or list `pam_unix.so` as `required` in the service file itself
(`packaging/pam.d-snippets/display-managers`).

### ssh

Password and keyboard-interactive logins go through the PAM auth stack and work as above. Key-only logins do not run it. For keys plus Atlas set
`AuthenticationMethods publickey,keyboard-interactive`, `UsePAM yes`, `KbdInteractiveAuthentication yes` and install with `--no-password sshd`.

### Module arguments

`helper=/path` (the helper must still be root-owned), `no_password` (run without a password from an earlier module).

## Pieces

| | |
|---|---|
| `pam/` | `pam_atlas.so` (C, Linux-PAM) and the conversation logic shared with the macOS module; unit and integration tests |
| `helper/` | Go: `atlas-pam-helper serve` (one process per login), `atlas-enroll`, `atlas-sync` (hourly via a systemd timer, or busybox periodic on Alpine) |
| `scripts/` | `atlas-pam-install`, `atlas-pam-uninstall` |
| `packaging/` | nfpm config for deb/rpm/apk, systemd units, pam.d snippets |
| `ansible/` | role `atlas_desktop_mfa` |

Files: `/etc/atlas/desktop.json` (config), `/var/lib/atlas/` (device key, bundle MAC key, offline state; root only), `/etc/atlas/pam-disabled` (kill switch).

## Build and test

CI builds on Debian, Fedora and Alpine containers (amd64 and arm64): `make test`, the PAM integration test (`sudo make itest`, the real PAM stack
with a fake helper), the installer tests, and package install/remove tests. See `.github/workflows/ci.yml`. Read `SECURITY.md` for the limits (software device key; no TPM yet).

MIT licensed.
