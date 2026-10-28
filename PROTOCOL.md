# Protocol

This agent speaks the same workstation protocol as the Windows credential provider and the macOS authorization plugin
(`/v1/client/desktop_mfa/*`, signed with the device key). The specification is `PROTOCOL.md` in the macOS agent
directory of the Atlas desktop sources, and the reference vectors are `helper/internal/agent/testdata/protocol-vectors.json`;
the Go tests reproduce them (bundle MAC, ECIES opening, scrypt PIN, TOTP, signed message).

Linux differences:

- `platform` is `linux` at enrolment.
- One software ES256 key serves both signing and opening offline bundles (ECDH), so no `seal_public_key` is sent.
- Config lives in `/etc/atlas/desktop.json`; the device key, bundle MAC key and offline state in `/var/lib/atlas` (root only, mode 0700).
- The PAM module and the helper talk over a socketpair using the line protocol documented in `pam/atlas_pam_core.h`.
