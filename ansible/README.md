# Ansible role `atlas_desktop_mfa`

Installs the package, enrols the machine, and (only when `atlas_apply_pam: true`) edits the PAM stacks through `atlas-pam-install`, which keeps
backups and refuses layouts it does not recognise.

```yaml
- hosts: workstations
  become: true
  roles:
    - role: atlas_desktop_mfa
      vars:
        atlas_package_url: https://github.com/Atlas-Authorization/atlas-desktop-linux/releases/download/v0.1.0/atlas-desktop-mfa_0.1.0_amd64.deb
        atlas_instance_url: https://auth.example.com
        atlas_publishable_key: pk_live_xxx
        atlas_instance_id: ins_xxx
        atlas_enrol_code: "{{ vault_enrol_codes[inventory_hostname] }}"   # one code per machine
        atlas_offline_pin: "{{ vault_offline_pin }}"
        atlas_break_glass_accounts: [emergency-admin]
        atlas_apply_pam: false      # first run: look at the preview, then set true
```

Roll out to a few hosts first, with a second session open. `ROLLBACK.md` in the package explains the kill switch.
