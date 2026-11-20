# Debian 13 empty-password PAM follow-up

Branch main. Base `16d51a63`. The policy remains Debian 13 only. Runtime
apply still mutates only its exact journal-bound slot.

- The verified generated Winbind Primary is admitted with its packaged
  arguments, trusted module, and Unix and Winbind success jumps to the
  same generated permit barrier. Unix success skips Winbind, which can
  modify the PAM token and identity. The general analyzer, ownership,
  rollback and package scripts retain their existing contracts.
- The generated homed and SSSD optional smart-card graphs are rejected
  with no PAM or journal writes. The required smart-card profile was
  inspected. No Winbind AD or homed-user authentication was run.
- Real 0.1.0 DEBs from `0e4d014a` were upgraded to 0.1.1 from
  `16d51a63` and to the follow-up in separate Debian 13 containers.
  A manual rule inside generated common-auth was preserved. The upgrade
  stayed half-configured with the INSTALLING fence, no selected hook,
  a neutral new slot and unchanged old slots, config and journal pair.
  Restoring the known generated file and retrying dpkg configuration
  completed installation. This is the existing package contract.
- The final native gate exercises local PAM and online LDAP/SSSD with
  Winbind and faillock enabled, exact ownership, unsupported control
  flow, reinstall, and refusal of detach while a physical reference
  remains. The retry uses the documented restricted daemon startup.
- Four focused Debian 13 CTests passed. The native ownership executable
  passed within the package gate.

Evidence in `/tmp/fic-d13-followup.ugs23n9o/`: `profiles.log`,
`baseline.log`, `upgrade-baseline.log`, `upgrade-final.log`,
`fixed-build.log` and `native-verified.log`. Native logs point to
durable local evidence under `build-package-lifecycle/`. The runtime
fixture copies two newly packaged SSH snippet symlink targets as regular
files with identical bytes because the independent SSH inventory
otherwise refuses rollback all. Production SSH checks were unchanged.

Reproduction is in `tests/integration/pam-empty-password/README.md`.
The upgrade and detach repair contracts are in `docs/package-lifecycle.md`.
