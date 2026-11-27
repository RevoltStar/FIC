# DM inventory optimization

Branch main. Task base a0fae90b073321ea8bb07c00d664d033ac91f19f.

## Accepted invariants

Three tasks: client-side unit-file listing, package-independent observational
compliance, then research only for show optimization. Installed-manager
autologin scope, trust, transaction rechecks, SDDM package-version proof,
ownership/rollback, prelogin IPC/timeouts remain.

## Completed

Task 1 changes only the unit-file argv to systemctl --root=/ list-unit-files.
Running/loaded unit and logind queries remain live. The shipped fic.service
has no RootDirectory, PrivateMounts or alternate unit filesystem. Custom
mount/root/unit lookup overrides require separate validation.

Native systemd fixtures compare all names/states including runtime, generated,
transient, aliases, masks, templates and concrete instances. Fixtures and
evidence are in tests/integration/dm-inventory/. ALT258, Ubuntu24 systemd255
and Ubuntu26 systemd259 passed. Debian12/13 images are still downloading APT
indexes; native equivalence is not claimed for them yet.

Task 1 target build passed. DM transaction suite passed in root Ubuntu26
container; five targeted planner/save/static checks passed. Logs /tmp/fic-dm-opt/.
Versioned upstream v252/255/257/258/259 sources were read: arg_root selects
client-side enumeration; client and manager use unit_file_get_list.

## Remaining

Finish task 2 and targeted regression; task 3 research report. Retry/record
Debian native checks if images become available. No full CI or host mutations.
