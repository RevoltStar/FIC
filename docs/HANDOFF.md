# Current working state

## Current base
* main, Ubuntu task parent548286e4d556dd32fc919223ccfb8bfae39a7ee4. No push.

## Current task
* Attachment0632096f-d7d8-4bd3-a9bf-c6408faf409b: Ubuntu24/26 verified SSH socket activation. Exactly two commits A audit, B implementation. A contains only fixtures/docs/CI guard; B must follow autonomously, no checkpoint-only stop.

## Accepted bounded contract
* docs/ubuntu-ssh-socket-activation-spec.md records native observations and concrete B sequence/map. Existing Debian engine/CAS/ownership/mutex/Prepared/A-B-C-P/receipt reused. M1/package/schema/global coordinator/new snapshot engine forbidden.
* Normal socket enabled+active/service disabled+inactive supported by protected normal loopback trigger. Service-only/disabled socket fails, no enable/start/unmask/reset-failed by product.
* Generator, loaded Listen and actual listener are distinct; daemon-reload alone leaves old kernel sockets. PID1 socket inode must be inherited by actual sshd; IPv4/v6 exact full set, no stale controlled listener.
* Native -T/-t fail255 without /run/sshd on both OS. B may prepare only missing stock root:root0755 runtime directory after positive unit/closure/ownership checks; never repair/adopt unsafe existing object. No secret-key test workaround or hidden service start.
* One effective port, <=16 locally triggerable literal endpoints; safe Description/CPUWeight service overrides, Description socket; native output/loaded/kernel proofs, negative Include closure unchanged. Unknown generator masks/overrides refuse.
* Narrow internal Ubuntu-specific engine profile/hook may accept inactive service+exact ssh.socket trigger; public generic/default/Debian guarantees unchanged. Ubuntu hook performs no copy/mount, all snapshot/observer/cleanup stays in same engine.
* Active socket rollback may safe-refuse before unproven release activation; offline service+socket allow ownership-only release with repeated checks/no runtime claim. No schema/large recovery redesign.

## Completed
* Native audit scripts tests/integration/ssh-ubuntu-socket-research and condensed sanitized evidence.21 scenarios PASS each: versions/API, normal inactive/active, inherited inode, Port caches/reload/restart under held connection, AF_INET/6/default outputs, nested Include, protected input vs old-FD persistent mutation, stale loaded after cleanup, inactive/failed/disabled socket, absent runtime dir.
* Ubuntu24 openssh1:9.6p1-3ubuntu13.20/systemd255.4-1ubuntu8.18; Ubuntu26 openssh1:10.2p1-2ubuntu3.8/systemd259.5-0ubuntu3.4. Common WSL2 kernel6.6.87.2. No host SSH/PAM touched.
* Guard self-test PASS; shell syntax PASS; root CMake adds opt-in-free safe guard CTest. Production unchanged at A.

## Next
* Commit A exact title test(ssh): establish Ubuntu socket activation native contract, then implement B exact title feat(ssh): implement verified Ubuntu socket activation. Must not stop after A. Audit PASS is not production completion.
* Implement platform mode/generator trust catalog, typed socket reader and narrow internal hook, Ubuntu lifecycle/inode proofs/rate budget/receipt, Ssh integration and offline release. Then native classes/matrix + Debian/provenance/generic/full D12 gates; docs/TODO/HANDOFF final completion. No extra commits or push.
* Generic socket Exec commands use legacy a(sasbttttuii) arrays, require empty; service still uses Ex forms. Listen a(ss) retains all endpoints (systemctl show repeats Listen lines).
* Generated normal file /run/systemd/generator/ssh.socket.d/addresses.conf; default any/wildcard22 has no output. RO native generator/PID1 sees protected2288 despite persistent2299 via oldFD; cleanup does not invalidate manager cache.

## Environment
* Docker fic-ssh-audit:{ubuntu2404,ubuntu2604,debian12,debian13,alt-p11}. Runtime no host binds/network/ports, private namespaces/PID1. Audit runner exports build-ubuntu-socket-research/<row>/report.json/container.json/journal; fixture keys remain inside disposable image.
* M1 remains frozen. Module/native test runner allowed; no fake Installed/full daemon/PAM/VM claims.
