# Static hardware and udev policy scope

### Current base

Branch `main`; pre-task base `3539deb40d9b890bf3f13e480116f9001a7d152b`.

### Current task

Prevent explicit CPU, board and memory policy from breaking generated udev rules while preserving permanent-device checks and desired/active activation behavior.

### Accepted architecture / invariants

`DevicePolicyCompiler` generates rules for udev events in `usb`, `usbmisc`, `pci` and `block`. Direct placement/identity rules outside that scope are omitted. A non-udev ancestor inside `/devices/` can still supply inherited `children_control` to future udev descendants; static hardware is omitted from every generated rule section. Static policy remains in the DB and separate permanent-device scan. Unsafe identity for in-scope udev devices remains a compilation error.

### Completed

Compiler scope filter, regression matrix for CPU/board/memory and all four levels, unchanged rule bytes after static updates, later USB compilation/activation, weak USB identity failure, non-udev ancestor inheritance and static permanent snapshot. A focused disposable Docker IPC gate exercises real `fic-dick` update and activation, plus a missing permanent CPU scan. `fic-dick/README.md` describes the boundary.

### Changed areas

`fic-dick/src/policy/DevicePolicyCompiler.cpp`, `fic-dick/README.md`, `tests/fic-dick/policy/DevicePolicyCompilerTests.cpp`, `tests/fic-dick/device/DeviceTreeSnapshotTests.cpp`, `tests/integration/device-control/static_hardware_ipc_gate.py`.

### Validation

Native `fic-dick` and affected unit targets built. Native compiler, snapshot, category, permanent incident and device-control static CTests passed. Permanent incident integration passed outside sandbox because AF_UNIX bind is denied inside it. Ubuntu 26 Docker builder passed compiler, snapshot, category and permanent incident integration CTests. The focused Docker IPC gate passed with a test-only lifecycle and udevadm fixture. `git diff --check` passed.

### Remaining

The pre-existing broad `category_ipc_gate.py` cannot reach its tests on this checkout: its lifecycle fixture lacks `INSTALLED` admission; this task did not change that separate gate. The focused Docker gate checks missing-CPU detection and incident request fields, while the existing incident integration test checks delivery separately. Physical udev/sysfs enforcement, host activation and full native distro matrix were not run.
