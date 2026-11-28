# DE/DM scope validation follow-up

Branch main; base 361b48ea7cce6ff3dbcbaad88efda4a29b789bbc.

Current task: preserve legacy ENABLE behavior for ordinary defaulted policies,
while retaining nonempty-scope checks for the two controlled DE/DM policies.

Accepted contract: only policies opting into enabled-value validation deserialize
the current stored value for that check. An absent value supplies the logical
default directly. No-default policies retain explicit-value validation.
`enable()` and `setPolicyValue()` remain the production configuration paths;
GUI target-state preflight and apply/rollback semantics are unchanged.

Completed: opted-in Policy validation, production `enable()` moved into the
existing registry mutation translation unit so it can be exercised directly.
Tests call actual enable/setPolicyValue on both controlled policies and verify
failure diagnostics and unchanged config bytes. GRUB regression was RED before
the fix and GREEN afterward, including absent and malformed stored values.

Validation: the GRUB regression failed on the old code before the fix and
passed afterward. `fic` and `fic-gui` built. All seven focused CTests passed:
GRUB, module registry, DE scope, policy save/dependency, GUI descriptor/service,
and execution planner. Final GRUB, registry and policy save tests also passed in
disposable Ubuntu 26 Docker. The Ubuntu 24 builder image lacks Qt runtime, so
the GUI-linked test was run in Ubuntu 26. `git diff --check` passed.

No host system policies or package lifecycle were run. Full native distro matrix
and live daemon IPC were not run. One local completion commit remains; no push.
