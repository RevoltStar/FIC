# FIC handoff

## Current base
* Branch: main; follow-up based on `a0f5ff85341e609f889342f51231f1c8e1a6de6c`.
* This snapshot accompanies `Restore session-only DE enforcement and simplify graphical scope application`.

## Current task
* Restore SessionOnly KDE/XFCE, FLY persistent enforcement/convergence and validation-only DE/DM scope. Implementation complete; no next refactor planned.

## Accepted architecture / invariants
* KDE/XFCE are SessionOnly: native apply/readback for all applicable current sessions, no physical journal/CAS/rollback or user ownership markers. Valid policy with no applicable sessions succeeds; any applicable failure fails the policy. Exclusion/disable leaves user values; periodic/session_ready retries enforcement.
* GNOME/FLY and DM retain MutationJournal, exact inverse ownership release, preflight, fsync, crash recovery and orphan refusal. Root CAS + FIC locks retain the accepted residual race with non-cooperating root writers.
* Scope apply validates enabled typed nonempty configured intent only. Required/reverse guards remain. Global checkpoint proves system reconciliation, independently of session results; session failure never undoes successful global changes.
* Scope data setter saves first. Administrative handler reloads then separately applies only its graphical submodule through PolicyExecutionPlanner, reporting saved/applied independently. Manual scope-only apply has no physical preprocessing. Graphical mutations apply their own submodule; reload_config applies both. Other mutations do not invoke graphical apply.
* FLY controls only system theme.master ScreenSaverDelay; persistent_configuration=VERIFIED/runtime_effect=NOT_VERIFIED. fly-wmfunc is a session helper, with failure classified as MandatoryGlobal runtime warning. No user theme-file writes.
* DM always enrolls an owned block even when foreign autologin is already disabled. No restart; native persistent SUCCESS/live runtime NOT_VERIFIED. KConfig Kiosk/XFCE system locking forbidden; LXQt locker Unsupported.

## Completed / changed areas
* KDE kwriteconfig5/6 and XFCE typed setters restored from e279c46; existing owner/PID/UID/procfs/topology/runtime reload and typed readback guards unchanged. FLY native helper restored; persistent journal backend re-enabled.
* SessionOnly no longer blocks global scope checkpoints. screenlock_timeout invokes joint global reconciliation before session apply; startup audit separates global verification from policy/session outcome.
* DE/DM declarations and compliance use configured validation; disable_autologin invokes existing physical coordinator. Daemon scope-save/internal submodule apply, startup/periodic/manual/reload paths updated; native DM failure diagnostics retained.
* Rollback enrollment: scope/compliance/media NotEnrolled; screenlock_timeout Supported only for GNOME/FLY physical release; no session inverse, absent global ownership permits disable. disable_autologin Supported; unknown policies Unsupported.
* Regression tests extended for native setters, KDE tool versions, sessions/new-session/partial failures, mixed scope transitions, fresh dependent apply, scoped planner/Required blocking, media/SessionOnly disable, already-disabled DM ownership, preserved global conflicts/recovery/security checks. Docs updated.

## Validation
* Docker Debian12 configure: `cmake -S /src -B /build -DFIC_TARGET_PLATFORM=debian-12` PASS; full `cmake --build /build -j4` PASS (including daemon, clients, all test targets).
* Full `ctest --test-dir /build --output-on-failure`: **174/174 PASS**, final run 72.43s. Drops DAC_OVERRIDE/DAC_READ_SEARCH; sets Git safe.directory=/src. Includes PAM, packaging, prelogin and session-agent checks.
* Targeted final regression gates: **6/6 PASS** (planner, screenlock global, KDE runtime context, rollback executor, DM transaction, DE architecture static checks).
* After the last daemon routing change: full build PASS; routing/planner/static checks **3/3 PASS**. Final Unsupported LXQt factory/static checks **2/2 PASS** after rebuild.
* Native GNOME dconf/GSettings journal ensure/shared owners/restart/release PASS: Debian12, Ubuntu24.04, ALT p11. Native DM persistent loader/journal lifecycle PASS on the same three real package snapshots. ALT GNOME initially refused stock profile/foreign databases in the harness; stock /etc/dconf was preserved in /tmp inside a disposable container to isolate the fixture, then PASS. Production guards unchanged.
* Evidence: ignored build-prelogin-validation/dm-evidence/session-followup-*. Temporary snapshots created for this run removed; preexisting native containers/images retained. No host /etc or real-session mutation.
* `git diff --check` PASS.

## Remaining / limits
* No unfinished implementation components.
* Live KDE/XFCE/FLY/GNOME Shell/DM sessions and actual package-manager erase NOT VERIFIED. Native Astra testing intentionally deferred to administrator. Mock/filesystem/native persistent evidence does not prove live runtime.
* Root CAS/locking residual race remains; no stronger atomicity guarantee claimed.
