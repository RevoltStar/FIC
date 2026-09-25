#!/usr/bin/env python3

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def field(profile: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}:\s*(.+)$", profile, re.MULTILINE)
    require(match is not None, f"PAM profile has no {name} field")
    return match.group(1).strip()


def optional_field(profile: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}:\s*(.+)$", profile, re.MULTILINE)
    return "" if match is None else match.group(1).strip()


def function_body(script: str, name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{\n(?P<body>.*?)^\}}$",
        script,
        re.MULTILINE | re.DOTALL,
    )
    require(match is not None, f"packaging builder has no function {name}")
    return match.group("body")


PERMANENT_HOOKS = (
    "fic-faillock-hook-preauth",
    "fic-faillock-hook-authfail",
    "fic-faillock-hook-authsucc",
    "fic-faillock-hook-account",
)
AUTH_HOOKS = PERMANENT_HOOKS[:3]
LEGACY_POLICY_PROFILES = (
    "fic-faillock-notify",
    "fic-faillock-preauth-required",
    "fic-faillock-authsucc",
    "fic-pwquality",
    "fic-pwhistory",
)

# Step 5B managed password hook profiles: package payload, attached only
# through an explicit administrator pam-auth-update selection, never by the
# package itself. The history hook is a dual-stack profile: one selection
# record, two generated includes (Password and Password-Initial).
PASSWORD_HOOKS = ("fic-password-quality-hook", "fic-password-history-hook")
PASSWORD_HOOK_TARGETS = ("fic-password-quality", "fic-password-history",
                         "fic-password-history-initial")


def hook_target(hook: str) -> str:
    return hook.replace("fic-faillock-hook-", "fic-faillock-")


def sandbox_pam_paths(script_text: str, pam_state: Path, pam_d: Path) -> str:
    """Redirect the standard pam-auth-update state paths of a generated
    maintainer script into a test sandbox so the host is never touched."""
    require("/var/lib/pam" in script_text and "/etc/pam.d" in script_text,
            "generated script lost the standard pam-auth-update state paths")
    return (script_text
            .replace("/var/lib/pam", str(pam_state))
            .replace("/etc/pam.d", str(pam_d)))


def canonical_include(facility: str, target: str) -> str:
    """Canonical pam-auth-update generated include rule for a hook target."""
    return f"{facility}\t\t\t\tinclude\t\t\t\t{target}\n"


def write_attached_pam_state(pam_state: Path, pam_d: Path) -> None:
    """Seed the sandbox with the standard pam-auth-update state of an
    installed package: all four permanent hook profiles selected and the
    common-* stacks regenerated (Module: records plus active, correctly
    facilitated include lines)."""
    pam_state.mkdir(parents=True, exist_ok=True)
    pam_d.mkdir(parents=True, exist_ok=True)
    (pam_state / "auth").write_text(
        "".join(f"Module: {hook}\ninclude {hook_target(hook)}\n"
                for hook in AUTH_HOOKS),
        encoding="utf-8")
    (pam_state / "account").write_text(
        f"Module: {PERMANENT_HOOKS[3]}\n"
        f"include {hook_target(PERMANENT_HOOKS[3])}\n",
        encoding="utf-8")
    (pam_d / "common-auth").write_text(
        "".join(canonical_include("auth", hook_target(hook))
                for hook in AUTH_HOOKS),
        encoding="utf-8")
    (pam_d / "common-account").write_text(
        canonical_include("account", hook_target(PERMANENT_HOOKS[3])),
        encoding="utf-8")


def write_selected_password_hooks(pam_state: Path, pam_d: Path,
                                  quality: bool, history: bool) -> None:
    """Seed the sandbox with an arbitrary administrator selection of the
    Step 5B password hook profiles (package payload): exact "Module:
    <profile>" records in the per-facility password state file plus the
    active, correctly facilitated includes in the generated common-password
    stack (the history hook is dual-stack, so its selection regenerates
    both includes)."""
    lines = ""
    stack_lines = ""
    if quality:
        lines += "Module: fic-password-quality-hook\ninclude fic-password-quality\n"
        stack_lines += canonical_include("password", "fic-password-quality")
    if history:
        lines += "Module: fic-password-history-hook\ninclude fic-password-history\n"
        stack_lines += (canonical_include("password", "fic-password-history") +
                        canonical_include("password",
                                          "fic-password-history-initial"))
    (pam_state / "password").write_text(lines, encoding="utf-8")
    (pam_d / "common-password").write_text(stack_lines, encoding="utf-8")


def pam_state_digest(pam_state: Path, pam_d: Path) -> str:
    """Stable digest of every sandboxed PAM state element; used to prove the
    generated proof function is strictly read-only."""
    import hashlib
    digest = hashlib.sha256()
    for directory in (pam_state, pam_d):
        if not directory.is_dir():
            continue
        for element in sorted(directory.rglob("*")):
            digest.update(str(element.relative_to(directory)).encode())
            if element.is_file():
                digest.update(element.read_bytes())
    return digest.hexdigest()


def read_pam_state(pam_state: Path, pam_d: Path) -> tuple[str, str]:
    state = "".join(
        (pam_state / name).read_text(encoding="utf-8") + "\n"
        for name in ("auth", "account", "password")
        if (pam_state / name).is_file())
    stack = "".join(
        (pam_d / name).read_text(encoding="utf-8") + "\n"
        for name in ("common-auth", "common-account", "common-password")
        if (pam_d / name).is_file())
    return state, stack


def stateful_pam_auth_update_fake() -> str:
    """POSIX-sh simulator of pam-auth-update. Selection state lives in
    $FAKE_PAM_STATE/{auth,account,password} as "Module: <profile>" blocks;
    each run regenerates active, correctly facilitated include lines into
    $FAKE_PAM_D/common-{auth,account,password}. The password facility
    models the Step 5B dual-stack hook profiles: the quality hook
    generates "password include fic-password-quality", the history hook
    generates both "password include fic-password-history" and the
    Password-Initial equivalent "password include
    fic-password-history-initial".
    Failure injection: FAKE_PAU_REMOVE_FAILS (detach failure),
    FAKE_PAU_PARTIAL + FAKE_PAU_PARTIAL_HOOKS (detach fails after a real
    partial mutation), FAKE_PAU_ENABLE_FAILS (faillock hook recovery
    failure), FAKE_PAU_PASSWORD_ENABLE_FAILS (password hook recovery
    enable failure after rc=0 for the faillock recovery),
    FAKE_PAU_PASSWORD_MALFORMED (rc=0 but the regenerated quality include
    is deliberately not a valid active include rule, to exercise the
    strict resulting-state proof after rc=0), FAKE_PAU_MALFORMED
    (commented | wrong-facility: the regenerated auth hook lines are
    deliberately not valid active include rules, to exercise the strict
    physical proof in the maintainer scripts). Pure shell builtins plus
    awk, so it works on a fakes-only PATH."""
    return """#!/bin/sh
printf "pam-auth-update %s\\n" "$*" >> "$FAKE_LOG"
state="$FAKE_PAM_STATE"
pam_d="$FAKE_PAM_D"
mkdir -p "$state" "$pam_d"
remove_profile() {
    [ -f "$1" ] || return 0
    awk -v p="$2" '/^Module: / { keep = (substr($0, 9) != p) } keep { print }' "$1" > "$1.new" && mv "$1.new" "$1"
}
add_profile() {
    file="$1"; profile="$2"
    [ -f "$file" ] || : > "$file"
    case "$(cat "$file")" in
        *"Module: $profile"*) return 0 ;;
    esac
    case "$profile" in
        fic-password-*)
            printf "Module: %s\\ninclude %s\\n" "$profile" "${profile%-hook}" >> "$file" ;;
        *)
            printf "Module: %s\\ninclude fic-faillock-%s\\n" "$profile" "${profile#fic-faillock-hook-}" >> "$file" ;;
    esac
}
regen() {
    : > "$pam_d/common-auth.new"
    for h in fic-faillock-hook-preauth fic-faillock-hook-authfail fic-faillock-hook-authsucc; do
        case "$(cat "$state/auth" 2>/dev/null)" in
            *"Module: $h"*)
                case "$FAKE_PAU_MALFORMED" in
                    commented)
                        printf "# auth\\t\\t\\t\\tinclude\\t\\t\\t\\tfic-faillock-%s\\n" "${h#fic-faillock-hook-}" >> "$pam_d/common-auth.new" ;;
                    wrong-facility)
                        printf "account\\t\\t\\t\\tinclude\\t\\t\\t\\tfic-faillock-%s\\n" "${h#fic-faillock-hook-}" >> "$pam_d/common-auth.new" ;;
                    *)
                        printf "auth\\t\\t\\t\\tinclude\\t\\t\\t\\tfic-faillock-%s\\n" "${h#fic-faillock-hook-}" >> "$pam_d/common-auth.new" ;;
                esac ;;
        esac
    done
    mv "$pam_d/common-auth.new" "$pam_d/common-auth"
    : > "$pam_d/common-account.new"
    case "$(cat "$state/account" 2>/dev/null)" in
        *"Module: fic-faillock-hook-account"*)
            printf "account\\t\\t\\t\\tinclude\\t\\t\\t\\tfic-faillock-account\\n" >> "$pam_d/common-account.new" ;;
    esac
    mv "$pam_d/common-account.new" "$pam_d/common-account"
    : > "$pam_d/common-password.new"
    case "$(cat "$state/password" 2>/dev/null)" in
        *"Module: fic-password-quality-hook"*)
            if [ "$FAKE_PAU_PASSWORD_MALFORMED" = "1" ]; then
                printf "# password\\t\\t\\t\\tinclude\\t\\t\\t\\tfic-password-quality\\n" >> "$pam_d/common-password.new"
            else
                printf "password\\t\\t\\t\\tinclude\\t\\t\\t\\tfic-password-quality\\n" >> "$pam_d/common-password.new"
            fi ;;
    esac
    case "$(cat "$state/password" 2>/dev/null)" in
        *"Module: fic-password-history-hook"*)
            printf "password\\t\\t\\t\\tinclude\\t\\t\\t\\tfic-password-history\\n" >> "$pam_d/common-password.new"
            printf "password\\t\\t\\t\\tinclude\\t\\t\\t\\tfic-password-history-initial\\n" >> "$pam_d/common-password.new" ;;
    esac
    mv "$pam_d/common-password.new" "$pam_d/common-password"
}
case " $* " in
    *" --remove "*)
        if [ "$FAKE_PAU_REMOVE_FAILS" = "1" ]; then
            if [ "$FAKE_PAU_PARTIAL" = "1" ]; then
                printf "FAKE-PAU-PARTIAL-MUTATION %s\\n" "$FAKE_PAU_PARTIAL_HOOKS" >> "$FAKE_LOG"
                for p in $FAKE_PAU_PARTIAL_HOOKS; do
                    remove_profile "$state/auth" "$p"
                    remove_profile "$state/account" "$p"
                    remove_profile "$state/password" "$p"
                done
                regen
            fi
            exit 1
        fi
        shift 2
        for p in "$@"; do
            remove_profile "$state/auth" "$p"
            remove_profile "$state/account" "$p"
            remove_profile "$state/password" "$p"
        done
        regen
        exit 0
        ;;
esac
case "$1" in
    --enable)
        shift
        [ "$FAKE_PAU_ENABLE_FAILS" = "1" ] && exit 1
        for p in "$@"; do
            case "$p" in
                fic-password-*)
                    [ "$FAKE_PAU_PASSWORD_ENABLE_FAILS" = "1" ] && exit 1
                    add_profile "$state/password" "$p" ;;
                fic-faillock-hook-account) add_profile "$state/account" "$p" ;;
                *) add_profile "$state/auth" "$p" ;;
            esac
        done
        regen
        exit 0
        ;;
    --package)
        regen
        exit 0
        ;;
esac
exit 0
"""

def proof_unit_tests() -> None:
    """Behavioral unit proof of the read-only permanent hook proof
    (fic_prove_permanent_hooks_attached): the generated function is executed
    against sandboxed /var/lib/pam and /etc/pam.d states and must accept
    only the canonical pam-auth-update topology (exact Module: selection in
    the correct facility state file plus an active, correctly facilitated,
    exact include rule in the generated stack). Every candidate
    false-positive shape must be rejected."""
    builder_path = (Path(__file__).resolve().parents[3] /
                    "packaging/deb/build-fic-debian12-deb.sh")
    generated = subprocess.run(
        ["bash", "-c",
         'set -- 0.1.0; FIC_PRODUCT_VERSION=0.1.0 FIC_BUILD_COMMIT=test '
         'FIC_RELEASE_TAG=test FIC_RELEASE_BUILD=0; '
         'source "$BUILDER" >/dev/null 2>&1; '
         'write_pam_hook_proof_function'],
        env={"PATH": "/usr/bin:/bin",
             "BUILDER": str(builder_path)},
        text=True, capture_output=True, check=False)
    require(generated.returncode == 0,
            "could not generate the permanent hook proof function: " +
            generated.stderr.strip())
    proof_function = generated.stdout

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        pam_state = tmp_path / "var-lib-pam"
        pam_d = tmp_path / "etc-pam.d"
        proof_script = tmp_path / "proof-sandboxed.sh"

        def run_proof(seed) -> subprocess.CompletedProcess:
            for directory in (pam_state, pam_d):
                if directory.is_dir():
                    shutil.rmtree(directory)
            seed()
            proof_script.write_text(
                "#!/bin/sh\n" +
                sandbox_pam_paths(proof_function, pam_state, pam_d) +
                "\nfic_prove_permanent_hooks_attached\n",
                encoding="utf-8")
            proof_script.chmod(0o755)
            return subprocess.run(
                [str(proof_script)],
                env={"PATH": "/usr/bin:/bin"},
                text=True, capture_output=True, check=False)

        def expect_pass(name: str, seed) -> None:
            ran = run_proof(seed)
            require(ran.returncode == 0,
                    f"proof must PASS for {name}: rc={ran.returncode} "
                    f"{ran.stderr.strip()}")

        def expect_fail(name: str, seed) -> None:
            ran = run_proof(seed)
            require(ran.returncode != 0,
                    f"proof must FAIL for {name} (false-positive accepted)")

        def seed_state(auth_state: str, account_state: str,
                       common_auth: str, common_account: str) -> None:
            pam_state.mkdir(parents=True, exist_ok=True)
            pam_d.mkdir(parents=True, exist_ok=True)
            (pam_state / "auth").write_text(auth_state, encoding="utf-8")
            (pam_state / "account").write_text(account_state,
                                               encoding="utf-8")
            (pam_d / "common-auth").write_text(common_auth, encoding="utf-8")
            (pam_d / "common-account").write_text(common_account,
                                                  encoding="utf-8")

        module_auth = "".join(f"Module: {hook}\ninclude {hook_target(hook)}\n"
                              for hook in AUTH_HOOKS)
        module_account = (f"Module: {PERMANENT_HOOKS[3]}\n"
                          f"include {hook_target(PERMANENT_HOOKS[3])}\n")
        include_auth = "".join(canonical_include("auth", hook_target(hook))
                               for hook in AUTH_HOOKS)
        include_account = canonical_include(
            "account", hook_target(PERMANENT_HOOKS[3]))

        # G: canonical valid topology — exact Module: records in the correct
        # facility state files plus active, correctly facilitated include
        # rules in the generated stacks.
        expect_pass("canonical topology",
                    lambda: seed_state(module_auth, module_account,
                                       include_auth, include_account))

        # G-variation: normal whitespace variation of the canonical
        # generated include lines must still pass.
        expect_pass(
            "canonical topology (space-separated include)",
            lambda: seed_state(
                module_auth, module_account,
                "".join(f"auth include {hook_target(hook)}\n"
                        for hook in AUTH_HOOKS),
                f"account include {hook_target(PERMANENT_HOOKS[3])}\n"))

        # A: commented generated hook line with a correct Module: selection.
        expect_fail(
            "commented generated hook",
            lambda: seed_state(module_auth, module_account,
                               "# " + include_auth, include_account))

        # B: wrong facility — the preauth target included from the account
        # phase instead of auth.
        expect_fail(
            "wrong facility include",
            lambda: seed_state(
                module_auth, module_account,
                include_auth.replace("auth\t\t\t\tinclude",
                                     "account\t\t\t\tinclude", 1),
                include_account))

        # C: prefix/suffix collision — a longer target that merely contains
        # the real target as a substring.
        expect_fail(
            "target suffix collision",
            lambda: seed_state(
                module_auth, module_account,
                include_auth.replace("fic-faillock-preauth\n",
                                     "fic-faillock-preauth-backup\n", 1),
                include_account))

        # D: mere text occurrence — the targets mentioned outside a PAM rule
        # (comments), with no active include rule at all.
        expect_fail(
            "mere text occurrence",
            lambda: seed_state(
                module_auth, module_account,
                "# managed target: fic-faillock-preauth\n"
                "# managed target: fic-faillock-authfail\n"
                "# managed target: fic-faillock-authsucc\n",
                include_account))

        # D2: active rules but with a non-include control word
        # (auth optional <target>) must not prove attachment.
        expect_fail(
            "non-include control word",
            lambda: seed_state(
                module_auth, module_account,
                "auth\t\t\t\toptional\t\t\t\tfic-faillock-preauth\n"
                "auth\t\t\t\toptional\t\t\t\tfic-faillock-authfail\n"
                "auth\t\t\t\toptional\t\t\t\tfic-faillock-authsucc\n",
                include_account))

        # E: the account hook Module: record only in the wrong facility
        # state file (/var/lib/pam/auth instead of /var/lib/pam/account).
        expect_fail(
            "wrong /var/lib/pam facility record",
            lambda: seed_state(module_auth + module_account, "",
                               include_auth, include_account))

        # F: Module: prefix/suffix collision — a longer profile name that
        # merely contains the real profile name as a substring.
        expect_fail(
            "Module: suffix collision",
            lambda: seed_state(
                module_auth.replace("Module: fic-faillock-hook-preauth\n",
                                    "Module: fic-faillock-hook-preauth-old\n", 1),
                module_account, include_auth, include_account))

        # F2: missing selection record — stacks intact but one profile
        # deselected.
        expect_fail(
            "missing selection record",
            lambda: seed_state(
                module_auth.replace(
                    "Module: fic-faillock-hook-authsucc\n"
                    "include fic-faillock-authsucc\n", "", 1),
                module_account, include_auth, include_account))

        # Read-only guarantee: the proof must not change any state element
        # it reads.
        seed_state(module_auth, module_account, include_auth,
                   include_account)
        before = pam_state_digest(pam_state, pam_d)
        ran = subprocess.run(
            [str(proof_script)],
            env={"PATH": "/usr/bin:/bin"},
            text=True, capture_output=True, check=False)
        require(ran.returncode == 0,
                "proof unexpectedly failed on the canonical state: " +
                ran.stderr.strip())
        require(before == pam_state_digest(pam_state, pam_d),
                "the permanent hook proof mutated the PAM state")

    print("permanent hook proof unit checks passed")


def main() -> int:
    root = Path(sys.argv[1])
    proof_unit_tests()
    profile_dir = root / "packaging/deb/pam-configs"
    expected = {
        "fic-faillock-notify": {
            "Name": "FIC PAM faillock pre-authentication and account check",
            "Priority": "1025",
            "rules": (
                "pam_faillock.so preauth",
                "required\t\t\tpam_faillock.so",
            ),
        },
        "fic-faillock-authfail": {
            "Name": "FIC PAM faillock failed authentication counter",
            "Priority": "1",
            "rules": ("[default=die]\t\t\tpam_faillock.so authfail",),
        },
        "fic-faillock-preauth-required": {
            "Name": "FIC PAM faillock pre-authentication and account check (required)",
            "Priority": "1025",
            "rules": (
                "pam_faillock.so preauth",
                "required\t\t\tpam_faillock.so",
            ),
        },
        "fic-faillock-authsucc": {
            "Name": "FIC PAM faillock success accounting and lock denial",
            "Priority": "1025",
            "rules": ("required\t\t\tpam_faillock.so authsucc",),
        },
        "fic-faillock-hook-preauth": {
            "Name": "FIC permanent pam_faillock preauth hook",
            "Priority": "100000",
            "rules": ("include                     fic-faillock-preauth",),
        },
        "fic-faillock-hook-authfail": {
            "Name": "FIC permanent pam_faillock authfail hook",
            "Priority": "-100000",
            "rules": ("include                     fic-faillock-authfail",),
        },
        "fic-faillock-hook-authsucc": {
            "Name": "FIC permanent pam_faillock authsucc hook",
            "Priority": "-100000",
            "rules": ("include                     fic-faillock-authsucc",),
        },
        "fic-faillock-hook-account": {
            "Name": "FIC permanent pam_faillock account hook",
            "Priority": "100000",
            "rules": ("include                     fic-faillock-account",),
        },
        "fic-pwquality": {
            "Name": "FIC PAM password quality checking",
            "Priority": "1024",
            "rules": ("requisite\t\t\tpam_pwquality.so retry=3",),
        },
        "fic-pwhistory": {
            "Name": "FIC PAM password history checking",
            "Priority": "1023",
            "rules": (
                "pam_pwhistory.so use_authtok",
                "requisite\t\t\tpam_pwhistory.so",
            ),
        },
        "fic-password-quality-hook": {
            "Name": "FIC password quality hook",
            "Priority": "1024",
            "rules": (
                "include                     fic-password-quality",
            ),
        },
        "fic-password-history-hook": {
            "Name": "FIC password history hook",
            "Priority": "1023",
            "rules": (
                "include                     fic-password-history",
                "include                     fic-password-history-initial",
            ),
        },
    }
    prohibited_arguments = (
        "deny=",
        "fail_interval=",
        "unlock_time=",
        "remember=",
        "enforce_for_root",
        "try_first_pass",
    )

    for name, contract in expected.items():
        path = profile_dir / name
        require(path.is_file() and not path.is_symlink(), f"missing physical PAM profile: {name}")
        profile = path.read_text(encoding="utf-8")
        require(field(profile, "Name") == contract["Name"], f"wrong Name in {name}")
        require(field(profile, "Default") == "no", f"{name} must default to disabled")
        require(field(profile, "Priority") == contract["Priority"], f"wrong Priority in {name}")
        for rule in contract["rules"]:
            require(rule in profile, f"{name} is missing rule: {rule}")
        for argument in prohibited_arguments:
            require(argument not in profile, f"{name} embeds policy argument: {argument}")

    # Step 5B: managed password slot bootstrap contract. The two permanent
    # password hook profiles are immutable package infrastructure: Primary
    # password type, exact priorities, Default: no, and the exact include
    # targets into the package-owned managed slots. They are never enabled
    # by the package (attach is a later, explicitly separate step).
    quality_hook = (profile_dir / "fic-password-quality-hook").read_text(encoding="utf-8")
    history_hook = (profile_dir / "fic-password-history-hook").read_text(encoding="utf-8")
    for hook_name, hook in (("fic-password-quality-hook", quality_hook),
                            ("fic-password-history-hook", history_hook)):
        require(field(hook, "Password-Type") == "Primary",
                f"{hook_name} Password-Type is not Primary")
        require(optional_field(hook, "Auth-Type") == "" and
                optional_field(hook, "Account-Type") == "",
                f"{hook_name} must only register password facility rules")
    require(re.search(r"^Password:\n\s+include\s+fic-password-quality$",
                      quality_hook, re.MULTILINE) is not None,
            "quality hook Password section must include fic-password-quality")
    require(re.search(r"^Password-Initial:\n\s+include\s+fic-password-quality$",
                      quality_hook, re.MULTILINE) is not None,
            "quality hook Password-Initial section must include fic-password-quality")
    require(re.search(r"^Password:\n\s+include\s+fic-password-history$",
                      history_hook, re.MULTILINE) is not None,
            "history hook Password section must include fic-password-history")
    require(re.search(r"^Password-Initial:\n\s+include\s+fic-password-history-initial$",
                      history_hook, re.MULTILINE) is not None,
            "history hook Password-Initial section must include "
            "fic-password-history-initial")

    # The three managed password slots ship as canonical-neutral package
    # payload: package owns existence, runtime policy + journal own state.
    slot_payload_dir = root / "packaging/deb/pam-slots"
    neutral_slot_body = "# FIC managed password slot: state=neutral\n"
    for slot in ("fic-password-quality", "fic-password-history",
                 "fic-password-history-initial"):
        slot_path = slot_payload_dir / slot
        require(slot_path.is_file() and not slot_path.is_symlink(),
                f"missing managed password slot payload: {slot}")
        require(slot_path.read_text(encoding="utf-8") == neutral_slot_body,
                f"managed password slot {slot} payload is not canonical neutral")

    notify = (profile_dir / "fic-faillock-notify").read_text(encoding="utf-8")
    require(field(notify, "Auth-Type") == "Primary", "notify profile Auth-Type is not Primary")
    require(field(notify, "Account-Type") == "Primary", "notify profile Account-Type is not Primary")
    require("requisite\t\t\tpam_faillock.so preauth" in notify, "notify profile has wrong preauth control")

    authfail = (profile_dir / "fic-faillock-authfail").read_text(encoding="utf-8")
    require(field(authfail, "Auth-Type") == "Primary", "authfail profile Auth-Type is not Primary")
    preauth_required = (profile_dir / "fic-faillock-preauth-required").read_text(encoding="utf-8")
    require(field(preauth_required, "Auth-Type") == "Primary",
            "preauth-required profile Auth-Type is not Primary")
    require(field(preauth_required, "Account-Type") == "Primary",
            "preauth-required profile Account-Type is not Primary")
    require("required\t\t\tpam_faillock.so preauth" in preauth_required,
            "preauth-required profile has wrong preauth control")
    authsucc = (profile_dir / "fic-faillock-authsucc").read_text(encoding="utf-8")
    # authsucc must run in the Additional auth block: a Primary authsucc is
    # jumped over by successful primary credential providers (success=N
    # jumps past the whole primary block into pam_permit), which lets a
    # locked user with a correct password authenticate.
    require(field(authsucc, "Auth-Type") == "Additional",
            "authsucc profile Auth-Type is not Additional; Primary authsucc "
            "is bypassed by primary provider success jumps")
    require("required\t\t\tpam_faillock.so authsucc" in authsucc,
            "authsucc profile has wrong control; upstream sufficient must not "
            "be copied blindly and the denial must not be skippable")
    require("sufficient" not in authsucc, "authsucc profile must not use sufficient control")
    require("Account-Type" not in authsucc,
            "authsucc profile must not add an account pam_faillock phase")
    # The three strategy-selector profiles conflict with each other so
    # pam-auth-update cannot generate a mixed strategy. The shared authfail
    # profile must not conflict with them because every strategy recipe
    # enables authfail together with one selector.
    selector_profiles = {
        "fic-faillock-notify",
        "fic-faillock-preauth-required",
        "fic-faillock-authsucc",
    }
    for conflicting in selector_profiles:
        profile = (profile_dir / conflicting).read_text(encoding="utf-8")
        conflicts = optional_field(profile, "Conflicts")
        for other in selector_profiles:
            if other == conflicting:
                continue
            require(other in conflicts,
                    f"{conflicting} does not declare a Conflicts entry for {other}")
        require("fic-faillock-authfail" not in conflicts,
                f"{conflicting} conflicts with the shared authfail profile")
    authfail_conflicts = optional_field(authfail, "Conflicts")
    for selector in selector_profiles:
        require(selector not in authfail_conflicts,
                f"authfail conflicts with required selector {selector}")

    quality = (profile_dir / "fic-pwquality").read_text(encoding="utf-8")
    require(field(quality, "Password-Type") == "Primary",
            "pwquality profile Password-Type is not Primary")
    require("pwquality" not in optional_field(quality, "Conflicts").split(),
            "fic-pwquality must not conflict with the distro pwquality profile")

    history = (profile_dir / "fic-pwhistory").read_text(encoding="utf-8")
    require(field(history, "Password-Type") == "Primary", "history profile Password-Type is not Primary")
    require("Password-Initial:" in history, "history profile has no Password-Initial stanza")

    deb_builder = (root / "packaging/deb/build-fic-debian12-deb.sh").read_text(encoding="utf-8")
    sourced = subprocess.run(
        ["bash", "-c",
         'set -- 0.1.0; source "$BUILDER"; '
         'declare -F write_common_preinst >/dev/null; '
         'declare -F write_fic_pam_preinst >/dev/null'],
        cwd=root,
        env={"PATH": "/usr/bin:/bin", "BUILDER":
             str(root / "packaging/deb/build-fic-debian12-deb.sh")},
        text=True,
        capture_output=True,
        check=False,
    )
    require(
        sourced.returncode == 0,
        "Debian PAM preinst helpers are not top-level shell functions: " +
        sourced.stderr.strip(),
    )
    rpm_builder = (root / "packaging/rpm/build-fic-alt-p11-rpm.sh").read_text(encoding="utf-8")
    rpm_facility_path = root / "packaging/rpm/fic-pam-faillock"
    rpm_facility = rpm_facility_path.read_text(encoding="utf-8")
    rpm_history_facility_path = root / "packaging/rpm/fic-pam-pwhistory"
    rpm_history_facility = rpm_history_facility_path.read_text(encoding="utf-8")
    fic_cmake = (root / "fic/CMakeLists.txt").read_text(encoding="utf-8")

    fic_package = function_body(deb_builder, "build_fic_package")
    fic_dick_package = function_body(deb_builder, "build_fic_dick_package")
    fic_pam_preinst_start = deb_builder.find("\nwrite_fic_pam_preinst() {")
    fic_pam_preinst_end = deb_builder.find(
        "\nwrite_common_postinst() {", fic_pam_preinst_start + 1
    )
    require(fic_pam_preinst_start >= 0 and
            fic_pam_preinst_end > fic_pam_preinst_start,
            "Debian builder has no bounded write_fic_pam_preinst function")
    fic_pam_preinst = deb_builder[fic_pam_preinst_start:fic_pam_preinst_end]
    require('write_fic_pam_preinst "$package_root"' in fic_package,
            "Debian fic package does not use the legacy PAM upgrade guard")
    for legacy_id in (
        "fic-faillock-notify",
        "fic-faillock-authfail",
        "fic-faillock-preauth-required",
        "fic-faillock-authsucc",
        "fic-pwquality",
        "fic-pwhistory",
    ):
        require(legacy_id in fic_pam_preinst,
                f"upgrade guard misses legacy PAM identifier {legacy_id}")
    require('"${1:-}" = "upgrade"' in fic_pam_preinst,
            "legacy PAM guard is not limited to upgrades")
    fic_postinst = function_body(deb_builder, "write_system_integration_symlink_postinst")
    fic_prerm = function_body(deb_builder, "write_system_integration_symlink_prerm")
    generic_prerm = function_body(deb_builder, "write_symlink_prerm")

    require("/opt/fic/db/mutation-journal.json" in fic_pam_preinst and
            '"status": "(prepared|applied|rollback_failed)"' in fic_pam_preinst,
            "legacy PAM upgrade guard does not inspect active journal provenance")
    require("active_units=" in fic_pam_preinst and
            'systemctl start "$unit" || true' in fic_pam_preinst,
            "legacy PAM upgrade guard does not restore services after race refusal")
    require('local profile_dir="$package_root/usr/share/pam-configs"' in deb_builder,
            "Debian builder does not stage profiles in /usr/share/pam-configs")
    require('install_fic_pam_profiles "$package_root"' in fic_package,
            "Debian fic package does not install PAM profiles")
    require(deb_builder.count('install_fic_pam_profiles "$package_root"') == 1,
            "PAM profiles must be staged only in the Debian fic package")
    require('install_fic_pam_slots "$package_root"' in fic_package,
            "Debian fic package does not install PAM managed slots")
    require(deb_builder.count('install_fic_pam_slots "$package_root"') == 1,
            "PAM slots must be staged only in the Debian fic package")
    require('"libpam-runtime" "libpam-modules" "libpam-pwquality"' in fic_package,
            "Debian fic package lacks direct PAM dependencies")
    require('package_depends="$(join_depends "$binary_depends" "udev")"' in fic_dick_package,
            "Debian fic-dick package does not compose the udev runtime dependency")
    require('"$package_name" \\\n        "$package_depends" \\' in fic_dick_package,
            "Debian fic-dick control file does not use its composed runtime dependencies")
    require('"$package_root/DEBIAN/conffiles"' in deb_builder,
            "Debian builder does not protect mutable PAM slots as conffiles")
    for slot in (
        "fic-faillock-preauth",
        "fic-faillock-authfail",
        "fic-faillock-authsucc",
        "fic-faillock-account",
        "fic-password-quality",
        "fic-password-history",
        "fic-password-history-initial",
    ):
        require(f"/etc/pam.d/{slot}" in deb_builder,
                f"Debian conffiles contract misses PAM slot {slot}")
    require("pam-auth-update --package" in fic_postinst,
            "Debian postinst does not register package profiles")

    # Step 5B: the package bootstraps managed password slot existence before
    # the read-only pre-attach validation and never attaches the password
    # hook profiles itself (attach is a later, explicitly separate step).
    bootstrap_pos = fic_postinst.find("--maintenance bootstrap-pam-password-slots")
    require(bootstrap_pos >= 0,
            "Debian postinst does not bootstrap the managed password slots")
    validate_pos = fic_postinst.find("--maintenance validate-pam-slots-before-attach")
    require(validate_pos > bootstrap_pos,
            "Debian postinst must bootstrap the managed password slots "
            "before the pre-attach validation")
    for password_hook in ("fic-password-quality-hook",
                          "fic-password-history-hook"):
        require(f"pam-auth-update --enable \\\n        {password_hook}"
                not in fic_postinst and
                f"pam-auth-update --enable {password_hook}" not in fic_postinst,
                f"Debian postinst must not enable the password hook "
                f"profile {password_hook} (attach is out of Step 5B scope)")
    require("common-password" not in fic_postinst,
            "Debian postinst must not edit the pam-auth-update generated "
            "common-password stack")

    remove_start = fic_prerm.find("pam-auth-update --package --remove")
    remove_end = fic_prerm.find("\nfi", remove_start)
    require(remove_start >= 0 and remove_end > remove_start,
            "Debian prerm has no bounded PAM profile removal block")
    remove_block = fic_prerm[remove_start:remove_end]
    for name in expected:
        require(name in remove_block, f"Debian prerm does not remove {name}")

    # Lifecycle invariant: package removal first stops all FIC PAM writers
    # (the daemon can mutate PAM or re-activate infrastructure while alive)
    # and only then detaches the permanent hook profiles.
    stop_pos = fic_prerm.find("systemctl disable --now fic.service")
    remove_pos = fic_prerm.find("pam-auth-update --package --remove")
    require(stop_pos >= 0 and remove_pos > stop_pos,
            "Debian prerm must stop FIC services before pam-auth-update --remove")
    stop_block = fic_prerm[stop_pos:remove_pos]
    for unit in ("fic-notify.service", "fic-device.service"):
        require(unit in stop_block,
                f"Debian prerm must stop {unit} before detaching PAM hooks")
    require("daemon-reload" in stop_block,
            "Debian prerm must reload systemd units before detaching PAM hooks")
    require("is-active --quiet" in stop_block,
            "Debian prerm does not verify that FIC services stopped before "
            "detaching PAM hooks")

    # Lifecycle invariant: a failing `pam-auth-update --remove` must be
    # contained inside the prerm while every FIC writer is still stopped.
    # The prerm restores ONLY the permanent hook infrastructure (never the
    # legacy policy-owned selector profiles), proves the restoration with the
    # read-only standard-state proof, and always exits non-zero, so dpkg's
    # later abort-remove path never has to restart a writer on top of a
    # partially detached PAM graph.
    require("if ! pam-auth-update --package --remove" in fic_prerm,
            "Debian prerm does not contain the PAM detach failure branch")
    enable_pos = fic_prerm.find("pam-auth-update --enable")
    require(enable_pos > remove_pos,
            "Debian prerm PAM recovery does not re-enable the permanent "
            "hooks after the failed detach attempt")
    recovery_enable_block = fic_prerm[enable_pos:fic_prerm.find(
        "then", enable_pos)]
    for hook in ("fic-faillock-hook-preauth", "fic-faillock-hook-authfail",
                 "fic-faillock-hook-authsucc", "fic-faillock-hook-account"):
        require(hook in recovery_enable_block,
                f"Debian prerm PAM recovery does not re-enable {hook}")
    for legacy_policy_profile in ("fic-faillock-notify",
                                  "fic-faillock-preauth-required",
                                  "fic-pwquality", "fic-pwhistory"):
        require(legacy_policy_profile not in fic_prerm[enable_pos:],
                f"prerm PAM recovery must not re-activate the legacy "
                f"policy-owned profile {legacy_policy_profile}")
    require("fic_prove_permanent_hooks_attached" in fic_prerm[enable_pos:],
            "Debian prerm PAM recovery does not prove the restored "
            "permanent hooks")
    for diagnostic in ("restoring the package PAM hook infrastructure",
                       "PAM infrastructure recovery failed",
                       "restored and proven attached",
                       "NOT proven restored"):
        require(diagnostic in fic_prerm,
                f"Debian prerm PAM detach-failure diagnostic missing: "
                f"{diagnostic}")

    # Step 5B selection-preserving password hook removal contract: the exact
    # pre-removal selection of the managed password hook profiles is
    # snapshotted read-only from the standard per-facility state file with
    # the exact full-line "Module: <profile>" grammar BEFORE the first
    # pam-auth-update call.
    for hook in PASSWORD_HOOKS:
        snapshot_grep = f'grep -q "^Module: {hook}\\$" /var/lib/pam/password'
        require(snapshot_grep in fic_prerm,
                f"Debian prerm does not snapshot the pre-removal selection "
                f"of {hook} with the exact Module: grammar")
        require(fic_prerm.find(snapshot_grep) < remove_pos,
                f"Debian prerm must snapshot the {hook} selection before "
                f"the first pam-auth-update call")
    require("password hook recovery failed" in fic_prerm,
            "Debian prerm lacks the selection-preserving password hook "
            "recovery failure diagnostic")
    # The recovery must be selection-preserving: password hooks are
    # re-enabled ONLY through the snapshot-derived restore list (never a
    # hard-coded profile list), after the mandatory faillock infrastructure
    # restore, and rc=0 is never trusted without the strict resulting-state
    # proof.
    password_enable_pos = fic_prerm.find(
        "pam-auth-update --enable \\$fic_password_hook_restore_list")
    require(password_enable_pos > enable_pos,
            "Debian prerm must re-enable password hooks only through the "
            "snapshot-derived restore list")
    for line in fic_prerm.splitlines():
        if "pam-auth-update" in line and "--enable" in line:
            require("fic-password-quality-hook" not in line and
                    "fic-password-history-hook" not in line,
                    "Debian prerm must not enable password hooks from a "
                    "hard-coded profile list: " + line.strip())
    password_proof_pos = fic_prerm.find(
        "fic_prove_password_hook_state_restored")
    require(password_proof_pos > password_enable_pos,
            "Debian prerm must prove the password hook state after the "
            "selection-preserving recovery enable")
    require('"\\$fic_password_quality_hook_selected" \\\\' in fic_prerm and
            '"\\$fic_password_history_hook_selected"; then' in fic_prerm,
            "Debian prerm must pass the exact pre-removal selection flags "
            "to the password hook proof")
    password_proof = function_body(
        deb_builder, "write_password_hook_proof_function")
    for state_element in ("/var/lib/pam/password",
                          "/etc/pam.d/common-password",
                          'grep -q "^Module: fic-password-quality-hook$" '
                          '/var/lib/pam/password',
                          'grep -q "^Module: fic-password-history-hook$" '
                          '/var/lib/pam/password'):
        require(state_element in password_proof,
                f"password hook proof lacks {state_element}")
    # Same strict grammar as the permanent hook proof: exact full-line
    # "Module: <profile>" selection records plus exact active, correctly
    # facilitated include rules, with the history hook proven on both of its
    # dual-stack physical includes.
    for include_pattern in (
            "^password[[:space:]]+include[[:space:]]+fic-password-quality$",
            "^password[[:space:]]+include[[:space:]]+fic-password-history$",
            "^password[[:space:]]+include[[:space:]]+"
            "fic-password-history-initial$"):
        require(f'grep -Eq "{include_pattern}" /etc/pam.d/common-password'
                in password_proof,
                f"password hook proof lacks the exact include proof for "
                f"{include_pattern}")
    for forbidden in ("pam-auth-update", "rm ", "mv ", ">>", "> ",
                      "tee ", "chmod", "chown"):
        require(forbidden not in password_proof,
                f"password hook proof must stay read-only but contains "
                f"{forbidden}")
    pam_proof = function_body(deb_builder, "write_pam_hook_proof_function")
    for state_element in ("/var/lib/pam", "/etc/pam.d/common-auth",
                          "/etc/pam.d/common-account", '"Module: '):
        require(state_element in pam_proof,
                f"standard-state permanent hook proof lacks {state_element}")
    # Hardened selection proof: each permanent hook profile must be proven by
    # an exact full-line "Module: <profile>" entry in the CORRECT facility
    # state file (auth hooks in /var/lib/pam/auth, account hook in
    # /var/lib/pam/account). Substring matching across concatenated state
    # files cannot distinguish facilities and accepts prefix/suffix
    # collisions, so it is forbidden.
    for hook, facility in (("fic-faillock-hook-preauth", "auth"),
                           ("fic-faillock-hook-authfail", "auth"),
                           ("fic-faillock-hook-authsucc", "auth"),
                           ("fic-faillock-hook-account", "account")):
        require(f'grep -q "^Module: {hook}$" /var/lib/pam/{facility}'
                in pam_proof,
                f"permanent hook proof lacks the exact Module: selection "
                f"check for {hook} in /var/lib/pam/{facility}")
        # Hardened physical proof: each hook target must be proven by an
        # active, correctly facilitated, exact include rule in the generated
        # stack (anchored full PAM rule, real include control, exact target).
        target = hook.replace("fic-faillock-hook-", "fic-faillock-")
        require(f'grep -Eq "^{facility}[[:space:]]+include[[:space:]]+{target}$"'
                in pam_proof,
                f"permanent hook proof lacks the anchored {facility} include "
                f"check for {target}")
    for weak_form in ('*"Module: $fic_hook"*', "fic_selected=",
                      "grep -q 'fic-faillock-", "session-noninteractive"):
        require(weak_form not in pam_proof,
                f"permanent hook proof still uses the weak proof form: "
                f"{weak_form}")
    # The proof stays strictly read-only: no pam-auth-update invocation, no
    # writes into the pam-auth-update state, the generated stacks or any
    # other PAM/slot/journal state.
    for forbidden in ("pam-auth-update", "rm ", "mv ", ">>", "> ",
                      "tee ", "chmod", "chown"):
        require(forbidden not in pam_proof,
                f"read-only permanent hook proof must not contain: "
                f"{forbidden}")
    # The prerm itself never touches managed slots, journal or witness:
    # it has no reason to run any FIC maintenance command.
    for forbidden in ("fic --maintenance", "fic-dick", "mutation-journal"):
        require(forbidden not in fic_prerm,
                f"Debian prerm must not touch FIC runtime state: {forbidden}")
    # Final stop proof: after the bounded wait the prerm must POSITIVELY
    # prove every FIC PAM writer is inactive; a timeout is a package-removal
    # failure (exit 1), never permission to detach the hooks. The proof is a
    # plain is-active check (no `|| true`) followed by exit 1 with a unit
    # name in the diagnostic.
    require('if systemctl is-active --quiet "\\$unit"; then' in stop_block and
            "is still active after the bounded stop wait" in stop_block and
            "exit 1" in stop_block,
            "Debian prerm must abort hook detachment when a FIC service is "
            "still active after the bounded stop wait")

    # Lifecycle invariant: installation/reinstallation never attaches the
    # permanent fic-faillock-hook-* profiles until the existing
    # /etc/pam.d/fic-faillock-* state passed read-only pre-attach validation
    # (canonical neutral or journal-bound FIC-owned).
    validator_call = "fic --maintenance validate-pam-slots-before-attach"
    require(validator_call in fic_postinst,
            "Debian postinst never validates existing FIC PAM slots "
            "before attach")
    validate_pos = fic_postinst.find(validator_call)
    package_pos = fic_postinst.find("pam-auth-update --package")
    enable_pos = fic_postinst.find("pam-auth-update --enable")
    require(package_pos > validate_pos and enable_pos > validate_pos,
            "Debian postinst must attach FIC PAM hooks only after "
            "pre-attach slot validation")
    require("exit 1" in fic_postinst[validate_pos:package_pos],
            "Debian postinst must abort package configuration when slot "
            "validation fails")
    configure_pos = fic_postinst.find('\\${1:-}" = "configure"')
    require(configure_pos >= 0 and validate_pos > configure_pos,
            "pre-attach slot validation must run inside the postinst "
            "configure branch")

    # The daemon (a PAM writer) must not be started before the pre-attach
    # validation passed and the hooks were attached.
    start_pos = fic_postinst.find("systemctl enable --now fic.service")
    require(start_pos < 0 or start_pos > enable_pos,
            "postinst must not start the FIC daemon before pre-attach slot "
            "validation and hook attach")

    # Lifecycle invariant: `postinst abort-remove` (dpkg's recovery entry
    # point after a failed `prerm remove`) is an early systemd-only path,
    # never a configure path: it restores package-managed service
    # enablement/runtime state and must not touch PAM topology, managed
    # slots, the mutation journal, the journal witness, or stop/restart a
    # possibly refusing live writer.
    abort_pos = fic_postinst.find('"abort-remove"')
    require(abort_pos >= 0, "Debian postinst has no abort-remove recovery path")
    abort_exit = fic_postinst.find("exit 0", abort_pos)
    require(abort_exit > abort_pos,
            "abort-remove recovery path does not exit before configure logic")
    abort_block = fic_postinst[abort_pos:abort_exit]
    require(abort_exit < configure_pos,
            "abort-remove recovery path must precede the configure branch")
    stop_loop_pos = fic_postinst.find("systemctl stop")
    require(stop_loop_pos < 0 or stop_loop_pos > abort_exit,
            "abort-remove recovery path must precede the generic "
            "service-stop loop")
    require("daemon-reload" in abort_block,
            "abort-remove recovery must reload systemd units")
    for unit in ("fic.service", "fic-device.service"):
        require(f"enable {unit}" in abort_block and f"start {unit}" in abort_block,
                f"abort-remove recovery must re-enable and start {unit}")
        require(f"is-active --quiet {unit}" in abort_block,
                f"abort-remove recovery must prove {unit} active")
    for forbidden in ("pam-auth-update", "validate-pam-slots-before-attach",
                      "ensure-config", "check-config", "check-db",
                      "trust-sync", "initialize-db", "systemctl stop",
                      "systemctl restart", "disable --now"):
        require(forbidden not in abort_block,
                f"abort-remove recovery path must not contain: {forbidden}")

    # The read-only permanent hook guard: dpkg runs abort-remove after ANY
    # failed `prerm remove` and the argument carries no failure reason. The
    # guard proves the permanent hook infrastructure is attached (standard
    # state, no PAM tool invocation, no slot/journal/witness access) before
    # any FIC writer is restarted.
    require("fic_prove_permanent_hooks_attached" in abort_block,
            "abort-remove recovery lacks the read-only permanent hook guard")
    require("not proven attached" in abort_block,
            "abort-remove guard diagnostic must state the unproven PAM state")
    # fic-notify.service is mandatory in the normal configure path
    # (`systemctl enable --now` under `set -e`), so the abort-remove
    # recovery must restore it strictly as well.
    require("if ! systemctl enable fic-notify.service" in abort_block and
            "if ! systemctl start fic-notify.service" in abort_block and
            "systemctl is-active --quiet fic-notify.service" in abort_block,
            "abort-remove must restore fic-notify.service strictly "
            "(mandatory service, same model as configure)")
    require("fic-notify.service || true" not in abort_block,
            "abort-remove still treats fic-notify.service as best-effort")

    # Behavioral proof of the removal invariant: run the generated prerm
    # with fake systemctl/pam-auth-update and verify the actual call order.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        package_root = tmp_path / "pkg"
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir(parents=True)
        (package_root / "DEBIAN").mkdir(parents=True)
        log = tmp_path / "calls.log"

        fake_systemctl = fake_bin / "systemctl"
        fake_systemctl.write_text(
            "#!/bin/sh\n"
            'printf "systemctl %s\\n" "$*" >> "$FAKE_LOG"\n'
            "for argument in \"$@\"; do\n"
            "  [ \"$argument\" = \"is-active\" ] && exit 1\n"
            "done\n"
            "exit 0\n",
            encoding="utf-8")
        fake_systemctl.chmod(0o755)
        fake_pam = fake_bin / "pam-auth-update"
        fake_pam.write_text(
            "#!/bin/sh\n"
            'printf "pam-auth-update %s\\n" "$*" >> "$FAKE_LOG"\n'
            "exit 0\n",
            encoding="utf-8")
        fake_pam.chmod(0o755)

        generated = subprocess.run(
            ["bash", "-c",
             'pkg_root="$1"; '
             'set -- 0.1.0; '
             'source "$BUILDER" >/dev/null 2>&1; '
             'write_system_integration_symlink_prerm "$pkg_root" fic /opt/fic/bin/fic',
             "bash", str(package_root)],
            cwd=root,
            env={"PATH": "/usr/bin:/bin",
                 "BUILDER": str(root / "packaging/deb/build-fic-debian12-deb.sh")},
            text=True,
            capture_output=True,
            check=False)
        prerm_path = package_root / "DEBIAN/prerm"
        require(generated.returncode == 0 and prerm_path.is_file(),
                "could not generate Debian prerm for the behavioral check: " +
                generated.stderr.strip())
        ran = subprocess.run(
            [str(prerm_path), "remove"],
            env={"PATH": f"{fake_bin}:/usr/bin:/bin", "FAKE_LOG": str(log)},
            text=True,
            capture_output=True,
            check=False)
        require(ran.returncode == 0,
                "generated prerm failed under fake systemctl: " +
                ran.stderr.strip())
        calls = log.read_text(encoding="utf-8").splitlines() \
            if log.is_file() else []
        pam_calls = [index for index, line in enumerate(calls)
                     if line.startswith("pam-auth-update")]
        stop_calls = [index for index, line in enumerate(calls)
                      if "disable --now" in line]
        require(pam_calls and stop_calls and max(stop_calls) < min(pam_calls),
                "prerm ordering regression: pam-auth-update ran before the "
                "FIC services were stopped")
        require(any("--remove" in calls[index] for index in pam_calls),
                "prerm did not deselect the FIC PAM profiles on remove")

        # Timeout path: a FIC service that stays active after the bounded
        # wait must abort the removal BEFORE any pam-auth-update call and
        # name the offending unit in the diagnostic.
        fake_sleep = fake_bin / "sleep"
        fake_sleep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_sleep.chmod(0o755)
        fake_systemctl.write_text(
            "#!/bin/sh\n"
            'printf "systemctl %s\\n" "$*" >> "$FAKE_LOG"\n'
            "exit 0\n",
            encoding="utf-8")
        fake_systemctl.chmod(0o755)
        log.unlink(missing_ok=True)
        stuck = subprocess.run(
            [str(prerm_path), "remove"],
            env={"PATH": f"{fake_bin}:/usr/bin:/bin", "FAKE_LOG": str(log)},
            text=True,
            capture_output=True,
            check=False)
        require(stuck.returncode != 0,
                "prerm remove must fail when a FIC service remains active "
                "after the bounded stop wait")
        stuck_calls = log.read_text(encoding="utf-8").splitlines() \
            if log.is_file() else []
        require(not any(line.startswith("pam-auth-update")
                        for line in stuck_calls),
                "pam-auth-update ran although a FIC service remained active")
        require("fic.service" in stuck.stderr,
                "stop-timeout diagnostic must name the unit that failed "
                "to stop: " + stuck.stderr.strip())

    # Behavioral proof of the detach-failure recovery invariant: run the
    # generated prerm with fake systemctl and a stateful fake
    # pam-auth-update while the standard pam-auth-update state paths are
    # substituted into a sandbox (the host is never touched). Verifies: a
    # failing detach restores ONLY the permanent hook infrastructure,
    # proves the restoration, and always exits non-zero.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        package_root = tmp_path / "pkg"
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir(parents=True)
        (package_root / "DEBIAN").mkdir(parents=True)
        log = tmp_path / "prerm-recovery-calls.log"
        pam_state = tmp_path / "pam-state"
        pam_d = tmp_path / "pam.d"

        fake_systemctl = fake_bin / "systemctl"
        fake_systemctl.write_text(
            "#!/bin/sh\n"
            'printf "systemctl %s\\n" "$*" >> "$FAKE_LOG"\n'
            "for argument in \"$@\"; do\n"
            "  [ \"$argument\" = \"is-active\" ] && exit 1\n"
            "done\n"
            "exit 0\n",
            encoding="utf-8")
        fake_systemctl.chmod(0o755)
        fake_pam = fake_bin / "pam-auth-update"
        fake_pam.write_text(stateful_pam_auth_update_fake(),
                            encoding="utf-8")
        fake_pam.chmod(0o755)

        generated = subprocess.run(
            ["bash", "-c",
             'pkg_root="$1"; '
             'set -- 0.1.0; '
             'source "$BUILDER" >/dev/null 2>&1; '
             'write_system_integration_symlink_prerm "$pkg_root" fic /opt/fic/bin/fic',
             "bash", str(package_root)],
            cwd=root,
            env={"PATH": "/usr/bin:/bin",
                 "BUILDER": str(root / "packaging/deb/build-fic-debian12-deb.sh")},
            text=True,
            capture_output=True,
            check=False)
        require(generated.returncode == 0,
                "could not generate Debian prerm for the detach-failure "
                "behavioral check: " + generated.stderr.strip())
        prerm_text = (package_root / "DEBIAN/prerm").read_text(
            encoding="utf-8")
        # The generated prerm may only READ the generated common-password
        # stack (proof greps and existence checks); pam-auth-update is the
        # single writer of the generated stacks.
        for line in prerm_text.splitlines():
            if "common-password" in line:
                stripped = line.strip()
                require(stripped.startswith(("grep", "[ ", "#")),
                        "Debian prerm must never edit the generated "
                        "common-password stack directly: " + stripped)
        prerm_script = tmp_path / "prerm-sandboxed.sh"

        # detach-failure scenario helpers follow
        def run_prerm(env_extra=None) -> subprocess.CompletedProcess:
            prerm_script.write_text(
                sandbox_pam_paths(prerm_text, pam_state, pam_d),
                encoding="utf-8")
            prerm_script.chmod(0o755)
            env = {"PATH": f"{fake_bin}:/usr/bin:/bin",
                   "FAKE_LOG": str(log),
                   "FAKE_PAM_STATE": str(pam_state),
                   "FAKE_PAM_D": str(pam_d),
                   "FAKE_PAU_REMOVE_FAILS": "", "FAKE_PAU_PARTIAL": "",
                   "FAKE_PAU_PARTIAL_HOOKS": "",
                   "FAKE_PAU_ENABLE_FAILS": "",
                   "FAKE_PAU_PASSWORD_ENABLE_FAILS": "",
                   "FAKE_PAU_PASSWORD_MALFORMED": ""}
            if env_extra:
                env.update(env_extra)
            return subprocess.run(
                [str(prerm_script), "remove"],
                env=env, text=True, capture_output=True, check=False)

        def read_calls() -> list:
            return log.read_text(encoding="utf-8").splitlines() \
                if log.is_file() else []

        def require_hooks_attached() -> None:
            state, stack = read_pam_state(pam_state, pam_d)
            for hook in PERMANENT_HOOKS:
                require(f"Module: {hook}" in state,
                        f"permanent hook profile not selected after "
                        f"recovery: {hook}")
                require(hook_target(hook) in stack,
                        f"permanent hook target missing from the generated "
                        f"stacks after recovery: {hook_target(hook)}")

        partial_hooks = ("fic-faillock-hook-preauth "
                         "fic-faillock-hook-authsucc")

        # Scenario A: the detach fails without changing any PAM state.
        # Recovery must still run, re-enable exactly the four permanent
        # hooks (never the legacy policy-owned selector profiles), prove
        # the restored state and exit non-zero. All FIC stop/proof work
        # must have happened before any PAM operation.
        write_attached_pam_state(pam_state, pam_d)
        log.unlink(missing_ok=True)
        ran = run_prerm({"FAKE_PAU_REMOVE_FAILS": "1"})
        require(ran.returncode != 0,
                "prerm must fail when the PAM detach fails: " +
                ran.stderr.strip())
        calls = read_calls()
        pam_positions = [index for index, line in enumerate(calls)
                         if line.startswith("pam-auth-update")]
        stop_positions = [index for index, line in enumerate(calls)
                          if "disable --now" in line]
        require(stop_positions and pam_positions
                and max(stop_positions) < min(pam_positions),
                "prerm ordering regression: PAM operations ran before the "
                "FIC service stop proof: " + "\n".join(calls))
        enable_calls = [line for line in calls
                        if line.startswith("pam-auth-update --enable")]
        require(len(enable_calls) == 1,
                "prerm recovery must run exactly one permanent hook "
                "re-enable call: " + "\n".join(calls))
        for hook in PERMANENT_HOOKS:
            require(hook in enable_calls[0],
                    f"prerm recovery does not re-enable {hook}")
        for legacy in LEGACY_POLICY_PROFILES:
            require(legacy not in enable_calls[0],
                    f"prerm recovery re-activated legacy profile {legacy}")
        require_hooks_attached()
        require("restoring the package PAM hook infrastructure"
                in ran.stderr,
                "prerm detach-failure diagnostic must announce the PAM "
                "recovery: " + ran.stderr.strip())
        require("restored and proven attached" in ran.stderr,
                "prerm must report the proven restoration: " +
                ran.stderr.strip())
        require(all(line.startswith(("systemctl ", "pam-auth-update "))
                    for line in calls),
                "prerm detach-failure path touched non-systemd, non-PAM "
                "state (managed slots, journal or witness must stay "
                "untouched): " + "\n".join(calls))

    # detach-failure scenarios B-D follow
        # Scenario B: the detach fails AFTER a real partial mutation (two
        # hooks already deselected and the stacks regenerated). Recovery
        # must fully restore and prove all four permanent hooks.
        write_attached_pam_state(pam_state, pam_d)
        log.unlink(missing_ok=True)
        ran = run_prerm({"FAKE_PAU_REMOVE_FAILS": "1",
                         "FAKE_PAU_PARTIAL": "1",
                         "FAKE_PAU_PARTIAL_HOOKS": partial_hooks})
        require(ran.returncode != 0,
                "prerm must fail when the PAM detach fails after a partial "
                "mutation: " + ran.stderr.strip())
        calls = read_calls()
        require(any(line.startswith("FAKE-PAU-PARTIAL-MUTATION")
                    for line in calls),
                "partial mutation injection did not run: " +
                "\n".join(calls))
        require_hooks_attached()
        require("restored and proven attached" in ran.stderr,
                "prerm must report the proven restoration after a partial "
                "detach: " + ran.stderr.strip())

        # Scenario C: the recovery itself fails while the detach changed
        # nothing. The permanent hooks stay attached and are proven, but the
        # prerm must report the failed recovery explicitly and exit non-zero.
        write_attached_pam_state(pam_state, pam_d)
        log.unlink(missing_ok=True)
        ran = run_prerm({"FAKE_PAU_REMOVE_FAILS": "1",
                         "FAKE_PAU_ENABLE_FAILS": "1"})
        require(ran.returncode != 0,
                "prerm must fail when the PAM recovery enable fails")
        require("PAM infrastructure recovery failed" in ran.stderr and
                "proven still attached" in ran.stderr,
                "prerm must distinguish failed recovery with intact hook "
                "state: " + ran.stderr.strip())
        require_hooks_attached()

        # Scenario D: the recovery fails after a partial mutation. The PAM
        # state is NOT proven restored: the prerm must say so explicitly,
        # leave the partial state untouched and exit non-zero.
        write_attached_pam_state(pam_state, pam_d)
        log.unlink(missing_ok=True)
        ran = run_prerm({"FAKE_PAU_REMOVE_FAILS": "1",
                         "FAKE_PAU_PARTIAL": "1",
                         "FAKE_PAU_PARTIAL_HOOKS": partial_hooks,
                         "FAKE_PAU_ENABLE_FAILS": "1"})
        require(ran.returncode != 0,
                "prerm must fail when recovery cannot restore the "
                "permanent hooks")
        require("NOT proven restored" in ran.stderr,
                "prerm must state that the PAM state is not proven "
                "restored: " + ran.stderr.strip())
        state, stack = read_pam_state(pam_state, pam_d)
        require("Module: fic-faillock-hook-preauth" not in state and
                "Module: fic-faillock-hook-authsucc" not in state,
                "prerm recovery silently restored hooks although the "
                "recovery enable failed")
        require("Module: fic-faillock-hook-authfail" in state and
                "Module: fic-faillock-hook-account" in state,
                "untouched hook profiles must stay selected")

        # Scenario E (hardened physical proof): the recovery --enable
        # "succeeds" but regenerates a malformed physical hook line
        # (commented / wrong facility). The selection records look correct,
        # but the strict physical proof must refuse to confirm the
        # restoration: the prerm must report the state as NOT proven
        # restored and exit non-zero.
        for malformed in ("commented", "wrong-facility"):
            write_attached_pam_state(pam_state, pam_d)
            log.unlink(missing_ok=True)
            ran = run_prerm({"FAKE_PAU_REMOVE_FAILS": "1",
                             "FAKE_PAU_MALFORMED": malformed})
            require(ran.returncode != 0,
                    f"prerm must fail when the regenerated physical hook "
                    f"line is malformed ({malformed}): " + ran.stderr.strip())
            require("NOT proven restored" in ran.stderr,
                    f"prerm must treat a malformed physical hook line "
                    f"({malformed}) as an unproven PAM restoration: " +
                    ran.stderr.strip())

        # Step 5B matrix: the managed password hook profiles are package
        # payload with an administrator-controlled pam-auth-update selection.
        # A remove run must never change that selection, and a failed removal
        # must restore ONLY the hooks that were selected before the removal,
        # proven against the resulting standard state (rc=0 is never
        # trusted). The mandatory faillock infrastructure restore keeps its
        # stronger always-restore invariant.
        def require_password_hook_state(quality: bool,
                                        history: bool) -> None:
            password_state = (pam_state / "password").read_text(
                encoding="utf-8") if (pam_state / "password").is_file() \
                else ""
            password_stack = (pam_d / "common-password").read_text(
                encoding="utf-8") if (pam_d / "common-password").is_file() \
                else ""
            for hook, selected in (("fic-password-quality-hook", quality),
                                   ("fic-password-history-hook", history)):
                record = f"Module: {hook}"
                if selected:
                    require(record in password_state,
                            f"selected password hook lost its selection "
                            f"record after the recovery: {hook}")
                else:
                    require(record not in password_state,
                            f"unselected password hook must not gain a "
                            f"selection record: {hook}")
            for target, present in (("fic-password-quality", quality),
                                    ("fic-password-history", history),
                                    ("fic-password-history-initial",
                                     history)):
                if present:
                    require(canonical_include("password", target)
                            in password_stack,
                            f"selected password hook include missing from "
                            f"the generated stack: {target}")
                else:
                    require(target not in password_stack,
                            f"unselected password hook include must not "
                            f"appear in the generated stack: {target}")

        # P-A: nothing selected; a failed removal must not enable any
        # password hook (only the mandatory faillock restore runs).
        write_attached_pam_state(pam_state, pam_d)
        write_selected_password_hooks(pam_state, pam_d, False, False)
        log.unlink(missing_ok=True)
        ran = run_prerm({"FAKE_PAU_REMOVE_FAILS": "1",
                         "FAKE_PAU_PARTIAL": "1",
                         "FAKE_PAU_PARTIAL_HOOKS": partial_hooks})
        require(ran.returncode != 0,
                "prerm must report the failed removal (P-A)")
        require_hooks_attached()
        require_password_hook_state(False, False)
        require(not any(line.startswith("pam-auth-update --enable") and
                        "fic-password-" in line for line in read_calls()),
                "recovery must not enable password hooks that were "
                "unselected before the removal: " + repr(read_calls()))

        # P-B: only the quality hook was selected and the partial mutation
        # detached it: recovery must re-select exactly that hook (and never
        # the history hook), after the mandatory faillock restore.
        write_attached_pam_state(pam_state, pam_d)
        write_selected_password_hooks(pam_state, pam_d, True, False)
        log.unlink(missing_ok=True)
        ran = run_prerm({"FAKE_PAU_REMOVE_FAILS": "1",
                         "FAKE_PAU_PARTIAL": "1",
                         "FAKE_PAU_PARTIAL_HOOKS":
                             "fic-faillock-hook-preauth "
                             "fic-password-quality-hook"})
        require(ran.returncode != 0,
                "prerm must report the failed removal (P-B)")
        require_hooks_attached()
        require_password_hook_state(True, False)
        password_enables = [line for line in read_calls()
                            if line.startswith("pam-auth-update --enable")
                            and "fic-password-" in line]
        require(len(password_enables) == 1 and
                "fic-password-quality-hook" in password_enables[0] and
                "fic-password-history-hook" not in password_enables[0],
                "recovery must re-enable exactly the pre-removal password "
                "hook selection: " + repr(password_enables))
        enable_calls = [line for line in read_calls()
                        if line.startswith("pam-auth-update --enable")]
        faillock_enable_pos = next(
            i for i, line in enumerate(enable_calls)
            if "fic-faillock-hook-preauth" in line)
        password_enable_pos = next(
            i for i, line in enumerate(enable_calls)
            if "fic-password-" in line)
        require(faillock_enable_pos < password_enable_pos,
                "the mandatory faillock infrastructure restore must run "
                "before the selection-preserving password hook restore")

        # P-C: both hooks selected and the partial mutation detached both:
        # recovery must restore exactly both, with both dual-stack history
        # includes proven in the generated stack.
        write_attached_pam_state(pam_state, pam_d)
        write_selected_password_hooks(pam_state, pam_d, True, True)
        log.unlink(missing_ok=True)
        ran = run_prerm({"FAKE_PAU_REMOVE_FAILS": "1",
                         "FAKE_PAU_PARTIAL": "1",
                         "FAKE_PAU_PARTIAL_HOOKS":
                             "fic-faillock-hook-authsucc "
                             "fic-password-quality-hook "
                             "fic-password-history-hook"})
        require(ran.returncode != 0,
                "prerm must report the failed removal (P-C)")
        require_hooks_attached()
        require_password_hook_state(True, True)

        # P-D: the selection-preserving recovery itself fails (the
        # pam-auth-update --enable of the password hooks returns rc!=0 after
        # the faillock restore succeeded): the prerm must fail closed and
        # must not claim that the selection was restored.
        write_attached_pam_state(pam_state, pam_d)
        write_selected_password_hooks(pam_state, pam_d, True, True)
        log.unlink(missing_ok=True)
        ran = run_prerm({"FAKE_PAU_REMOVE_FAILS": "1",
                         "FAKE_PAU_PARTIAL": "1",
                         "FAKE_PAU_PARTIAL_HOOKS":
                             "fic-password-quality-hook "
                             "fic-password-history-hook",
                         "FAKE_PAU_PASSWORD_ENABLE_FAILS": "1"})
        require(ran.returncode != 0,
                "prerm must fail when the password hook recovery fails (P-D)")
        require("password hook recovery failed" in ran.stderr and
                "NOT proven restored" in ran.stderr,
                "prerm must state explicitly that the password hook "
                "selection is not proven restored: " + ran.stderr.strip())
        require_password_hook_state(False, False)

        # P-E: rc=0 is not trusted: the enable "succeeds" but regenerates a
        # malformed (commented) quality include, so the strict
        # resulting-state proof must fail the removal closed.
        write_attached_pam_state(pam_state, pam_d)
        write_selected_password_hooks(pam_state, pam_d, True, False)
        log.unlink(missing_ok=True)
        ran = run_prerm({"FAKE_PAU_REMOVE_FAILS": "1",
                         "FAKE_PAU_PARTIAL": "1",
                         "FAKE_PAU_PARTIAL_HOOKS":
                             "fic-password-quality-hook",
                         "FAKE_PAU_PASSWORD_MALFORMED": "1"})
        require(ran.returncode != 0,
                "prerm must not trust rc=0 from the recovery enable without "
                "the resulting-state proof (P-E)")
        require("password hook recovery failed" in ran.stderr,
                "prerm must report the failed proof as a password hook "
                "recovery failure: " + ran.stderr.strip())

        # P-S: the normal removal path with both hooks selected: the removal
        # succeeds, no dangling includes and no dangling selection records
        # remain in the generated stack or the state file.
        write_attached_pam_state(pam_state, pam_d)
        write_selected_password_hooks(pam_state, pam_d, True, True)
        log.unlink(missing_ok=True)
        ran = run_prerm()
        require(ran.returncode == 0,
                "prerm remove must succeed when pam-auth-update succeeds: " +
                ran.stderr.strip())
        require_password_hook_state(False, False)

    # Behavioral proof of the attach invariant: run the configure tail of the
    # generated postinst with fake binaries and verify the actual order:
    # pre-attach validation → pam-auth-update --package → hook enable →
    # daemon start; on validator failure no pam-auth-update and no daemon
    # start may happen at all. /opt/fic paths are redirected to PATH fakes
    # so the host system is never touched.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        package_root = tmp_path / "pkg"
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir(parents=True)
        (package_root / "DEBIAN").mkdir(parents=True)
        log = tmp_path / "postinst-calls.log"

        def fake_tool(name: str, exit_code: int) -> None:
            tool = fake_bin / name
            tool.write_text(
                "#!/bin/sh\n"
                f'printf "{name} %s\\n" "$*" >> "$FAKE_LOG"\n'
                f"exit {exit_code}\n",
                encoding="utf-8")
            tool.chmod(0o755)

        fake_tool("pam-auth-update", 0)
        fake_tool("systemctl", 0)
        fake_tool("fic", 0)
        fake_tool("fic-dick", 0)

        generated = subprocess.run(
            ["bash", "-c",
             'pkg_root="$1"; '
             'set -- 0.1.0; '
             'source "$BUILDER" >/dev/null 2>&1; '
             'write_system_integration_symlink_postinst "$pkg_root" fic '
             '"/opt/fic/bin/fic"',
             "bash", str(package_root)],
            cwd=root,
            env={"PATH": "/usr/bin:/bin",
                 "BUILDER": str(root / "packaging/deb/build-fic-debian12-deb.sh")},
            text=True,
            capture_output=True,
            check=False)
        require(generated.returncode == 0,
                "could not generate Debian postinst for the behavioral "
                "check: " + generated.stderr.strip())
        postinst_text = (package_root / "DEBIAN/postinst").read_text(
            encoding="utf-8")
        configure_start = postinst_text.find(
            'if [ "${1:-}" = "configure" ]; then')
        require(configure_start >= 0,
                "generated postinst lost its configure branch")
        configure_tail = postinst_text[configure_start:].replace(
            "/opt/fic/bin/fic-dick", "fic-dick").replace(
                "/opt/fic/bin/fic", "fic")
        tail_script = tmp_path / "configure-tail.sh"
        tail_script.write_text("#!/bin/sh\nset -e\n" + configure_tail,
                               encoding="utf-8")
        tail_script.chmod(0o755)

        # Success path: validation passes → hooks attach → daemon starts.
        ran = subprocess.run(
            [str(tail_script), "configure"],
            env={"PATH": str(fake_bin), "FAKE_LOG": str(log)},
            text=True,
            capture_output=True,
            check=False)
        require(ran.returncode == 0,
                "postinst configure tail failed under fake binaries: " +
                ran.stderr.strip())
        calls = log.read_text(encoding="utf-8").splitlines() \
            if log.is_file() else []
        validate_calls = [index for index, line in enumerate(calls)
                          if "validate-pam-slots-before-attach" in line]
        bootstrap_calls = [index for index, line in enumerate(calls)
                           if "bootstrap-pam-password-slots" in line]
        pam_package_calls = [index for index, line in enumerate(calls)
                             if line.startswith("pam-auth-update --package")]
        pam_enable_calls = [index for index, line in enumerate(calls)
                            if line.startswith("pam-auth-update --enable")]
        daemon_start_calls = [index for index, line in enumerate(calls)
                              if "enable --now fic.service" in line]
        require(bootstrap_calls and validate_calls and pam_package_calls
                and pam_enable_calls and daemon_start_calls
                and max(bootstrap_calls) < min(validate_calls)
                and max(validate_calls) < min(pam_package_calls)
                and max(pam_package_calls) < min(pam_enable_calls)
                and max(pam_enable_calls) < min(daemon_start_calls),
                "postinst attach-order regression: bootstrap, validation, "
                "pam-auth-update and daemon start are out of order: " +
                "\n".join(calls))
        enable_call = calls[min(pam_enable_calls)]
        for hook in ("fic-faillock-hook-preauth", "fic-faillock-hook-authfail",
                     "fic-faillock-hook-authsucc", "fic-faillock-hook-account"):
            require(hook in enable_call,
                    f"postinst did not enable permanent hook {hook} "
                    "in the behavioral check")

        # Failure path: the pre-attach validator refuses → exit non-zero,
        # no pam-auth-update, no daemon start. The bootstrap maintenance
        # call is a separate command and still succeeds, mirroring the real
        # exit semantics of a validation failure.
        log.unlink(missing_ok=True)
        validator_fails = fake_bin / "fic"
        validator_fails.write_text(
            "#!/bin/sh\n"
            'printf "fic %s\\n" "$*" >> "$FAKE_LOG"\n'
            'for argument in "$@"; do\n'
            '    if [ "$argument" = "validate-pam-slots-before-attach" ]; then\n'
            "        exit 1\n"
            "    fi\n"
            "done\n"
            "exit 0\n",
            encoding="utf-8")
        validator_fails.chmod(0o755)
        refused = subprocess.run(
            [str(tail_script), "configure"],
            env={"PATH": str(fake_bin), "FAKE_LOG": str(log)},
            text=True,
            capture_output=True,
            check=False)
        require(refused.returncode != 0,
                "postinst must abort when pre-attach slot validation fails")
        refused_calls = log.read_text(encoding="utf-8").splitlines() \
            if log.is_file() else []
        require(not any(line.startswith("pam-auth-update")
                        for line in refused_calls),
                "pam-auth-update ran although pre-attach validation failed")
        require(not any("enable --now" in line for line in refused_calls),
                "daemon was started although pre-attach validation failed")
        require("pre-attach validation" in refused.stderr,
                "postinst failure diagnostic must mention pre-attach "
                "validation: " + refused.stderr.strip())

        # Failure path: the managed password slot bootstrap refuses → the
        # package configuration fails closed before the pre-attach
        # validation, any pam-auth-update call, and any daemon start.
        log.unlink(missing_ok=True)
        bootstrap_fails = fake_bin / "fic"
        bootstrap_fails.write_text(
            "#!/bin/sh\n"
            'printf "fic %s\\n" "$*" >> "$FAKE_LOG"\n'
            'for argument in "$@"; do\n'
            '    if [ "$argument" = "bootstrap-pam-password-slots" ]; then\n'
            "        exit 1\n"
            "    fi\n"
            "done\n"
            "exit 0\n",
            encoding="utf-8")
        bootstrap_fails.chmod(0o755)
        bootstrap_refused = subprocess.run(
            [str(tail_script), "configure"],
            env={"PATH": str(fake_bin), "FAKE_LOG": str(log)},
            text=True,
            capture_output=True,
            check=False)
        require(bootstrap_refused.returncode != 0,
                "postinst must abort when managed password slot bootstrap "
                "fails")
        bootstrap_refused_calls = log.read_text(encoding="utf-8").splitlines() \
            if log.is_file() else []
        require(not any(line.startswith("pam-auth-update")
                        for line in bootstrap_refused_calls),
                "pam-auth-update ran although the managed password slot "
                "bootstrap failed")
        require(not any("validate-pam-slots-before-attach" in line
                        for line in bootstrap_refused_calls),
                "pre-attach validation ran although the managed password "
                "slot bootstrap failed")
        require(not any("enable --now" in line
                        for line in bootstrap_refused_calls),
                "daemon was started although the managed password slot "
                "bootstrap failed")
        require("bootstrap" in bootstrap_refused.stderr,
                "postinst bootstrap failure diagnostic must mention the "
                "bootstrap: " + bootstrap_refused.stderr.strip())

    # Behavioral proof of the abort-remove recovery invariant: run the full
    # generated postinst with `abort-remove` against fake binaries and
    # verify the actual recovery call set/order (daemon-reload → enable →
    # start) and that nothing from the configure path runs (no PAM
    # operations, no maintenance commands, no service stop/restart).
    # Every non-systemd helper (getent, groupadd, mkdir, ...) is a logging
    # no-op fake, so even a broken early exit can never touch the host.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        package_root = tmp_path / "pkg"
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir(parents=True)
        (package_root / "DEBIAN").mkdir(parents=True)
        log = tmp_path / "abort-remove-calls.log"
        state_dir = tmp_path / "systemd-state"
        state_dir.mkdir()

        def fake_tool(name: str) -> None:
            tool = fake_bin / name
            tool.write_text(
                "#!/bin/sh\n"
                f'printf "{name} %s\\n" "$*" >> "$FAKE_LOG"\n'
                "exit 0\n",
                encoding="utf-8")
            tool.chmod(0o755)

        def stateful_systemctl() -> None:
            # State model (pure shell builtins, works on a fakes-only PATH):
            # active/enabled markers are files in $FAKE_STATE; stop/restart
            # always fail (the failed-prerm scenario: a live writer refuses
            # to stop); start/enable/is-active honor FAKE_START_FAILS /
            # FAKE_ENABLE_FAILS / FAKE_IS_ACTIVE_FAILS for failure
            # injection.
            fake = fake_bin / "systemctl"
            fake.write_text(
                "#!/bin/sh\n"
                'printf "systemctl %s\\n" "$*" >> "$FAKE_LOG"\n'
                "action=$1\n"
                'for unit in "$@"; do :; done\n'
                "state=$FAKE_STATE\n"
                'if [ "$action" = "is-active" ]; then\n'
                '    if [ "$unit" = "$FAKE_IS_ACTIVE_FAILS" ]; then\n'
                "        exit 1\n"
                "    fi\n"
                '    if [ -f "$state/active-$unit" ]; then\n'
                "        exit 0\n"
                "    fi\n"
                "    exit 1\n"
                "fi\n"
                'if [ "$action" = "start" ]; then\n'
                '    if [ "$unit" = "$FAKE_START_FAILS" ]; then\n'
                "        exit 1\n"
                "    fi\n"
                '    : > "$state/active-$unit"\n'
                "    exit 0\n"
                "fi\n"
                'if [ "$action" = "stop" ] || [ "$action" = "restart" ]; then\n'
                "    exit 1\n"
                "fi\n"
                'if [ "$action" = "enable" ]; then\n'
                '    if [ "$unit" = "$FAKE_ENABLE_FAILS" ]; then\n'
                "        exit 1\n"
                "    fi\n"
                '    : > "$state/enabled-$unit"\n'
                "    exit 0\n"
                "fi\n"
                "exit 0\n",
                encoding="utf-8")
            fake.chmod(0o755)

        def fresh_state(fic_active: bool) -> None:
            # Post-failed-prerm state: the failed prerm disabled everything
            # and stopped fic-device/fic-notify; fic.service could not be
            # stopped, so it is still active (but disabled).
            for stale in state_dir.glob("*"):
                stale.unlink()
            if fic_active:
                (state_dir / "active-fic.service").write_text("")

        def run_abort(overrides=None) -> subprocess.CompletedProcess:
            env = {"PATH": f"{fake_bin}:/usr/bin:/bin",
                   "FAKE_LOG": str(log),
                   "FAKE_STATE": str(state_dir),
                   "FAKE_START_FAILS": "", "FAKE_ENABLE_FAILS": "",
                   "FAKE_IS_ACTIVE_FAILS": ""}
            if overrides:
                env.update(overrides)
            return subprocess.run(
                [str(postinst_path), "abort-remove"],
                env=env, text=True, capture_output=True, check=False)

        for name in ("getent", "groupadd", "mkdir", "chown", "find", "ln",
                     "systemd-tmpfiles", "udevadm", "pam-auth-update",
                     "fic", "fic-dick"):
            fake_tool(name)
        stateful_systemctl()

        generated = subprocess.run(
            ["bash", "-c",
             'pkg_root="$1"; '
             'set -- 0.1.0; '
             'source "$BUILDER" >/dev/null 2>&1; '
             'write_system_integration_symlink_postinst "$pkg_root" fic '
             '"/opt/fic/bin/fic"',
             "bash", str(package_root)],
            cwd=root,
            env={"PATH": "/usr/bin:/bin",
                 "BUILDER": str(root / "packaging/deb/build-fic-debian12-deb.sh")},
            text=True,
            capture_output=True,
            check=False)
        postinst_path = package_root / "DEBIAN/postinst"
        require(generated.returncode == 0 and postinst_path.is_file(),
                "could not generate Debian postinst for the abort-remove "
                "behavioral check: " + generated.stderr.strip())

        # The read-only permanent hook guard inspects the standard
        # pam-auth-update state; sandbox those paths so the host is never
        # touched, and seed the installed-package state (all four permanent
        # hooks attached).
        pam_state = tmp_path / "pam-state"
        pam_d = tmp_path / "pam.d"
        postinst_text = postinst_path.read_text(encoding="utf-8")
        postinst_path.write_text(
            sandbox_pam_paths(postinst_text, pam_state, pam_d),
            encoding="utf-8")
        write_attached_pam_state(pam_state, pam_d)

        # Test A: abort-remove must not go through the configure path. All
        # non-systemd helpers are logging fakes, so any configure-path step
        # (group setup, /opt/fic mutations, PAM operations, maintenance
        # commands) would appear in the log even though it would be a no-op.
        fresh_state(fic_active=True)
        log.unlink(missing_ok=True)
        ran = run_abort()
        require(ran.returncode == 0,
                "postinst abort-remove must restore the package and exit 0: " +
                ran.stderr.strip())
        calls = log.read_text(encoding="utf-8").splitlines() \
            if log.is_file() else []
        require(calls and all(line.startswith("systemctl ") for line in calls),
                "abort-remove reached a non-systemd (configure path) "
                "command: " + "\n".join(calls))
        for required in ("systemctl daemon-reload",
                         "systemctl enable fic.service",
                         "systemctl enable fic-device.service",
                         "systemctl enable fic-notify.service",
                         "systemctl enable fic_get_device_udev_info.service",
                         "systemctl start fic.service",
                         "systemctl start fic-device.service",
                         "systemctl start fic-notify.service"):
            require(required in calls,
                    f"abort-remove recovery did not run: {required}")
        for forbidden in (" stop ", " restart ", "disable",
                          "pam-auth-update", "ensure-config", "check-config",
                          "initialize-db", "trust-sync",
                          "validate-pam-slots-before-attach"):
            require(not any(forbidden in line for line in calls),
                    f"abort-remove ran a forbidden operation "
                    f"({forbidden.strip()}): " + "\n".join(calls))

        # Test B: live fic.service recovery. fic.service is active but
        # disabled and physically refuses manual stops (fake systemctl
        # fails any stop/restart); fic-device/fic-notify are inactive and
        # disabled. Recovery must rely on idempotent enable/start only and
        # finish with all FIC services active and enabled again.
        fresh_state(fic_active=True)
        log.unlink(missing_ok=True)
        ran = run_abort()
        require(ran.returncode == 0,
                "abort-remove must succeed while fic.service refuses to "
                "stop: " + ran.stderr.strip())
        calls = log.read_text(encoding="utf-8").splitlines() \
            if log.is_file() else []
        require(all(line.startswith("systemctl ") for line in calls),
                "abort-remove recovery ran non-systemd commands: " +
                "\n".join(calls))
        reload_positions = [index for index, line in enumerate(calls)
                            if line == "systemctl daemon-reload"]
        enable_positions = [index for index, line in enumerate(calls)
                            if line.startswith("systemctl enable ")]
        start_positions = [index for index, line in enumerate(calls)
                           if line.startswith("systemctl start ")]
        require(reload_positions and enable_positions and start_positions
                and max(reload_positions) < min(enable_positions)
                and max(enable_positions) < min(start_positions),
                "abort-remove recovery ordering regression "
                "(daemon-reload → enable → start): " + "\n".join(calls))
        for unit in ("fic.service", "fic-device.service", "fic-notify.service"):
            require(f"systemctl start {unit}" in calls,
                    f"abort-remove did not start {unit}")
        for unit in ("fic.service", "fic-device.service",
                     "fic-notify.service"):
            require(f"systemctl is-active --quiet {unit}" in calls,
                    f"abort-remove did not prove {unit} active")
        for unit in ("fic.service", "fic-device.service",
                     "fic-notify.service"):
            require((state_dir / f"active-{unit}").is_file(),
                    f"abort-remove did not restore runtime state of {unit}")
        for unit in ("fic.service", "fic-device.service",
                     "fic-notify.service", "fic_get_device_udev_info.service"):
            require((state_dir / f"enabled-{unit}").is_file(),
                    f"abort-remove did not restore enablement of {unit}")

        # Test C: a critical FIC writer that cannot be started again is a
        # genuine recovery failure: abort-remove must exit non-zero with a
        # diagnostic naming the unit instead of pretending success.
        fresh_state(fic_active=False)
        log.unlink(missing_ok=True)
        failed = run_abort({"FAKE_START_FAILS": "fic-device.service"})
        require(failed.returncode != 0,
                "abort-remove must fail when a critical FIC writer cannot "
                "be restored")
        require("fic-device.service" in failed.stderr,
                "abort-remove failure diagnostic must name the critical "
                "unit: " + failed.stderr.strip())

        # Test D: mandatory fic-notify.service. Normal configure starts it
        # strictly (`systemctl enable --now` under `set -e`), so a failing
        # enable or start of fic-notify.service must fail the recovery.
        fresh_state(fic_active=False)
        log.unlink(missing_ok=True)
        failed = run_abort({"FAKE_ENABLE_FAILS": "fic-notify.service"})
        require(failed.returncode != 0,
                "abort-remove must fail when fic-notify.service cannot be "
                "re-enabled (mandatory service)")
        require("fic-notify.service" in failed.stderr,
                "abort-remove diagnostic must name fic-notify.service: " +
                failed.stderr.strip())
        fresh_state(fic_active=False)
        log.unlink(missing_ok=True)
        failed = run_abort({"FAKE_START_FAILS": "fic-notify.service"})
        require(failed.returncode != 0,
                "abort-remove must fail when fic-notify.service cannot be "
                "started (mandatory service)")
        require("fic-notify.service" in failed.stderr,
                "abort-remove diagnostic must name fic-notify.service: " +
                failed.stderr.strip())
        # A start that "succeeds" but leaves the unit inactive must fail the
        # final activity proof as well.
        fresh_state(fic_active=False)
        log.unlink(missing_ok=True)
        failed = run_abort({"FAKE_IS_ACTIVE_FAILS": "fic-notify.service"})
        require(failed.returncode != 0,
                "abort-remove must fail when fic-notify.service is left "
                "inactive")
        require("fic-notify.service inactive" in failed.stderr,
                "abort-remove diagnostic must name the inactive unit: " +
                failed.stderr.strip())

        # Test E: when the prerm-side PAM recovery did not succeed, the
        # permanent hooks are not proven attached and abort-remove must
        # refuse to restart any FIC writer (read-only guard) instead of
        # silently starting a daemon on top of a partially detached PAM
        # graph. dpkg then keeps the package in the error state for manual
        # administrator recovery.
        stateful_systemctl()
        detached_state = tmp_path / "pam-state-detached"
        detached_d = tmp_path / "pam.d-detached"
        detached_state.mkdir()
        detached_d.mkdir()
        # Simulate a partially detached state: hooks deselected, stacks
        # regenerated without the permanent hook targets.
        (detached_state / "auth").write_text("", encoding="utf-8")
        (detached_state / "account").write_text("", encoding="utf-8")
        (detached_d / "common-auth").write_text("", encoding="utf-8")
        (detached_d / "common-account").write_text("", encoding="utf-8")
        postinst_path.write_text(
            sandbox_pam_paths(postinst_text, detached_state, detached_d),
            encoding="utf-8")
        fresh_state(fic_active=False)
        log.unlink(missing_ok=True)
        failed = run_abort()
        require(failed.returncode != 0,
                "abort-remove must refuse to restore FIC services when the "
                "permanent PAM hooks are not proven attached")
        require("not proven attached" in failed.stderr,
                "abort-remove guard diagnostic must state the unproven PAM "
                "state: " + failed.stderr.strip())
        guard_calls = log.read_text(encoding="utf-8").splitlines() \
            if log.is_file() else []
        require(not any(" start " in line or " enable " in line
                        for line in guard_calls),
                "abort-remove restarted FIC writers over an unproven PAM "
                "state: " + "\n".join(guard_calls))

        # Test F (hardened physical proof): the selection records look
        # correct, but the generated common-auth hook includes are
        # malformed (commented / wrong facility). The strict read-only
        # guard must fail the proof and refuse to enable or start any FIC
        # writer (fail-closed abort-remove).
        for malformed in ("commented", "wrong-facility"):
            malformed_state = tmp_path / f"pam-state-malformed-{malformed}"
            malformed_d = tmp_path / f"pam.d-malformed-{malformed}"
            malformed_state.mkdir()
            malformed_d.mkdir()
            # Correct Module: selection records in the correct facilities.
            (malformed_state / "auth").write_text(
                "".join(f"Module: {hook}\ninclude {hook_target(hook)}\n"
                        for hook in AUTH_HOOKS),
                encoding="utf-8")
            (malformed_state / "account").write_text(
                f"Module: {PERMANENT_HOOKS[3]}\n"
                f"include {hook_target(PERMANENT_HOOKS[3])}\n",
                encoding="utf-8")
            # Correct account stack, malformed auth hook lines only.
            (malformed_d / "common-account").write_text(
                canonical_include("account",
                                  hook_target(PERMANENT_HOOKS[3])),
                encoding="utf-8")
            if malformed == "commented":
                (malformed_d / "common-auth").write_text(
                    "".join("# " + canonical_include("auth",
                                                     hook_target(hook))
                            for hook in AUTH_HOOKS),
                    encoding="utf-8")
            else:
                (malformed_d / "common-auth").write_text(
                    "".join(canonical_include("account",
                                              hook_target(hook))
                            for hook in AUTH_HOOKS),
                    encoding="utf-8")
            postinst_path.write_text(
                sandbox_pam_paths(postinst_text, malformed_state,
                                  malformed_d),
                encoding="utf-8")
            fresh_state(fic_active=False)
            log.unlink(missing_ok=True)
            failed = run_abort()
            require(failed.returncode != 0,
                    f"abort-remove must fail the strict physical proof "
                    f"when the generated hook line is malformed "
                    f"({malformed})")
            require("not proven attached" in failed.stderr,
                    f"abort-remove diagnostic must state the unproven PAM "
                    f"state for malformed physical hooks ({malformed}): " +
                    failed.stderr.strip())
            guard_calls = log.read_text(encoding="utf-8").splitlines() \
                if log.is_file() else []
            require(not any(" start " in line or " enable " in line
                            for line in guard_calls),
                    f"abort-remove enabled or started FIC writers over a "
                    f"malformed physical hook state ({malformed}): " +
                    "\n".join(guard_calls))

        # Restore the attached-state postinst for consistency.
        postinst_path.write_text(
            sandbox_pam_paths(postinst_text, pam_state, pam_d),
            encoding="utf-8")

    require('if [ "\\$1" = "remove" ]; then' in fic_prerm,
            "PAM profile removal is not limited to package removal")
    require('if [ "\\${1:-}" = "configure" ]; then' in fic_postinst,
            "PAM profile registration is not limited to postinst configure")
    require("pam-auth-update" not in generic_prerm,
            "CLI/GUI package removal must not unregister fic PAM profiles")
    require("pam-auth-update --force" not in deb_builder,
            "maintainer scripts must not force PAM regeneration")
    require("pam-auth-update --enable" in fic_postinst,
            "Debian postinst does not enable permanent faillock hooks")
    for hook in (
        "fic-faillock-hook-preauth",
        "fic-faillock-hook-authfail",
        "fic-faillock-hook-authsucc",
        "fic-faillock-hook-account",
    ):
        require(hook in fic_postinst,
                f"Debian postinst does not enable permanent hook {hook}")
    for legacy_policy_profile in (
        "fic-faillock-notify",
        "fic-faillock-preauth-required",
        "fic-faillock-authsucc",
        "fic-pwquality",
        "fic-pwhistory",
    ):
        enable_pos = fic_postinst.find("pam-auth-update --enable")
        require(legacy_policy_profile not in fic_postinst[enable_pos:],
                f"postinst must not activate policy-owned legacy profile {legacy_policy_profile}")

    for forbidden in ("pam-auth-update", "libpam-runtime", "libpam-modules", "pam-configs/fic-"):
        require(forbidden not in rpm_builder, f"ALT packaging contains Debian PAM integration: {forbidden}")
        require(forbidden not in fic_cmake, f"generic CMake installs Debian PAM integration: {forbidden}")

    require(rpm_facility_path.is_file() and not rpm_facility_path.is_symlink(),
            "ALT fic-pam-faillock facility is missing")
    require(rpm_facility_path.stat().st_mode & 0o111,
            "ALT fic-pam-faillock facility is not executable")
    for operation in ("help", "list", "summary", "status", "enabled", "disabled"):
        require(operation in rpm_facility,
                f"ALT facility does not implement control operation: {operation}")
    require(". /etc/control.d/functions" in rpm_facility and
            "new_help enabled" in rpm_facility and
            "new_help disabled" in rpm_facility,
            "ALT facility does not use the native control protocol")
    require("--maintenance pam-alt-faillock" in rpm_facility,
            "ALT facility does not dispatch to the FIC PAM helper")
    for forbidden in ("sed ", "sed\t", "pam_faillock.so", "pam_tcb.so"):
        require(forbidden not in rpm_facility,
                f"ALT facility contains topology implementation: {forbidden}")

    require(rpm_history_facility_path.is_file() and
            not rpm_history_facility_path.is_symlink(),
            "ALT fic-pam-pwhistory facility is missing")
    require(rpm_history_facility_path.stat().st_mode & 0o111,
            "ALT fic-pam-pwhistory facility is not executable")
    for operation in ("help", "list", "summary", "status", "enabled", "disabled"):
        require(operation in rpm_history_facility,
                f"ALT password-history facility lacks operation: {operation}")
    require("--maintenance pam-alt-pwhistory" in rpm_history_facility,
            "ALT password-history facility does not dispatch to FIC")
    for forbidden in ("sed ", "sed\t", "pam_tcb.so"):
        require(forbidden not in rpm_history_facility,
                f"ALT password-history facility implements topology: {forbidden}")

    rpm_fic_package = function_body(rpm_builder, "build_fic_package")
    require('"$ROOT_DIR/packaging/rpm/fic-pam-faillock"' in rpm_fic_package and
            '"$package_root/etc/control.d/facilities/fic-pam-faillock"' in rpm_fic_package,
            "ALT fic package does not stage its control facility")
    require('"$ROOT_DIR/packaging/rpm/fic-pam-pwhistory"' in rpm_fic_package and
            '"$package_root/etc/control.d/facilities/fic-pam-pwhistory"' in rpm_fic_package,
            "ALT fic package does not stage its password-history facility")
    for dependency in ("control", "pam >= 1.7.1", "pam-config >= 1.10.0"):
        require(dependency in rpm_fic_package,
                f"ALT fic package lacks PAM facility dependency: {dependency}")
    for facility in ("fic-pam-faillock", "fic-pam-pwhistory"):
        require(f"control-dump {facility}" in rpm_builder and
                f"control-restore {facility}" in rpm_builder,
                f"ALT RPM upgrade does not preserve {facility} state")
    require('if [ "$1" -eq 0 ]; then' in
            function_body(rpm_builder, "fic_pam_facility_preun_script") and
            "control fic-pam-faillock disabled" in rpm_builder and
            "control fic-pam-pwhistory disabled" in rpm_builder,
            "ALT RPM final erase does not remove FIC-owned PAM topology")
    post_hook = function_body(rpm_builder, "fic_pam_facility_post_script")
    require("control fic-pam-faillock enabled" not in post_hook and
            "control fic-pam-pwhistory enabled" not in post_hook and
            "pam-alt-pwhistory prepare" in post_hook and
            "control-restore" in post_hook,
            "ALT RPM install must prepare storage without enabling PAM topology")
    require("%config(noreplace)" in rpm_builder and
            "/etc/security/fic-pwhistory.conf" in rpm_builder,
            "ALT pam_pwhistory config is not preserved across upgrades")
    require("pam_fic_pwtxn" in fic_cmake and
            "fic-pwhistory.conf" in fic_cmake,
            "ALT PAM transaction module/config are not installed by CMake")
    require("fic-pam-passwdqc" not in rpm_builder,
            "ALT RPM must not install unsupported PAM facilities")

    print("PAM packaging checks passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"PAM packaging checks failed: {error}", file=sys.stderr)
        sys.exit(1)
