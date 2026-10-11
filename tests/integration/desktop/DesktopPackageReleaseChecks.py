#!/usr/bin/env python3
"""Exercise generated DE erase gates with isolated helpers, never host PAM/systemd."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("pam_packaging_fixture", root / "tests/integration/packaging/PamPackagingChecks.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

with tempfile.TemporaryDirectory(prefix="fic-de-package-") as directory:
    work = Path(directory)
    package = work / "package"
    (package / "DEBIAN").mkdir(parents=True)
    scripts = {}
    result = subprocess.run(["bash", "-c",
        'builder="$1"; package="$2"; set -- 0.1.0; source "$builder"; write_system_integration_symlink_prerm "$package" fic /opt/fic/bin/fic',
        "bash", str(root / "packaging/deb/build-fic-debian12-deb.sh"), str(package)],
        text=True, capture_output=True)
    fixture.require(result.returncode == 0, "DEB prerm generation failed: " + result.stderr)
    scripts["deb"] = (package / "DEBIAN/prerm").read_text()
    rpm = (root / "packaging/rpm/build-fic-alt-p11-rpm.sh").read_text()
    library = "\n".join(name + "() {\n" + fixture.function_body(rpm, name) + "\n}\n" for name in
        ("system_integration_symlink_preun_script", "fic_pam_facility_preun_script", "fic_pam_provider_post_stop_preun_script"))
    result = subprocess.run(["bash", "-c", library + '\nsystem_integration_symlink_preun_script fic /opt/fic/bin/fic "$(fic_pam_facility_preun_script)" "$(fic_pam_provider_post_stop_preun_script)"'],
        text=True, capture_output=True)
    fixture.require(result.returncode == 0, "RPM preun generation failed: " + result.stderr)
    scripts["rpm"] = result.stdout
    helpers = work / "helpers"
    helpers.mkdir()
    log = work / "calls"
    maintenance = helpers / "fic"
    maintenance.write_text(fixture.fake_maintenance_helper())
    maintenance.chmod(0o755)
    for name in ("systemctl", "control", "pam-auth-update"):
        helper = helpers / name
        helper.write_text('#!/bin/sh\nprintf "' + name + ' %s\\n" "$*" >> "$FAKE_LOG"\n'
            + ('case "$1" in is-active) exit 1;; esac\n' if name == "systemctl" else '') + 'exit 0\n')
        helper.chmod(0o755)
    pam_state, pam_d = work / "pam-state", work / "pam-d"
    pam_state.mkdir(); pam_d.mkdir()
    (pam_d / "sentinel").write_text("foreign PAM state\n")
    for kind, text in scripts.items():
        text = text.replace("/opt/fic/bin/fic", str(maintenance)).replace("/var/lib/pam", str(pam_state)).replace("/etc/pam.d", str(pam_d))
        text = text.replace("/bin/fic", str(work / "command-link"))
        for path in ("/usr/bin/systemctl", "/usr/sbin/systemctl", "/sbin/systemctl", "/bin/systemctl"):
            text = text.replace(path, str(helpers / "systemctl"))
        text = text.replace("/usr/sbin/control", str(helpers / "control"))
        script = work / (kind + "-erase.sh")
        script.write_text(text)
        for mode in ("preflight-fail", "release-fail"):
            log.write_text("")
            before = fixture.pam_state_digest(pam_state, pam_d)
            env = {**os.environ, "PATH": str(helpers) + ":/usr/bin:/bin", "FAKE_LOG": str(log),
                "FAKE_PAM_STATE": str(pam_state), "FAKE_PAM_D": str(pam_d),
                "FIC_FAKE_HELPER_MODE": "", "FIC_FAKE_PROVIDER_MODE": "", "FIC_FAKE_DESKTOP_MODE": mode}
            result = subprocess.run(["sh", str(script), "remove" if kind == "deb" else "0"],
                env=env, text=True, capture_output=True)
            calls = log.read_text()
            fixture.require(result.returncode != 0, kind + " accepted failed DE " + mode)
            fixture.require(before == fixture.pam_state_digest(pam_state, pam_d), "DE failure changed foreign PAM state")
            fixture.require("incident-pam-alt detach" not in calls and "pam-auth-update" not in calls, "DE failure detached account access gate")
            if mode == "preflight-fail":
                fixture.require("systemctl" not in calls and "control " not in calls and "desktop-prerm-prepare release" not in calls,
                    "DE preflight failure stopped writers or attempted release")
            else:
                fixture.require(calls.index("systemctl") < calls.index("desktop-prerm-prepare release"), "DE release ran before writer stop")
    print("PASS: generated DEB/RPM DE preflight and release failures preserve foreign state")
