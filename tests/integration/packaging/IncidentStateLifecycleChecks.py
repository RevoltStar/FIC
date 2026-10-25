#!/usr/bin/env python3
"""Static package authority and installation ordering checks, no host mutation."""
from pathlib import Path
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[3]
def require(condition,message):
    if not condition:raise AssertionError(message)
def main():
    startup=(ROOT/'fic/src/main.cpp').read_text()
    attach=startup[startup.index('if (command == "validate-pam-slots-before-attach")'):
                   startup.index('if (command == "bootstrap-pam-password-slots")')]
    require('checkPackagePasswordTopology(' in attach and 'validatePamPasswordSlotAttach(' not in attach,
            'current C2 package validation must not use the obsolete pair-slot contract')
    proof=(ROOT/'fic/src/daemon/InstallationProof.cpp').read_text()
    require('PamPasswordPackageRelease::Mode::Preflight' in proof and
            proof.count('checkPackagePasswordTopology(platform,executables,error)')==2,
            'installation completion must repeat the existing read-only C2 ownership proof')
    cmake=(ROOT/'fic/CMakeLists.txt').read_text()
    require('install(DIRECTORY DESTINATION "${FIC_CONFIG_DIR}"' not in cmake,
            'package must not own recovery configuration directory')
    for kind,name in [('deb','fic.postinst'),('rpm','fic.post')]:
        source=(ROOT/'packaging'/kind/'lifecycle'/name).read_text()
        require(source.index('systemctl daemon-reload')<source.index('fic-package-infrastructure prepare-install'),
                'unpacked unit definitions must be refreshed before writer inspection')
        require(source.count('--maintenance incident-init')==1,'only main package initializes incident state')
        require('chown -R' not in source and 'chmod -R' not in source and 'find /opt/fic' not in source,
                'package scripts must not repair persistent authority recursively')
        require('mkdir -p /opt/fic/config' not in source,'package script cannot create recovery authority')
        require('chown root:fic /opt/fic' in source and 'chmod 2750 /opt/fic' in source,
                'root-controlled security parent initialization missing')
        require("stat -c '%u' /opt/fic" in source and '" = 0 ]' in source,'untrusted parent must not be adopted')
        first=source.index('config_command=ensure-config')
        require(first<source.index('--maintenance incident-init')<source.index('--maintenance complete-install')<
                source.index('systemctl start fic.service'),'installation proof must precede service startup')
        require('[ ! -e /opt/fic/config ] && [ ! -L /opt/fic/config ]' in source and
                '[ ! -e /opt/fic/lockstatus ] && [ ! -L /opt/fic/lockstatus ]' in source,
                'fresh initialization must not repair existing recovery state')
    rpm=(ROOT/'packaging/rpm/build-fic-alt-p11-rpm.sh').read_text()
    dick_pre=(ROOT/'packaging/rpm/lifecycle/fic-dick.pre').read_text()
    require('"$(fic_dick_pre_script)"' in rpm and 'elif [ "$1" != 1 ]' in dick_pre and
            'fic-package-infrastructure prepare-install' in dick_pre and
            '/opt/fic/config' not in dick_pre,
            'dependency bootstrap must defer retained-state proof to the installed helper, rejecting helperless upgrades')
    manifest_function = re.search(r'^write_file_list\(\) \{.*?^\}',
                                  rpm, re.MULTILINE | re.DOTALL)
    require(manifest_function is not None, "RPM manifest generator missing")
    with tempfile.TemporaryDirectory() as temp:
        package_root = Path(temp) / "package"
        (package_root / "opt/fic/bin").mkdir(parents=True)
        (package_root / "opt/fic/config").mkdir()
        (package_root / "opt/fic/bin/fic").write_text("fixture")
        manifest = Path(temp) / "manifest"
        subprocess.run(["bash", "-c", manifest_function.group(0) +
                        '\nwrite_file_list "$1" "$2"', "bash",
                        str(package_root), str(manifest)], check=True)
        listed = manifest.read_text().splitlines()
        require("%dir /opt/fic" not in listed and
                "%dir /opt/fic/config" not in listed and
                "%dir /opt/fic/bin" in listed and "/opt/fic/bin/fic" in listed,
                "RPM manifest must leave security parent unowned and retain children")

    print('PASS: persistent authority not repaired; complete-install precedes start; RPM leaves recovery parent unowned')
if __name__=='__main__':main()
