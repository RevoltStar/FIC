#!/bin/bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 /path/to/fic-gui" >&2
    exit 2
fi

output="$(env -u DISPLAY -u WAYLAND_DISPLAY QT_QPA_PLATFORM=fic-invalid \
    "$1" --license-info)"

grep -Fq 'FIC is licensed under the Sustainable Use License 1.0.' <<<"${output}"
grep -Fq 'fic-gui uses Qt as separately licensed third-party software.' <<<"${output}"
grep -Fq 'applicable Qt open-source license terms' <<<"${output}"
grep -Fq 'LGPLv3-compatible distribution path where applicable' <<<"${output}"
grep -Fq 'alternative or additional license terms' <<<"${output}"
grep -Fq 'package notices, the provenance manifest' <<<"${output}"
grep -Fq '/usr/share/doc/fic-gui/' <<<"${output}"
