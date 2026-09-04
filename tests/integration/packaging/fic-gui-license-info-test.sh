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
grep -Fq 'distributed by FIC under GNU LGPL version 3 where that license option applies' \
    <<<"${output}"
grep -Fq 'alternative Qt licensing options and licenses of embedded third-party components' \
    <<<"${output}"
grep -Fq 'distribution notices, the provenance manifest' <<<"${output}"
grep -Fq '/usr/share/doc/fic-gui/' <<<"${output}"
