#!/usr/bin/env python3
"""Guard the daemon apply entrypoints that must report policy incidents."""

from pathlib import Path
import re

main = (Path(__file__).resolve().parents[3] / "fic/src/main.cpp").read_text()
for command in ("apply_all", "apply_module", "apply_policy"):
    start = main.index(f'if (command == "{command}")')
    end = main.index('return policy_apply_summary_json(', start)
    body = main[start:end]
    assert re.search(r'PolicyIncidentReporter\(incidentController\(\)\)\.report\(', body), command

start = main.index('bool run_daemon_apply_all_pass(')
end = main.index('return ok;', start)
assert 'PolicyIncidentReporter(incidentController()).report(' in main[start:end]
