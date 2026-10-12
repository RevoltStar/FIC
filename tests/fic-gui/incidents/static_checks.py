#!/usr/bin/env python3
"""Guard localization coverage and GUI-only incident ownership."""
import re
import sys
from pathlib import Path
root = Path(sys.argv[1])
area = root / 'fic-gui/src/features/incidents'
text = '\n'.join(p.read_text() for p in area.rglob('*.cpp'))
keys = set(re.findall(r'trIR\("([a-z_]+)"\)', text))
# Conditional tokens are selected at runtime.
keys |= {'action_ok','action_failed','proven','unproven','connected','connection_error','reported_yes','reported_no','yes','no','title','refresh','time','event','previous','final','source','reason','result'}
for lang in ('ru','en'):
    bundle = (root / f'fic/src/resources/lang/{lang}.lang').read_text()
    for key in keys:
        assert re.search(r'^\[incident:' + key + r'\]\s*=\s*\S', bundle, re.M), (lang,key)
for forbidden in ('IncidentController', 'ProcessExecutor', 'system(', 'QProcess', '/etc/', 'Policy::apply'):
    assert forbidden not in text, forbidden
print(f'Incident localization and ownership checks passed: {len(keys)} keys in RU/EN')

controller = (root / 'fic/src/incident/IncidentController.cpp').read_text()
parser = (area / 'models/IncidentAuditModel.cpp').read_text()
for token in set(re.findall(r'recordAudit\(\s*"(incident_[a-z_]+)"', controller)):
    assert f'"{token}"' in parser, token
assert 'LogService' not in parser and 'parseLogLine' not in parser
assert 'next_cursor' in (area / 'services/IncidentHistoryService.cpp').read_text()
