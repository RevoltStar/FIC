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

# Guard the actual production callback, not a duplicate fixture implementation.
# The planner test separately checks forwarding, disabled/Required guards and
# independent application. Pin this small callback so a missing classification
# or an accidental backend call cannot pass merely because the fixture is correct.
startup_pass = main[start:end]
callback = re.search(
    r'if \(startupDevice && !startupDevice->ready\(\)\) \{\s*'
    r'startupAdmission = \[&\]\(const PolicyRef& ref, Policy&\) -> std::optional<PolicyApplyResult> \{'
    r'(?P<body>.*?)\n\s*\};', startup_pass, re.S)
assert callback, 'missing production startup device admission callback'
expected = '''
    // Detector severity settings are not udev configuration: they only
    // validate their own configured value, so they are applied even
    // while the device daemon is not ready.
    if (ref.moduleName != "DC" ||
        ref.policyName == "permanent_device_missing_severity" ||
        ref.policyName == "static_device_present_severity" ||
        ref.policyName == "device_block_failed_severity")
        return std::nullopt;
    PolicyApplyResult result{ref.moduleName, ref.submoduleName, ref.policyName,
        PolicyApplyStatus::Failed, startupDevice->diagnostic};
    result.failureOrigin = PolicyFailureOrigin::ExecutionInfrastructureFailure;
    result.ownApplyAttempted = false;
    return result;
'''
assert re.sub(r'\s+', '', callback['body']) == re.sub(r'\s+', '', expected), \
    'startup-blocked DC must be an infrastructure failure without own apply'
assert re.search(
    r'applyAllPoliciesExceptModule\(\s*policyRegistry, "FIREWALL", std::move\(startupAdmission\)\)',
    startup_pass), 'startup admission callback must reach the production planner'
