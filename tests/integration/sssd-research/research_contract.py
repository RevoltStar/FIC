"""Static research contract; no native execution or production dependency."""
import copy
import hashlib
import json
import re
from pathlib import Path

PROOFS = {'A': 'Inputs', 'B': 'Activation', 'C': 'Semantics', 'P': 'Persistent'}
GATES = {
    'I1': {'launch-phase-change', 'conf-d-capture-race', 'late-foreign-snippet'},
    'I2': {'provider-scope-coverage', 'scope-receipt-change', 'effective-relation'},
    'I3': {'launch-phase-change', 'conf-d-capture-race', 'mount-topology',
           'activation-timeouts', 'cleanup-outcomes', 'runtime-effect-unknown'},
    'I4': {'prepared-crash-recovery', 'refresh-ownership'},
    'I5': {'release-with-foreign-inputs', 'release-runtime-faults'},
    'I6': {'package-policy-e2e', 'deployment-native'},
}


def require(condition, diagnostic):
    if not condition:
        raise ValueError(diagnostic)


def validate_metadata(metadata, records):
    require(metadata['schema'] == 'sssd-research-contract-v1', 'unknown contract')
    require(metadata['proofs'] == PROOFS, 'A/B/C/P meaning changed')
    require(metadata['admission_is_separate'], 'admission is not A')
    require(not metadata['generic_success_is_policy_success'], 'generic result is not policy success')
    for key in ('policy_success_requires_all_proofs', 'cleanup_failure_blocks_success',
                'new_transaction_requires_journal_finalization', 'current_runtime_receipt_may_avoid_restart'):
        require(metadata[key], key)
    require(not metadata['native_reexecuted_in_followup'], 'follow-up is evidence-only')
    env = metadata['environment']
    require(env['engine'] == 'Docker' and env['pid1'] == 'systemd', 'record actual environment')
    require(not env['podman_equivalence_proven'] and not env['bare_metal_certification'], 'unsupported environment claim')
    require(set(metadata['future_native_gates']) == set(GATES), 'missing implementation stage')
    for stage, gates in GATES.items():
        require(gates <= set(metadata['future_native_gates'][stage]), 'missing native gate: ' + stage)
    require(metadata['future_gates_status'] == 'SPECIFIED_NOT_EXECUTED_BY_FOLLOWUP', 'planned gates are not PASS')
    for stage, record in records.items():
        retained = metadata['retained_coverage'][stage]
        require(set(retained) == set(record['coverage']), 'missing research limitation')
        for key, observation in record['coverage'].items():
            require(retained[key]['status'] == observation['status'], 'limitation status changed: ' + key)
    for profile in ('debian-12', 'ubuntu-24.04', 'alt-p11'):
        require(profile in metadata['required_unsupported_profiles'], 'unsupported profile omitted')
        require(records['R1']['profiles'][profile]['claims']['public_engine_snapshot_notify']['status'] == 'UNSUPPORTED',
                'unsupported launch relabelled')


def validate_documents(root, metadata):
    design = (root / 'docs/sssd-verified-activation-design.md').read_text()
    table = design.split('<!-- sssd-proof-contract -->')[1].split('<!-- /sssd-proof-contract -->')[0]
    rows = [tuple(c.strip() for c in line.strip().strip('|').split('|')[:2])
            for line in table.splitlines() if re.match(r'^\s*\|\s*[ABCP]\s*\|', line)]
    require(len(rows) == 4 and dict(rows) == PROOFS, 'canonical proof table changed')
    plan = (root / 'docs/sssd-cross-policy-validation-design.md').read_text()
    for stage, gates in metadata['future_native_gates'].items():
        rows = [line for line in plan.splitlines()
                if line.lstrip().startswith('|') and line.split('|')[1].strip() == stage]
        require(len(rows) == 1, 'missing/duplicate native acceptance row: ' + stage)
        ids = set(re.findall(r'`([a-z0-9-]+)`', rows[0]))
        require(set(gates) <= ids, 'documented native gates missing: ' + stage)


def check_contract(root, r1, r2):
    root = Path(root)
    metadata = json.loads((root / 'tests/integration/sssd-research/research-contract.json').read_text())
    records = {'R1': r1, 'R2': r2}
    validate_metadata(metadata, records)
    validate_documents(root, metadata)
    for relative, expected in metadata['frozen_artifacts'].items():
        require(hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected,
                'historical evidence changed: ' + relative)
    # Negative controls operate only on copies, never edit recorded experiments.
    for corruption in ('proof', 'limitation', 'gate', 'unsupported', 'cleanup'):
        bad = copy.deepcopy(metadata)
        if corruption == 'proof':
            bad['proofs']['A'], bad['proofs']['B'] = bad['proofs']['B'], bad['proofs']['A']
        elif corruption == 'limitation':
            bad['retained_coverage']['R1']['readiness_timeout']['status'] = 'PASS'
        elif corruption == 'gate':
            bad['future_native_gates']['I3'].remove('cleanup-outcomes')
        elif corruption == 'unsupported':
            bad['required_unsupported_profiles'].remove('alt-p11')
        else:
            bad['cleanup_failure_blocks_success'] = False
        try:
            validate_metadata(bad, records)
        except ValueError:
            continue
        raise AssertionError('contract accepted corrupted ' + corruption)
    print('SSSD proof/gate/limitation contract PASS; 5 negative controls (evidence only)')
