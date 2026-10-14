#include "modules/global/lock_settings/GLOBAL_lock_exempt_fic_members.h"
#include "incident/IncidentRecoveryConfigReader.h"

GLOBAL_lock_exempt_fic_members::GLOBAL_lock_exempt_fic_members(StatusReader reader)
    : reader_(reader ? std::move(reader)
                     : StatusReader(fic::incident::IncidentRecoveryConfigReader::ficMemberExemptionStatus)) {
    submoduleName = "lock_settings";
    policyName = "lock_exempt_fic_members";
    policyTypeValue = std::make_unique<FixedPolicyTypeValue>("ENABLE");
}

bool GLOBAL_lock_exempt_fic_members::apply() {
    std::string path, error;
    AtomicTargetState version;
    if (!captureConfigurationVersion(path, version, error)) {
        log(error, logLevel::ERROR);
        return false;
    }
    const auto effective = reader_(error);
    if (!effective || *effective != isEnabled() ||
        !AtomicFileWriter::targetStateMatches(path, version, &error)) {
        log("Recovery exemption status is not proven: " + error, logLevel::ERROR);
        return false;
    }
    return true;
}
