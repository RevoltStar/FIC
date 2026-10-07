#include "incident/IncidentAccessGateCore.h"

#include <stdexcept>

namespace {
void require(bool value) {
    if (!value) throw std::runtime_error("incident access gate invariant failed");
}
}

int main() {
    using namespace fic::incident;
    using fic::identity::pam::PamUserIdentity;
    fic::platform::PamPlatformConfig::IncidentAccessGateConfig config;
    config.controlledServices = {"login", "sshd", "gdm-autologin"};
    config.trustedLocalRootServices = {"login"};
    config.recoveryGroup = "fic";

    int requests = 0;
    bool configEnabled = false;
    bool member = false;
    bool identityProven = true;
    bool daemonAllows = false;
    IncidentResponseMode mode = IncidentResponseMode::Active;
    AccessGateDependencies dependencies{
        [&](const std::string& name, PamUserIdentity& identity, std::string&) {
            if (!identityProven) return false;
            identity.canonicalName = name;
            identity.uid = name == "root" ? 0 : 1000;
            identity.primaryGroup = 1000;
            return true;
        },
        [&](std::string&) { return configEnabled; },
        [&](const PamUserIdentity&, const std::string& group,
            bool& result, std::string&) {
            require(group == "fic");
            result = member;
            return true;
        },
        [&] { ++requests; return IncidentAccessReply{daemonAllows, "daemon"}; },
        [&] { return IncidentResponseModeResult{mode, true, "test mode"}; }
    };

    require(decideIncidentAccess({"ordinary", "sudo", ""}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Neutral);
    require(requests == 0);
    require(decideIncidentAccess({"ordinary", "gdm-launch-environment", ""},
                                 config, dependencies).disposition ==
            AccessGateDisposition::Neutral);
    require(requests == 0);
    require(decideIncidentAccess({"ordinary", "login", ""}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Deny);
    require(requests == 1);
    require(decideIncidentAccess({"ordinary", "gdm-autologin", ""}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Deny);
    require(requests == 2);
    daemonAllows = true;
    require(decideIncidentAccess({"ordinary", "login", ""}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Pass);
    require(requests == 3);

    daemonAllows = false;
    require(decideIncidentAccess({"root", "login", ""}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Pass);
    require(requests == 3);
    require(decideIncidentAccess({"root", "login", "remote.example"}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Deny);
    require(requests == 4);
    require(decideIncidentAccess({"root", "sshd", ""}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Deny);
    require(requests == 5);

    identityProven = false;
    require(decideIncidentAccess({"root", "login", ""}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Deny);
    require(requests == 6);
    identityProven = true;
    configEnabled = true;
    member = true;
    require(decideIncidentAccess({"ordinary", "login", ""}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Pass);
    require(requests == 6);
    configEnabled = false;
    require(decideIncidentAccess({"ordinary", "login", ""}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Deny);
    require(requests == 7);
    mode = IncidentResponseMode::Passive;
    require(decideIncidentAccess({"ordinary", "login", ""}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Neutral);
    require(requests == 7);
    mode = IncidentResponseMode::Off;
    require(decideIncidentAccess({"ordinary", "sshd", ""}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Neutral);
    require(requests == 7);
    mode = IncidentResponseMode::Active;
    dependencies.resolveMode = [] {
        return IncidentResponseModeResult{IncidentResponseMode::Active, false,
                                          "fallback ACTIVE: unproven config"};
    };
    require(decideIncidentAccess({"ordinary", "login", ""}, config,
                                 dependencies).disposition ==
            AccessGateDisposition::Deny);
    require(requests == 8);
}
