#include "modules/identity_access/pam/PamMfaTopology.h"

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    using namespace fic::identity::pam;
    std::string error;
    if (argc == 2) {
        PamMfaTopology topology;
        if (!buildDebian13MfaTopology({PamMfaFactor::GoogleTotp}, topology, error)) return 1;
        const std::string part(argv[1]);
        if (part == "profile") std::cout << topology.profile;
        else if (part == "neutral") std::cout << topology.neutralSlot;
        else if (part == "required") std::cout << topology.requiredSlot;
        else return 2;
        return 0;
    }
    if (argc != 3) return 2;
    const std::string mode(argv[1]);
    if (mode != "candidate" && mode != "installed") return 2;
    const auto target = mode == "candidate" ? PamMfaProofTarget::Candidate : PamMfaProofTarget::Installed;
    if (!verifyDebian13Mfa(fic::platform::makeBuildPlatformProfile(), argv[2], target, error)) {
        std::cerr << error << '\n';
        return 1;
    }
    std::cout << "StructuralEffective\n";
}
