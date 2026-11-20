#include "modules/identity_access/pam/PamMfaTopology.h"

#include <iostream>
#include <string>

using namespace fic::identity::pam;

namespace {

bool proveRenderedGraph(PamMfaForm form, bool sssd, const std::string& body) {
    PamEffectiveStack stack;
    stack.service = mfaSshService;
    std::vector<PamRule> rules;
    std::string error;
    if (!PamConfiguration::parseRulesContent("slot", body, rules, error)) return false;
    for (auto& rule : rules) stack.entries.push_back({std::move(rule), {}});
    return proveMfaAuthenticationPaths(stack, {}, "slot", "slot", sssd, error, form);
}

bool replaceOnce(std::string& body, const std::string& from, const std::string& to) {
    const auto found = body.find(from);
    if (found == std::string::npos) return false;
    body.replace(found, from.size(), to);
    return true;
}

bool selfTest() {
    PamMfaTopology original, rendered;
    std::string error;
    if (!buildDebian13MfaTopology({PamMfaFactor::GoogleTotp}, original, error) ||
        !buildDebian13MfaTopology(PamMfaForm::InteractiveTwoPrompt, false, rendered, error) ||
        original.requiredSlot != rendered.requiredSlot || original.profile != rendered.profile ||
        rendered.attachment != "auth substack fic-mfa\n" ||
        rendered.requiredSlot.find("ignore=ignore") == std::string::npos) return false;

    for (const auto form : {PamMfaForm::SingleInputForwardPass, PamMfaForm::SshStagedAuthentication}) {
        for (const bool sssd : {false, true}) {
            if (!buildDebian13MfaTopology(form, sssd, rendered, error) ||
                !proveRenderedGraph(form, sssd, rendered.requiredSlot)) return false;
            const auto rejects = [&](const std::string& from, const std::string& to) {
                auto changed = rendered.requiredSlot;
                return replaceOnce(changed, from, to) && !proveRenderedGraph(form, sssd, changed);
            };
            if (!rejects("pam_unix.so", "pam_unix.so nullok") ||
                !rejects("auth requisite pam_deny.so", "auth sufficient pam_permit.so") ||
                !rejects("auth required pam_permit.so", "auth [success=reset default=ignore] pam_permit.so"))
                return false;
            if (form == PamMfaForm::SingleInputForwardPass) {
                if (!rejects(" forward_pass", "") || !rejects(" use_first_pass", "") ||
                    !rejects("success=ok default=die", "success=ok ignore=ignore default=die"))
                    return false;
            } else if (!rejects("success=2 auth_err=ignore", "success=1 auth_err=ignore") ||
                       !rejects("ignore=ignore default=die] pam_fic_ssh_stage.so",
                                "ignore=ignore default=ignore] pam_fic_ssh_stage.so") ||
                       !rejects("success=done default=die", "success=ignore default=die")) {
                return false;
            }
        }
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2 || argc > 5) return 2;
    std::string error;
    const std::string mode(argv[1]);
    if (argc == 2 && mode == "self-test") {
        if (selfTest()) return 0;
        std::cerr << "MFA topology self-test failed\n";
        return 1;
    }

    PamMfaForm form = PamMfaForm::InteractiveTwoPrompt;
    bool sssd = false;
    if (argc >= 4) {
        const std::string family(argv[2]);
        if (family == "ssh") form = PamMfaForm::SshStagedAuthentication;
        else if (family == "forward") form = PamMfaForm::SingleInputForwardPass;
        else return 2;
        const std::string primary(argv[3]);
        if (primary != "local" && primary != "sssd") return 2;
        sssd = primary == "sssd";
    }
    if (argc == 2 || argc == 4) {
        PamMfaTopology topology;
        if (!buildDebian13MfaTopology(form, sssd, topology, error)) return 1;
        if (mode == "profile") std::cout << topology.profile;
        else if (mode == "neutral") std::cout << topology.neutralSlot;
        else if (mode == "required") std::cout << topology.requiredSlot;
        else if (mode == "attachment") std::cout << topology.attachment;
        else if (mode == "slot-name") std::cout << topology.slotName << '\n';
        else return 2;
        return 0;
    }

    if (mode != "candidate" && mode != "installed") return 2;
    const auto target = mode == "candidate" ? PamMfaProofTarget::Candidate : PamMfaProofTarget::Installed;
    if (!verifyDebian13Mfa(fic::platform::makeBuildPlatformProfile(),
                         argv[argc - 1], target, form, sssd, error)) {
        std::cerr << error << '\n';
        return 1;
    }
    std::cout << "StructuralEffective\n";
}
