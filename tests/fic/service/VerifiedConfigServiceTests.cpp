#include "service/VerifiedConfigServiceActivator.h"
#include "service/VerifiedConfigMountSupport.h"
#include <fic/core/integrity/ContentDigest.h>
#include <iostream>
#include <stdexcept>
using namespace fic::service;
void require(bool yes, const char* text) { if (!yes) throw std::runtime_error(text); }
int main() {
    ActivationRequest valid;
    valid.unit = "example.service";
    valid.paths = {{"/etc/example.conf", ControlledPathKind::File, fic::core::ContentDigest::sha256Hex("config"), {}}};
    detail::validateRequest(valid);
    auto rejected = [](const ActivationRequest& r) {
        const auto result = VerifiedConfigServiceActivator::activate(r);
        require(result.status == ActivationStatus::UnsupportedConfiguration && !result.success() &&
                result.cleanupErrors.empty() && !result.readinessConfirmed, "invalid input escaped preflight");
    };
    auto r = valid; r.paths.clear(); rejected(r);
    for (const char* name : {"", "../x.service", "-bad.service", "x.service;id", "x.socket", "x.service\n"}) {
        r = valid; r.unit = name; rejected(r);
    }
    for (const char* path : {"relative", "/", "/etc/../bad", "/etc/./bad", "/etc/x\n"}) {
        r = valid; r.paths[0].path = path; rejected(r);
    }
    r = valid; r.timeout = std::chrono::milliseconds(0); rejected(r);
    r = valid; r.maxSnapshotBytes = 0; rejected(r);
    r = valid; r.paths[0].sha256 = std::string(64, 'F'); rejected(r);
    r = valid; r.paths.push_back(r.paths[0]); rejected(r);
    r = valid; r.paths.push_back({"/etc", ControlledPathKind::Directory, "", {}}); rejected(r);
    r = valid; r.paths[0] = {"/etc/example", ControlledPathKind::Directory, "", {{"../escape", valid.paths[0].sha256}}}; rejected(r);
    r.paths[0].manifest = {{"file", valid.paths[0].sha256}, {"file/child", valid.paths[0].sha256}}; rejected(r);
    const auto mounts = detail::parseMountInfo("11 1 0:2 / /run/with\\040space ro,nosuid - tmpfs fic-vcsa.example ro,size=1024\n");
    require(mounts.size() == 1 && mounts[0].target == "/run/with space" &&
            detail::mountOption(mounts[0].options, "ro") && detail::mountOption(mounts[0].superOptions, "ro"), "mountinfo parse failed");
    require(!detail::mountOption("errors=remount-ro,rw", "ro"), "substring confused with mount flag");
    bool bad = false;
    try { detail::parseMountInfo("invalid\n"); } catch (const detail::Failure&) { bad = true; }
    require(bad, "malformed mountinfo accepted");
    ActivationResult result; result.primaryStatus = ActivationStatus::RestartFailed;
    result.status = ActivationStatus::CleanupFailed; result.cleanupErrors.push_back("umount busy");
    require(!result.success() && result.primaryStatus == ActivationStatus::RestartFailed, "cleanup hid primary failure");
    std::cout << "Verified config API/preflight/mountinfo unit contracts PASS\n";
}
