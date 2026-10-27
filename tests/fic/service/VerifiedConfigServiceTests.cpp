#include "service/VerifiedConfigServiceActivator.h"
#include "service/VerifiedConfigMountSupport.h"
#include "service/VerifiedConfigLaunchContract.h"
#include <fic/core/integrity/ContentDigest.h>
#include <iostream>
#include <locale>
#include <cerrno>
#include <cstring>
#include <linux/limits.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
using namespace fic::service;
void require(bool yes, const char* text) { if (!yes) throw std::runtime_error(text); }
void xattrEnumerationCases() {
    // A size-only query could report 23 while actual names are empty: the
    // callback refuses all size queries, proving decisions use actual names.
    for (const ssize_t count : {ssize_t(0), ssize_t(1), ssize_t(23), ssize_t(XATTR_LIST_MAX), ssize_t(XATTR_LIST_MAX + 1)}) {
        unsigned calls = 0;
        detail::XattrTestHooks hooks;
        hooks.list = [&](int fd, char* buffer, std::size_t size) {
            require(fd == 42 && buffer && size == XATTR_LIST_MAX, "xattr descriptor/buffer bound changed");
            // Even an explicitly returned OverlayFS-looking name is forbidden:
            // only kernel filtering may produce an empty list, never FIC.
            std::memcpy(buffer, "trusted.overlay.origin", 23);
            ++calls; return count;
        };
        detail::setXattrTestHooks(hooks);
        bool refused = false;
        try { detail::checkXattrListForTests(42); }
        catch (const detail::Failure& e) {
            require(std::string(e.what()).find("trusted.overlay.origin") == std::string::npos, "sensitive xattr name leaked");
            refused = e.status == ActivationStatus::UnsupportedConfiguration;
        }
        require(refused == (count != 0) && calls == 1, "nonempty/oversized list accepted or unbounded retry");
    }
    for (const int error : {ERANGE, E2BIG, EINTR, ENOMEM, ENOTSUP, EOPNOTSUPP, EPERM, EACCES, EIO, EBADF, 12345}) {
        unsigned calls = 0;
        detail::XattrTestHooks hooks;
        hooks.list = [&](int, char* buffer, std::size_t size) -> ssize_t {
            require(buffer && size == XATTR_LIST_MAX, "error fallback used size query");
            ++calls; errno = error; return -1;
        };
        detail::setXattrTestHooks(hooks);
        bool refused = false;
        try { detail::checkXattrListForTests(42); }
        catch (const detail::Failure& e) { refused = e.status == ActivationStatus::UnsupportedConfiguration; }
        require(refused && calls == 1, "enumeration error accepted or retried");
    }
    detail::setXattrTestHooks({});
}
void mountInfoLocaleCase() {
    struct Grouped : std::numpunct<char> {
        char do_thousands_sep() const override{return ' ';}
        std::string do_grouping() const override{return "\3";}
    };
    struct Restore {
        std::locale previous=std::locale();
        ~Restore(){std::locale::global(previous);}
    } restore;
    std::locale::global(std::locale(std::locale::classic(),new Grouped));
    const auto mounts=detail::parseMountInfo("12345 10001 0:2 / /safe rw - tmpfs test rw\n");
    require(mounts.size()==1&&mounts[0].id==12345&&mounts[0].parent==10001,
            "daemon locale must not merge kernel mountinfo numeric fields");
    bool refused=false;
    try {detail::parseMountInfo("12,345 10001 0:2 / /safe rw - tmpfs test rw\n");}
    catch(const detail::Failure&){refused=true;}
    require(refused,"locale-independent mountinfo parser accepted grouped numeric input");
}
int main() {
    xattrEnumerationCases();
    mountInfoLocaleCase();
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
    const auto shared = detail::parseMountInfo("12 1 0:2 / /safe rw shared:1 master:2 - tmpfs test rw\n");
    require(shared[0].shared && shared[0].slave && !shared[0].unknownOptional, "shared-slave topology lost");
    const auto slave = detail::parseMountInfo("13 1 0:2 / /safe rw master:2 propagate_from:3 - tmpfs test rw\n");
    require(!slave[0].shared && slave[0].slave, "non-shared slave confused with shared");
    const auto unknown = detail::parseMountInfo("14 1 0:2 / /safe rw future:3 - tmpfs test rw\n");
    require(unknown[0].unknownOptional, "future propagation metadata silently ignored");
    bool missing = false;
    try { detail::validateLaunchContract({}); } catch (const detail::Failure& e) { missing = e.status == ActivationStatus::UnsupportedConfiguration; }
    require(missing, "absent required launch properties accepted");
    // Unit-source path grammar rejects before dereferencing even an unavailable root.
    for (const auto& path : {"", "relative", "/", "/lib/../usr/lib/x", "/lib//systemd/system/x"}) {
        std::uint64_t budget = 1024;
        bool denied = false;
        try { detail::fingerprintUnitSource(-1, path, budget); }
        catch (const detail::Failure& e) { denied = e.status == ActivationStatus::UnsupportedConfiguration; }
        require(denied && budget == 1024, "unit source grammar/identity refusal consumed budget or escaped");
    }
    // Pure typed classifier: it cannot grant coverage without explicit targets.
    using Json = nlohmann::json;
    const auto envContract = [](const Json& value, const std::string& signature = "a(sb)") {
        return detail::LaunchContract{{"launch.EnvironmentFiles", Json{{"signature", signature}, {"value", value}}.dump()}};
    };
    const auto targets = valid.paths;
    const auto entry = Json::array({"/etc/example.conf", false});
    auto covered = envContract(Json::array({entry, Json::array({"/etc/example.conf", true}), entry}));
    require(detail::validateEnvironmentFiles(covered, &targets).size() == 1, "duplicate explicit coverage rejected");
    auto denied = [&](const detail::LaunchContract& contract, const std::vector<ControlledPath>* paths) {
        bool refused = false;
        try { detail::validateEnvironmentFiles(contract, paths); }
        catch (const detail::Failure& e) { refused = e.status == ActivationStatus::UnsupportedConfiguration; }
        require(refused, "EnvironmentFiles classifier became permissive");
    };
    denied(covered, nullptr);
    denied({}, &targets);
    denied({{"launch.EnvironmentFiles", "not-json"}}, &targets);
    denied(envContract(Json::array(), "as"), &targets);
    for (const auto& badValue : {Json(), Json::object(), Json("path"), Json::array({"/etc/example.conf"}),
                               Json::array({Json::array({"/etc/example.conf", 1})}),
                               Json::array({Json::array({"/etc/example.conf", false, 0})})})
        denied(envContract(badValue), &targets);
    for (const auto& name : {"relative", "/etc/../example.conf", "/etc/./example.conf", "/etc//example.conf",
                             "/etc/example.conf/", "/etc/*.conf", "/etc/[a]", "/etc/x?", "/etc/%t", "/"}) {
        auto matching = targets; matching[0].path = name;
        denied(envContract(Json::array({Json::array({name, false})})), &matching);
    }
    denied(envContract(Json::array({Json::array({"/etc/missing", false})})), &targets);
    auto directoryTargets = targets; directoryTargets[0].kind = ControlledPathKind::Directory;
    denied(covered, &directoryTargets);
    auto invalidSha = targets; invalidSha[0].sha256 = ""; denied(covered, &invalidSha);
    require(detail::validateEnvironmentFiles(envContract(Json::array())).empty(), "strict empty legacy contract rejected");
    ActivationResult result; result.primaryStatus = ActivationStatus::RestartFailed;
    result.status = ActivationStatus::CleanupFailed; result.cleanupErrors.push_back("umount busy");
    require(!result.success() && result.primaryStatus == ActivationStatus::RestartFailed, "cleanup hid primary failure");
    std::cout << "Verified config API/preflight/mountinfo unit contracts PASS\n";
}
