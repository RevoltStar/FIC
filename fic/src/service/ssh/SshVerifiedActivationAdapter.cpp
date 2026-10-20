#include "service/ssh/SshVerifiedActivationAdapter.h"
#include "service/ssh/SshVerifiedInputClosure.h"
#include "service/ssh/SshPersistentMetadata.h"
#include "service/VerifiedConfigActivationProof.h"
#include "modules/net/ssh/SshInputAuthority.h"
#include "modules/net/ssh/SshRuntime.h"
#include "modules/net/ssh/SshManagedBlock.h"
#include "platform/PlatformCompatibility.h"
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/process/VerifiedProcessExecutor.h>
#include <nlohmann/json.hpp>
#include <fcntl.h>
#include <unistd.h>
#ifdef FIC_ACTIVATOR_TESTING
#include "service/ssh/SshVerifiedActivationTestAccess.h"
#endif
namespace fic::service::ssh {
namespace {
namespace d = fic::service::detail;
using Json = nlohmann::json;
[[noreturn]] void unsupported(const char* text) { throw d::Failure(ActivationStatus::UnsupportedConfiguration, text); }
struct SemanticFailure : std::runtime_error {
    bool mismatch;
    explicit SemanticFailure(bool known) : std::runtime_error("selected SSH semantics not confirmed"), mismatch(known) {}
};
Json value(const d::LaunchContract& launch, const char* key) {
    return Json::parse(launch.at(std::string("launch.") + key)).at("value");
}
void validateLaunch(const d::LaunchContract& launch) {
    const Json command = Json::array({Json::array({"/usr/sbin/sshd", Json::array({"/usr/sbin/sshd", "-D", "$SSHD_OPTS"}), Json::array()})});
    const Json pre = Json::array({Json::array({"/usr/sbin/sshd", Json::array({"/usr/sbin/sshd", "-t"}), Json::array()})});
    if (value(launch, "ExecStartEx") != command || value(launch, "ExecStartPreEx") != pre ||
        !value(launch, "ExecConditionEx").empty() || !value(launch, "ExecStartPostEx").empty() ||
        !value(launch, "ExecStopEx").empty() || !value(launch, "ExecStopPostEx").empty())
        unsupported("SSH v1 requires stock Debian ExecStart/Pre and no extra execution hooks");
    if (value(launch, "EnvironmentFiles") != Json::array({Json::array({"/etc/default/ssh", true})}) ||
        !value(launch, "Environment").empty() || !value(launch, "PassEnvironment").empty() ||
        !value(launch, "UnsetEnvironment").empty() || !value(launch, "DropInPaths").empty())
        unsupported("SSH v1 launch environment/drop-ins unsupported");
    if (value(launch, "User") != "" || value(launch, "Group") != "" || !value(launch, "SupplementaryGroups").empty())
        unsupported("SSH v1 requires stock root service credentials");
    const auto fragment = value(launch, "FragmentPath").get<std::string>();
    if (fragment != "/usr/lib/systemd/system/ssh.service" && fragment != "/lib/systemd/system/ssh.service")
        unsupported("SSH v1 requires vendor ssh.service");
    // No blanket acceptance of inherited environment. In particular loader,
    // allocator, locale collation and SSH option overrides cannot pass here.
    for (const auto& entry : Json::parse(launch.at("launch.ManagerEnvironment"))) {
        const auto env = entry.get<std::string>();
        if (env != "LANG=C" && env != "LANG=C.UTF-8" && env != "LANG=C.utf8" &&
            env != "LC_ALL=C" && env != "LC_ALL=C.UTF-8" &&
            env != "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" &&
            env != "PATH=/usr/sbin:/usr/bin:/sbin:/bin" &&
            env != "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin") unsupported("SSH v1 manager environment outside supported profile");
    }
}
struct Capture : detail::PersistentMetadata {
    detail::InputBytes bytes;
};
Capture capture(const ActivationRequest& request, bool published = false, bool persistent = false) {
    Capture out; auto budget = request.maxSnapshotBytes; const auto mounts = d::readMountInfo();
    for (const auto& p : request.paths) {
        std::string error;
        if (!persistent && !fic::ssh::trustedSshInput(p.path, p.kind == ControlledPathKind::Directory, false, error)) unsupported("untrusted SSH reference input");
        if (!published) for (const auto& mount : mounts)
            if (mount.target == p.path || (p.kind == ControlledPathKind::Directory && d::below(mount.target, p.path))) unsupported("SSH input has existing/nested mount");
        auto fd = d::openAbsolute(p.path, O_RDONLY);
        if (!persistent) d::verifyTree(fd.get(), p, request.maxSnapshotBytes);
        const auto tree = d::readTree(fd.get(), p.kind, budget);
        for (const auto& [name, content] : tree.files)
            out.bytes.emplace(p.kind == ControlledPathKind::File ? p.path.string() : (p.path / name).string(), content);
        const auto root = d::identity(fd.get());
        const auto& st = tree.attributes.at("");
        if (root.device != st.st_dev || root.inode != st.st_ino || root.mode != st.st_mode ||
            root.uid != st.st_uid || root.gid != st.st_gid)
            throw d::Failure(ActivationStatus::InterferenceDetected, "SSH source changed during capture");
        auto visible = d::openAbsolute(p.path, O_PATH);
        const auto visibleIdentity = d::identity(visible.get());
        if (visibleIdentity.mount != root.mount || !d::sameObject(visibleIdentity, root))
            throw d::Failure(ActivationStatus::InterferenceDetected, "SSH source replaced during capture");
        out.roots.emplace(p.path.string(), root); out.attributes.emplace(p.path.string(), tree.attributes);
    }
    return out;
}
void validateCaptured(const SshVerifiedActivationRequest& request, const Capture& observed) {
    const auto closure = detail::validateClosure(request.reference, observed.bytes);
    for (const auto& [root, entries] : observed.attributes) {
        for (const auto& [name, st] : entries) {
            if (st.st_uid != 0 || (st.st_mode & 0022)) unsupported("SSH tree requires root-controlled metadata");
            const auto path = name.empty() ? root : (std::filesystem::path(root) / name).string();
            if (closure.hostKeys.count(path)) detail::requireSafePrivateHostKey(st);
        }
    }
    const auto env = observed.bytes.find("/etc/default/ssh");
    if (env == observed.bytes.end()) unsupported("explicit EnvironmentFile reference required");
    detail::validateEmptyOptions(env->second);
}
SshVerifiedActivationResult perform(const SshVerifiedActivationRequest& request
#ifdef FIC_ACTIVATOR_TESTING
    , const detail::AdapterTestHooks* tests = nullptr
#endif
) {
    SshVerifiedActivationResult result;
    try {
        d::validateRequest(request.reference); detail::validatePolicies(request.policies);
        for (const auto& p : request.reference.paths)
            if (p.kind != ControlledPathKind::File && p.kind != ControlledPathKind::Directory) unsupported("unsupported SSH reference object kind");
        const auto deadline = std::chrono::steady_clock::now() + request.reference.timeout;
        const auto profile = fic::platform::makeBuildPlatformProfile(); std::string error;
        if ((profile.id != "debian-12" && profile.id != "debian-13") ||
            !fic::platform::validateHostCompatibility(profile, "/etc/os-release", error)) unsupported("SSH verified activation v1 supports Debian 12/13 only");
        const auto observed = capture(request.reference); validateCaptured(request, observed);
        d::SystemdActivation service(request.reference.unit, deadline, request.reference.paths);
        auto launch = service.preflight(); detail::validateLaunchProfile(launch.properties);
        fic::platform::PlatformExecutableResolver resolver(profile.executables);
        std::filesystem::path binary;
        if (!resolver.resolve(fic::platform::ExecutableId::Sshd, binary, error) || binary != "/usr/sbin/sshd" ||
            !CommandHashStore::verifyHash(binary, error)) unsupported("SSH executable trust not proven");
        auto executable = d::openAbsolute(binary, O_RDONLY); const auto binaryIdentity = d::identity(executable.get());
        auto checkBinary = [&] {
            auto current = d::openAbsolute(binary, O_RDONLY);
            if (!d::sameObject(d::identity(current.get()), binaryIdentity) || !CommandHashStore::verifyHash(binary, error))
                throw d::Failure(ActivationStatus::InterferenceDetected, "SSH executable changed");
        };
        SshRuntimeOptions options; options.configPath = "/etc/ssh/sshd_config"; options.includeBasePath = "/etc/ssh";
        options.requireTrustedInputs = true; options.useLaunchArguments = true;
        SshRuntime runtime(options, resolver, [&](const std::string& path, const std::vector<std::string>& args, const ProcessOptions& original) {
            auto bounded = original; bounded.timeout = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            bounded.maxOutputBytes = 1024 * 1024; bounded.clearEnvironment = true;
            bounded.environment = {{"LANG", "C"}, {"LC_ALL", "C"}};
            if (bounded.timeout.count() <= 0) throw d::Failure(ActivationStatus::TimedOut, "SSH proof deadline exceeded");
            return VerifiedProcessExecutor::execute(path, args, bounded);
        });
        const auto semantics = [&] {
            checkBinary();
            if (!runtime.validateConfiguration(error)) throw SemanticFailure(false);
            for (const auto& [id, expected] : request.policies) {
                auto verified = runtime.policyValueCompliance(sshPolicyDirectiveKeyword(id), expected);
                if (verified.compliance != SshCompliance::Compliant)
                    throw SemanticFailure(verified.compliance == SshCompliance::NonCompliant);
            }
            checkBinary();
        };
        semantics();
        d::ActivationProof proof;
        proof.expectedConfiguration = launch.properties;
        for (const auto* key : {"ActiveState", "SubState", "MainPID", "InvocationID", "Job", "Result"}) proof.expectedConfiguration.erase(key);
        proof.sourceRoots = observed.roots; proof.sourceAttributes = observed.attributes;
        bool publishedProof = false, runtimeProof = false;
        proof.published = [&](auto) {
            validateCaptured(request, capture(request.reference, true)); semantics(); publishedProof = true;
        };
        proof.ready = [&](const d::ServiceState& ready, auto) {
            if (std::chrono::steady_clock::now() >= deadline) throw d::Failure(ActivationStatus::TimedOut, "SSH proof deadline exceeded");
            checkBinary(); struct stat actual{}, expected{};
            if (::stat(("/proc/" + ready.at("MainPID") + "/exe").c_str(), &actual) || ::fstat(executable.get(), &expected) ||
                actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino)
                throw d::Failure(ActivationStatus::InterferenceDetected, "ready service executable differs from verified SSH binary");
            runtimeProof = true;
        };
#ifdef FIC_ACTIVATOR_TESTING
        if (tests && tests->beforeActivation) tests->beforeActivation();
#endif
        auto activationRequest = request.reference;
        activationRequest.timeout = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (activationRequest.timeout.count() <= 0) throw d::Failure(ActivationStatus::TimedOut, "SSH proof deadline exceeded");
        result.activationAttempted = true;
#ifdef FIC_ACTIVATOR_TESTING
        if (tests) result.activation = d::activateWithProofForTests(activationRequest, proof, tests->activation);
        else
#endif
        result.activation = d::activateWithProof(activationRequest, proof);
        result.status = SshActivationStatus::ActivationFailed;
        if (result.activation.primaryStatus == ActivationStatus::Success && publishedProof && runtimeProof) {
            result.inputs = result.semantics = ProofState::Proven;
        }
        result.persistent = detail::persistentProof(observed,
            [&] { return capture(request.reference, false, true); },
            [&](const Capture& current) { validateCaptured(request, current); });
        if (result.activation.success() && result.inputs == ProofState::Proven && result.semantics == ProofState::Proven) {
            result.status = result.persistent == ProofState::Proven ? SshActivationStatus::Success :
                result.persistent == ProofState::NonCompliant ? SshActivationStatus::RuntimeActivatedButPersistentDrift : SshActivationStatus::ActivationFailed;
        }
        result.diagnostic = result.activation.diagnostic;
        if (std::chrono::steady_clock::now() >= deadline) {
            result.status = SshActivationStatus::ActivationFailed;
            result.persistent = ProofState::NotProven;
            result.diagnostic = "runtime outcome preserved; persistent proof deadline exceeded";
        }
    } catch (const SemanticFailure& e) {
        result.semantics = e.mismatch ? ProofState::NonCompliant : ProofState::NotProven;
        result.diagnostic = e.what();
    } catch (const d::Failure& e) {
        result.diagnostic = e.what();
        if (e.status == ActivationStatus::UnsupportedConfiguration) result.semantics = ProofState::Unsupported;
    } catch (...) { result.diagnostic = "SSH proof unavailable"; }
    return result;
}
} // namespace
void detail::validateLaunchProfile(const std::map<std::string, std::string>& launch) { validateLaunch(launch); }
SshVerifiedActivationResult SshVerifiedActivationAdapter::activate(const SshVerifiedActivationRequest& r) { return perform(r); }
#ifdef FIC_ACTIVATOR_TESTING
namespace detail {
SshVerifiedActivationResult activateAdapterForTests(const SshVerifiedActivationRequest& r, const AdapterTestHooks& hooks) { return perform(r, &hooks); }
}
#endif
} // namespace fic::service::ssh
