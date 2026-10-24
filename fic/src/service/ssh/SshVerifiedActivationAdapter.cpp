#include "service/ssh/SshVerifiedActivationAdapter.h"
#include "service/ssh/SshVerifiedInputClosure.h"
#include "service/ssh/SshPersistentMetadata.h"
#include "service/ssh/SshServiceAdmission.h"
#include "service/ssh/UbuntuSshSocketFlow.h"
#include <memory>
#include <thread>
#include <mutex>
#include <algorithm>
#include "service/VerifiedConfigActivationProof.h"
#include "service/VerifiedConfigLaunchContract.h"
#include "modules/net/ssh/SshInputAuthority.h"
#include "modules/net/ssh/SshRuntime.h"
#include "modules/net/ssh/SshManagedBlock.h"
#include "platform/PlatformCompatibility.h"
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/integrity/ContentDigest.h>
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
bool ubuntuSocket() {
    const auto id=fic::platform::makeBuildPlatformProfile().id;
    return id=="ubuntu-24.04"||id=="ubuntu-26.04";
}
d::ActivationProfile activationProfile() {return ubuntuSocket()?d::ActivationProfile::UbuntuSshSocket:d::ActivationProfile::ActiveNotifyService;}
bool supportedProfile(const std::string& id) {return id=="debian-12"||id=="debian-13"||id=="ubuntu-24.04"||id=="ubuntu-26.04";}
void validateLaunch(const d::LaunchContract& launch) {
    if(ubuntuSocket()) {
        const auto state=value(launch,"UnitFileState");
        if(state!="enabled"&&state!="disabled"&&state!="indirect") unsupported("Ubuntu SSH service enablement unsupported");
    } else if(value(launch,"UnitFileState")!="enabled") unsupported("SSH RuntimeNotReady: service must be persistently enabled");
    const Json command = Json::array({Json::array({"/usr/sbin/sshd", Json::array({"/usr/sbin/sshd", "-D", "$SSHD_OPTS"}), Json::array()})});
    const Json pre = Json::array({Json::array({"/usr/sbin/sshd", Json::array({"/usr/sbin/sshd", "-t"}), Json::array()})});
    if (value(launch, "ExecStartEx") != command || value(launch, "ExecStartPreEx") != pre ||
        !value(launch, "ExecConditionEx").empty() || !value(launch, "ExecStartPostEx").empty() ||
        !value(launch, "ExecStopEx").empty() || !value(launch, "ExecStopPostEx").empty())
        unsupported("SSH v1 requires stock Debian ExecStart/Pre and no extra execution hooks");
    if (value(launch, "EnvironmentFiles") != Json::array({Json::array({"/etc/default/ssh", true})}) ||
        !value(launch, "Environment").empty() || !value(launch, "PassEnvironment").empty() ||
        !value(launch, "UnsetEnvironment").empty())
        unsupported("SSH v1 launch environment/drop-ins unsupported");
    const auto dropins = value(launch,"DropInPaths");
    if(!dropins.is_array() || dropins.size()>64) unsupported("unsupported SSH drop-in list");
    for(const auto& item:dropins) {
        const auto name=item.get<std::string>();
        const auto p=std::filesystem::path(name);
        if(p.parent_path()!="/etc/systemd/system/ssh.service.d" || p.extension()!=".conf" ||
           p.lexically_normal().string()!=name) unsupported("unsupported SSH drop-in path");
        const auto expected=launch.find("launch.file:"+name);
        if(expected==launch.end()) unsupported("SSH drop-in source proof missing");
        auto file=d::openAbsolute(p,O_RDONLY);std::uint64_t budget=65536;
        const auto tree=d::readTree(file.get(),ControlledPathKind::File,budget);
        const auto& bytes=tree.files.at("");
        if(Json::parse(expected->second).at("file").back()!=fic::core::ContentDigest::sha256Hex(bytes))
            throw d::Failure(ActivationStatus::InterferenceDetected,"SSH drop-in source differs");
        detail::validateCompatibleDropIn(bytes);
        auto root=d::openAbsolute("/",O_PATH|O_DIRECTORY);budget=1024*1024;
        if(d::fingerprintUnitSource(root.get(),name,budget)!=expected->second)
            throw d::Failure(ActivationStatus::InterferenceDetected,"SSH drop-in changed during classification");
    }
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
std::map<std::string,std::string> metadataIdentities(const detail::PersistentMetadata& state) {
    std::map<std::string,std::string> result;
    for(const auto& [path,root]:state.roots) {
        Json value=Json::array({root.mount,root.device,root.inode,root.mode,root.uid,root.gid});
        Json files=Json::object();
        for(const auto& [name,s]:state.attributes.at(path))files[name]=Json::array({s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,
            s.st_mtim.tv_sec,s.st_mtim.tv_nsec,s.st_ctim.tv_sec,s.st_ctim.tv_nsec});
        result.emplace(path,fic::core::ContentDigest::sha256Hex(Json::array({value,files}).dump()));
    }
    return result;
}
d::ServiceState admit(d::SystemdActivation& service
#ifdef FIC_ACTIVATOR_TESTING
    , const std::function<void()>& waiting = {}
#endif
) {
    while(true) {
        const auto state=service.current();validateLaunch(state.properties);
        const bool inactive=ubuntuSocket()&&state.at("ActiveState")=="inactive"&&state.at("SubState")=="dead"&&state.at("MainPID")=="0"&&state.at("Job").empty();
        if(inactive||detail::classifyServiceAdmission(state.at("ActiveState"),state.at("SubState"),state.at("Job"))==detail::ServiceAdmission::Ready) break;
#ifdef FIC_ACTIVATOR_TESTING
        if(waiting) waiting();
#endif
        std::this_thread::sleep_for(std::min(service.remaining(),std::chrono::milliseconds(50)));
    }
    auto ready=service.preflight();validateLaunch(ready.properties);return ready;
}
detail::RestartBudget restartBudget;
void awaitRestartBudget(d::SystemdActivation& service, const d::ServiceState& expected, bool reserve) {
    auto interval=value(expected.properties,"StartLimitIntervalUSec").get<std::uint64_t>();
    auto burst=value(expected.properties,"StartLimitBurst").get<std::uint64_t>();
    if(ubuntuSocket()) {
        const auto socket=d::readSshSocketContract(std::chrono::steady_clock::now()+service.remaining());
        const auto socketInterval=value(socket,"StartLimitIntervalUSec").get<std::uint64_t>();
        const auto socketBurst=value(socket,"StartLimitBurst").get<std::uint64_t>();
        interval=std::max(interval,socketInterval);burst=std::min(burst,socketBurst);
    }
    if(interval>30000000 || (interval && (!burst||burst>1024)))
        unsupported("SSH restart budget outside bounded supported profile (interval <=30s, burst 1..1024)");
    while(true) {
        const auto now=std::chrono::steady_clock::now();
        const auto next=restartBudget.availableAt(now,std::chrono::microseconds(interval),burst);
        if(next<=now) break;
        const auto remaining=service.remaining();
        std::this_thread::sleep_for(std::min({remaining,std::chrono::milliseconds(50),
            std::chrono::duration_cast<std::chrono::milliseconds>(next-now)+std::chrono::milliseconds(1)}));
    }
    const auto current=admit(service);
    if(current.properties!=expected.properties)
        throw d::Failure(ActivationStatus::InterferenceDetected,"SSH service changed while awaiting restart budget");
    if(reserve) restartBudget.record(std::chrono::steady_clock::now());
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
    const auto closure = detail::validateClosure(request.reference, observed.bytes, request.policies);
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
// One bounded process-local receipt; it grants no persistent ownership and is
// discarded on any detected interference/failure. No cache survives daemon restart.
struct RuntimeReceipt {
    std::string reference;
    std::map<std::string,std::string> launch, policies;
};
RuntimeReceipt runtimeReceipt;
std::mutex receiptMutex;
std::string referenceIdentity(const SshVerifiedActivationRequest& request, const Capture& observed) {
    Json paths=Json::array();
    for(const auto& p:request.reference.paths) paths.push_back({p.path.string(),static_cast<int>(p.kind),p.sha256,p.manifest});
    auto boot=d::openAbsolute("/proc/sys/kernel/random/boot_id",O_RDONLY);
    // procfs virtual files have zero st_size; bounded descriptor read, no path fallback.
    char bytes[80]; const auto count=::read(boot.get(),bytes,sizeof(bytes));
    if(count<=0||count==static_cast<ssize_t>(sizeof(bytes))) unsupported("boot identity unavailable");
    auto binary=d::openAbsolute("/usr/sbin/sshd",O_RDONLY);
    const auto identity=d::identity(binary.get());std::uint64_t budget=16*1024*1024;
    const auto binaryTree=d::readTree(binary.get(),ControlledPathKind::File,budget);
    return fic::core::ContentDigest::sha256Hex(Json({paths,metadataIdentities(observed),std::string(bytes,count),
        Json::array({identity.mount,identity.inode,identity.device,identity.mode,identity.uid,identity.gid}),
        fic::core::ContentDigest::sha256Hex(binaryTree.files.at(""))}).dump());
}
SshVerifiedActivationResult perform(const SshVerifiedActivationRequest& supplied
#ifdef FIC_ACTIVATOR_TESTING
    , const detail::AdapterTestHooks* tests = nullptr
#endif
) {
    const std::lock_guard<std::mutex> receiptLock(receiptMutex);
    SshVerifiedActivationRequest request=supplied;
    SshVerifiedActivationResult result;
    std::string receiptKey;
    bool receiptEligible=!request.expectedService.empty()&&!request.observedMetadata.empty();
#ifdef FIC_ACTIVATOR_TESTING
    if(tests) receiptEligible=false;
#endif
    try {
        d::validateRequest(request.reference); detail::validatePolicies(request.policies);
        for(auto it=request.additionalPolicies.begin();it!=request.additionalPolicies.end();) {
            try { detail::validatePolicies({*it}); ++it; }
            catch(const d::Failure&) { it=request.additionalPolicies.erase(it); }
        }
        for (const auto& p : request.reference.paths)
            if (p.kind != ControlledPathKind::File && p.kind != ControlledPathKind::Directory) unsupported("unsupported SSH reference object kind");
        const auto deadline = std::chrono::steady_clock::now() + request.reference.timeout;
        const auto profile = fic::platform::makeBuildPlatformProfile(); std::string error;
        if (!supportedProfile(profile.id) ||
            !fic::platform::validateHostCompatibility(profile, "/etc/os-release", error)) unsupported("SSH verified activation v1 supports Debian12/13 or Ubuntu24/26 only");
        d::SystemdActivation service(request.reference.unit, deadline, request.reference.paths,activationProfile());
        std::unique_ptr<detail::UbuntuSshSocketFlow> socket;
        if(ubuntuSocket())socket=std::make_unique<detail::UbuntuSshSocketFlow>(deadline);
        auto launch=admit(service
#ifdef FIC_ACTIVATOR_TESTING
            , tests ? tests->admissionWait : std::function<void()>{}
#endif
        );
        const auto combined=[&](const d::ServiceState& state) {return socket?socket->combined(state):state.properties;};
        const auto admittedLaunch=combined(launch);
        if(!request.expectedService.empty()&&request.expectedService!=admittedLaunch)
            throw d::Failure(ActivationStatus::InterferenceDetected,"SSH service differs from caller admission proof");
        const auto observed = capture(request.reference); validateCaptured(request, observed);
        if(!request.observedMetadata.empty()&&request.observedMetadata!=metadataIdentities(observed))
            throw d::Failure(ActivationStatus::InterferenceDetected,"SSH input metadata differs from caller reference capture");
        if(receiptEligible) {
            receiptKey=referenceIdentity(request,observed);
            if(runtimeReceipt.reference==receiptKey && runtimeReceipt.launch==admittedLaunch) {
                // Accumulate only policy values already proved on this exact
                // runtime/input identity. New selections still require activation.
                const auto selected=request.policies;
                for(const auto& [id,expected]:runtimeReceipt.policies)
                    request.policies.emplace(id,expected);
                bool covered=true;
                for(const auto& [id,expected]:selected) {
                    const auto found=runtimeReceipt.policies.find(id);
                    if(found==runtimeReceipt.policies.end()||found->second!=expected) covered=false;
                }
                if(covered) {
                    const auto again=admit(service);
                    validateCaptured(request,capture(request.reference));
                    if(combined(again)!=admittedLaunch || referenceIdentity(request,capture(request.reference))!=receiptKey)
                        throw d::Failure(ActivationStatus::InterferenceDetected,"SSH receipt changed during recheck");
                    // Executable trust remains a live condition even for no-op.
                    if(!CommandHashStore::verifyHash("/usr/sbin/sshd",error)) unsupported("SSH executable trust not proven");
                    auto expectedBinary=d::openAbsolute("/usr/sbin/sshd",O_RDONLY);
                    struct stat processBinary{},diskBinary{};
                    if(::stat(("/proc/"+again.at("MainPID")+"/exe").c_str(),&processBinary)||
                       ::fstat(expectedBinary.get(),&diskBinary)||processBinary.st_dev!=diskBinary.st_dev||processBinary.st_ino!=diskBinary.st_ino)
                        throw d::Failure(ActivationStatus::InterferenceDetected,"SSH receipt process executable changed");
                    result.status=SshActivationStatus::Success;
                    result.inputs=result.semantics=result.persistent=ProofState::Proven;
                    result.activation.status=result.activation.primaryStatus=ActivationStatus::Success;
                    result.activation.readinessConfirmed=true;
                    result.diagnostic="current verified runtime receipt; no restart";
                    return result;
                }
            }
        }
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
        if(socket) {detail::UbuntuSshSocketFlow::prepareRuntimeDirectory();detail::UbuntuSshSocketFlow::effectiveEndpoints(runtime);}
        semantics();
        d::ActivationProof proof;
        proof.profile=activationProfile();
        if(socket)proof.sshSocketActivation=[&](auto) {socket->activate(runtime,service,launch);};
        proof.expectedConfiguration = launch.properties;
        for (const auto* key : {"ActiveState", "SubState", "MainPID", "InvocationID", "Job", "Result"}) proof.expectedConfiguration.erase(key);
        proof.sourceRoots = observed.roots; proof.sourceAttributes = observed.attributes;
        bool publishedProof = false, runtimeProof = false;
        auto provenPolicies=request.policies;
        std::string promotedInvocation, promotedPid;
        proof.published = [&](auto) {
            const auto protectedInputs=capture(request.reference,true);
            validateCaptured(request, protectedInputs); semantics();
            for(const auto& [id,expected]:request.additionalPolicies) {
                if(request.policies.count(id)) continue;
                try {
                    auto candidate=request;candidate.policies={{id,expected}};
                    validateCaptured(candidate,protectedInputs);
                    if(runtime.policyValueCompliance(sshPolicyDirectiveKeyword(id),expected).compliance==SshCompliance::Compliant)
                        provenPolicies[id]=expected;
                } catch(const d::Failure&) { /* Optional selections cannot fail this policy. */ }
            }
            checkBinary(); publishedProof = true;
        };
        proof.ready = [&](const d::ServiceState& ready, auto) {
            if (std::chrono::steady_clock::now() >= deadline) throw d::Failure(ActivationStatus::TimedOut, "SSH proof deadline exceeded");
            checkBinary(); struct stat actual{}, expected{};
            if (::stat(("/proc/" + ready.at("MainPID") + "/exe").c_str(), &actual) || ::fstat(executable.get(), &expected) ||
                actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino)
                throw d::Failure(ActivationStatus::InterferenceDetected, "ready service executable differs from verified SSH binary");
            promotedInvocation=ready.at("InvocationID");promotedPid=ready.at("MainPID");
            if(socket)socket->ready(ready);
            runtimeProof = true;
        };
#ifdef FIC_ACTIVATOR_TESTING
        if (tests && tests->beforeActivation) tests->beforeActivation();
#endif
        if(receiptEligible) awaitRestartBudget(service,launch,true);
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
            const auto finalState=service.current();
            service.confirm(finalState);
            if(finalState.at("InvocationID")!=promotedInvocation || finalState.at("MainPID")!=promotedPid)
                throw d::Failure(ActivationStatus::InterferenceDetected,"SSH runtime identity changed after activation/cleanup");
            result.status = result.persistent == ProofState::Proven ? SshActivationStatus::Success :
                result.persistent == ProofState::NonCompliant ? SshActivationStatus::RuntimeActivatedButPersistentDrift : SshActivationStatus::ActivationFailed;
        }
        result.diagnostic = result.activation.diagnostic;
        if(result.success()) {
#ifdef FIC_ACTIVATOR_TESTING
            if(tests&&tests->beforeFinalConfirmation) tests->beforeFinalConfirmation();
#endif
            const auto receiptState=service.current();
            service.confirm(receiptState);
            if(receiptState.at("InvocationID")!=promotedInvocation||receiptState.at("MainPID")!=promotedPid)
                throw d::Failure(ActivationStatus::InterferenceDetected,"runtime changed before receipt publication");
            if(socket)socket->confirm(receiptState);
            if(receiptEligible) runtimeReceipt={receiptKey,combined(receiptState),provenPolicies};
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            result.status = SshActivationStatus::ActivationFailed;
            result.persistent = ProofState::NotProven;
            result.diagnostic = "runtime outcome preserved; persistent proof deadline exceeded";
        }
    } catch (const SemanticFailure& e) {
        result.status=result.activationAttempted?SshActivationStatus::ActivationFailed:SshActivationStatus::Refused;
        result.semantics = e.mismatch ? ProofState::NonCompliant : ProofState::NotProven;
        result.diagnostic = e.mismatch ? "NonCompliant: selected SSH effective values differ" :
            "Unknown: selected SSH syntax/semantics proof unavailable";
    } catch (const d::Failure& e) {
        result.status=result.activationAttempted?SshActivationStatus::ActivationFailed:SshActivationStatus::Refused;
        result.diagnostic = std::string(activationStatusName(e.status))+": "+e.what();
        if (e.status == ActivationStatus::UnsupportedConfiguration) result.semantics = ProofState::Unsupported;
    } catch (...) {
        result.status=result.activationAttempted?SshActivationStatus::ActivationFailed:SshActivationStatus::Refused;
        result.diagnostic = "Unknown: SSH proof unavailable";
    }
    if(!result.success()) runtimeReceipt={};
    return result;
}
} // namespace
detail::ServiceAdmission detail::classifyServiceAdmission(const std::string& active,
    const std::string& substate,const std::string& job) {
    if(active=="active"&&substate=="running"&&job.empty())return ServiceAdmission::Ready;
    if(active=="activating"||active=="deactivating"||active=="reloading"||
       (active=="inactive"&&!job.empty()))return ServiceAdmission::Wait;
    throw d::Failure(ActivationStatus::ReadinessUnconfirmed,"SSH RuntimeNotReady: inactive/failed/unsupported runtime; no configuration mutation");
}
void detail::validateLaunchProfile(const std::map<std::string, std::string>& launch) { validateLaunch(launch); }
std::map<std::string,std::string> SshVerifiedActivationAdapter::serviceAdmission() {
    const std::lock_guard<std::mutex> receiptLock(receiptMutex);
    const auto profile=fic::platform::makeBuildPlatformProfile();std::string error;
    if(::geteuid()!=0||!supportedProfile(profile.id)||
       !fic::platform::validateHostCompatibility(profile,"/etc/os-release",error))unsupported("SSH admission supports root on Debian12/13 or Ubuntu24/26 only");
    // The generic environment contract requires a real reference, even for
    // readonly admission. Do not satisfy it with a placeholder digest.
    if(!fic::ssh::trustedSshInput("/etc/default/ssh",false,false,error))unsupported("untrusted SSH EnvironmentFile");
    auto env=d::openAbsolute("/etc/default/ssh",O_RDONLY);std::uint64_t budget=65536;
    const auto tree=d::readTree(env.get(),ControlledPathKind::File,budget);
    const auto& content=tree.files.at("");detail::validateEmptyOptions(content);
    std::vector<ControlledPath> targets{{"/etc/default/ssh",ControlledPathKind::File,fic::core::ContentDigest::sha256Hex(content),{}}};
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(60);
    d::SystemdActivation service("ssh.service",deadline,targets,activationProfile());
    const auto ready=admit(service);awaitRestartBudget(service,ready,false);
    if(ubuntuSocket())return detail::UbuntuSshSocketFlow(deadline).combined(ready);
    return ready.properties;
}
void SshVerifiedActivationAdapter::prepareRuntimeProbe(const SshVerifiedActivationRequest& request) {
    if(!ubuntuSocket())return;
    if(request.expectedService!=serviceAdmission())throw d::Failure(ActivationStatus::InterferenceDetected,"Ubuntu launch changed before runtime probe");
    const auto observed=capture(request.reference);validateCaptured(request,observed);
    if(request.observedMetadata!=metadataIdentities(observed))throw d::Failure(ActivationStatus::InterferenceDetected,"Ubuntu inputs changed before runtime probe");
    std::string error;if(!CommandHashStore::verifyHash("/usr/sbin/sshd",error))unsupported("SSH executable trust unproven");
    detail::UbuntuSshSocketFlow::prepareRuntimeDirectory();
    const auto profile=fic::platform::makeBuildPlatformProfile();
    fic::platform::PlatformExecutableResolver resolver(profile.executables);
    SshRuntimeOptions options;options.configPath="/etc/ssh/sshd_config";options.includeBasePath="/etc/ssh";
    options.requireTrustedInputs=true;options.useLaunchArguments=true;
    SshRuntime runtime(options,resolver);
    detail::UbuntuSshSocketFlow::effectiveEndpoints(runtime);
}
SshVerifiedActivationRequest SshVerifiedActivationAdapter::captureReference(
    const std::map<std::string,std::string>& policies,const std::string& expectedMainSha) {
    if(::geteuid()!=0||!fic::core::ContentDigest::isCanonicalSha256Hex(expectedMainSha))
        unsupported("trusted reference requires root and explicit expected main-file identity");
    detail::validatePolicies(policies);
    const auto profile=fic::platform::makeBuildPlatformProfile();std::string error;
    if(!supportedProfile(profile.id)||
       !fic::platform::validateHostCompatibility(profile,"/etc/os-release",error))
        unsupported("trusted SSH reference supports Debian12/13 or Ubuntu24/26 only");
    SshVerifiedActivationRequest out;out.policies=policies;out.reference.unit="ssh.service";
    out.reference.timeout=std::chrono::seconds(60);
    detail::InputBytes bytes;detail::PersistentMetadata initial;
    std::uint64_t budget=out.reference.maxSnapshotBytes;
    const auto add=[&](const std::filesystem::path& path,ControlledPathKind kind) {
        if(!fic::ssh::trustedSshInput(path,kind==ControlledPathKind::Directory,false,error))
            unsupported("untrusted SSH reference source");
        auto fd=d::openAbsolute(path,O_RDONLY);
        const auto tree=d::readTree(fd.get(),kind,budget);
        initial.roots.emplace(path.string(),d::identity(fd.get()));
        initial.attributes.emplace(path.string(),tree.attributes);
        ControlledPath input;input.path=path;input.kind=kind;
        for(const auto& [relative,content]:tree.files) {
            const auto name=kind==ControlledPathKind::File?path.string():(path/relative).string();
            if(!bytes.emplace(name,content).second)unsupported("duplicate SSH reference input");
            const auto digest=fic::core::ContentDigest::sha256Hex(content);
            if(kind==ControlledPathKind::File)input.sha256=digest;
            else input.manifest.emplace(relative,digest);
        }
        out.reference.paths.push_back(std::move(input));
    };
    add("/etc/ssh/sshd_config",ControlledPathKind::File);
    if(fic::core::ContentDigest::sha256Hex(bytes.at("/etc/ssh/sshd_config"))!=expectedMainSha)
        throw d::Failure(ActivationStatus::ChecksumMismatch,"main SSH source differs from caller-authorized state");
    add("/etc/ssh/sshd_config.d",ControlledPathKind::Directory);
    add("/etc/default/ssh",ControlledPathKind::File);
    const auto keys=detail::discoverHostKeys(out.reference,bytes,policies);
    for(const auto& key:keys) {add(key,ControlledPathKind::File);add(key+".pub",ControlledPathKind::File);}
    // Re-read through the actual adapter's metadata/manifest checks. A changed
    // source is refused; discovery is never authority to bless later bytes.
    const auto observed=capture(out.reference);
    detail::requireStableMetadata(initial,observed);validateCaptured(out,observed);
    d::validatePublicationEnvironment(out.reference);
    out.observedMetadata=metadataIdentities(observed);
    return out;
}
SshVerifiedActivationResult SshVerifiedActivationAdapter::activate(const SshVerifiedActivationRequest& r) { return perform(r); }
#ifdef FIC_ACTIVATOR_TESTING
namespace detail {
SshVerifiedActivationResult activateAdapterForTests(const SshVerifiedActivationRequest& r, const AdapterTestHooks& hooks) { return perform(r, &hooks); }
}
#endif
} // namespace fic::service::ssh
