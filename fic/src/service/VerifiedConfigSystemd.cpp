#include "service/VerifiedConfigSystemd.h"
#include "service/VerifiedConfigLaunchContract.h"
#include "platform/PlatformExecutableResolver.h"
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/process/VerifiedProcessExecutor.h>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <unistd.h>

namespace fic::service::detail {
namespace {
const std::vector<std::string> properties{
    "Id", "LoadState", "ActiveState", "SubState", "Type", "NotifyAccess", "MainPID", "InvocationID", "Job", "Result",
    "RootDirectory", "RootImage", "ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths", "MountFlags",
    "PrivateMounts", "PrivateTmp", "PrivateDevices", "ProtectClock", "ProtectKernelTunables", "ProtectKernelModules",
    "ProtectKernelLogs", "ProtectControlGroups", "ProtectHome", "ProtectSystem", "BindPaths", "BindReadOnlyPaths",
    "TemporaryFileSystem", "ProtectHostname"};
const std::vector<std::string> noProperties{
    "PrivateMounts", "PrivateTmp", "PrivateDevices", "ProtectClock", "ProtectKernelTunables", "ProtectKernelModules",
    "ProtectKernelLogs", "ProtectControlGroups", "ProtectHome", "ProtectSystem", "ProtectHostname"};
const std::vector<std::string> emptyProperties{
    "RootDirectory", "RootImage", "ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths", "MountFlags",
    "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem"};
ProcessResult execute(const std::string& executable, const std::vector<std::string>& args,
                      std::chrono::milliseconds timeout) {
    ProcessOptions options; options.timeout = timeout; options.clearEnvironment = true;
    options.environment = {{"LANG", "C"}, {"LC_ALL", "C"}, {"PATH", "/usr/sbin:/usr/bin:/sbin:/bin"}};
    options.maxOutputBytes = 65536;
    return VerifiedProcessExecutor::execute(executable, args, options);
}
bool digits(const std::string& text) {
    return !text.empty() && std::all_of(text.begin(), text.end(), [](unsigned char c) { return c >= '0' && c <= '9'; });
}
std::string processToken(const ServiceState& state, const std::string& ns) {
    const auto text = state.at("MainPID");
    if (!digits(text) || text.size() > 10) throw Failure(ActivationStatus::ReadinessUnconfirmed, "invalid service MainPID");
    const auto value = std::stoull(text);
    if (value == 0 || value > 2147483647 || namespaceIdentity(value) != ns)
        throw Failure(ActivationStatus::ReadinessUnconfirmed, "service mount namespace is incompatible");
    std::ifstream input("/proc/" + text + "/stat"); std::string stat; std::getline(input, stat);
    const auto end = stat.rfind(')');
    if (end == std::string::npos) throw Failure(ActivationStatus::ReadinessUnconfirmed, "service process identity unavailable");
    std::istringstream fields(stat.substr(end + 1)); std::string field;
    for (unsigned i = 3; i <= 22; ++i) if (!(fields >> field))
        throw Failure(ActivationStatus::ReadinessUnconfirmed, "incomplete service process identity");
    struct stat root{}, self{};
    if (::stat(("/proc/" + text + "/root").c_str(), &root) || ::stat("/", &self) || root.st_dev != self.st_dev || root.st_ino != self.st_ino)
        throw Failure(ActivationStatus::ReadinessUnconfirmed, "service root is incompatible");
    return text + ":" + field;
}
}
std::string ServiceState::at(const std::string& key) const {
    const auto it = properties.find(key);
    if (it == properties.end()) throw Failure(ActivationStatus::UnsupportedConfiguration, "systemd property unavailable: " + key);
    return it->second;
}
SystemdActivation::SystemdActivation(const std::string& unit, std::chrono::steady_clock::time_point deadline,
                                     const std::vector<ControlledPath>& targets, ActivationProfile activationProfile)
    : profile_(activationProfile), unit_(unit), targets_(targets), deadline_(deadline) {
    namespace_ = namespaceIdentity(::getpid());
    std::ifstream comm("/proc/1/comm"); std::string name; std::getline(comm, name);
    if (name != "systemd" || namespaceIdentity(1) != namespace_)
        throw Failure(ActivationStatus::UnsupportedConfiguration, "activator and system manager must share a mount namespace");
    const auto profile = fic::platform::makeBuildPlatformProfile();
    if(profile_==ActivationProfile::UbuntuSshSocket && (unit_!="ssh.service" ||
       (profile.id!="ubuntu-24.04"&&profile.id!="ubuntu-26.04")))
        throw Failure(ActivationStatus::UnsupportedConfiguration,"closed Ubuntu SSH socket profile required");
    fic::platform::PlatformExecutableResolver resolver(profile.executables);
    std::filesystem::path executable; std::string error;
    if (!resolver.resolve(fic::platform::ExecutableId::Systemctl, executable, error) ||
        !CommandHashStore::verifyHash(executable, error))
        throw Failure(ActivationStatus::UnsupportedConfiguration, "systemctl trust is not proven: " + error);
    executable_ = executable.string();
}
std::chrono::milliseconds SystemdActivation::remaining() const {
    const auto value = std::chrono::duration_cast<std::chrono::milliseconds>(deadline_ - std::chrono::steady_clock::now());
    if (value.count() <= 0) throw Failure(ActivationStatus::TimedOut, "activation deadline exceeded");
    return value;
}
ServiceState SystemdActivation::query(std::chrono::milliseconds timeout) const {
    const auto queryDeadline = std::chrono::steady_clock::now() + timeout;
    std::string names;
    for (const auto& p : properties) { if (!names.empty()) names += ','; names += p; }
    const auto result = execute(executable_, {"--system", "--no-pager", "--no-ask-password", "show", "--property=" + names, "--", unit_}, timeout);
    if (!result.success()) throw Failure(result.timedOut ? ActivationStatus::TimedOut : ActivationStatus::ReadinessUnconfirmed,
        "systemctl show failed: " + result.error + result.standardError);
    ServiceState state; std::istringstream input(result.standardOutput); std::string line;
    while (std::getline(input, line)) {
        const auto equal = line.find('=');
        if (equal == std::string::npos || !state.properties.emplace(line.substr(0, equal), line.substr(equal + 1)).second)
            throw Failure(ActivationStatus::ReadinessUnconfirmed, "ambiguous systemctl properties");
    }
    for (const auto& p : properties) state.at(p);
    try {
        const auto launch = readLaunchContract(unit_, queryDeadline);
        state.properties.insert(launch.begin(), launch.end());
    } catch (const Failure& e) {
        if (!configuration_.empty() && e.status != ActivationStatus::TimedOut)
            throw Failure(ActivationStatus::InterferenceDetected, e.what());
        throw;
    }
    return state;
}
void SystemdActivation::verifyConfiguration(const ServiceState& s) const {
    // Changed/removed supported launch fields are interference, even when the
    // replacement is itself unsupported. Initial unsupported setups fail preflight.
    if (!configuration_.empty()) for (const auto& [key, expected] : configuration_)
        if (!s.properties.count(key) || s.at(key) != expected) throw Failure(ActivationStatus::InterferenceDetected, "service configuration changed: " + key);
    validateLaunchContract(s.properties, &targets_, profile_);
    if (s.at("Id") != unit_ || s.at("LoadState") != "loaded" || s.at("Type") != "notify" || s.at("NotifyAccess") != "main")
        throw Failure(ActivationStatus::UnsupportedConfiguration, "only loaded canonical notify/main service units are supported");
    for (const auto& p : noProperties) if (s.at(p) != "no")
        throw Failure(ActivationStatus::UnsupportedConfiguration, "unsupported service mount sandbox: " + p);
    for (const auto& p : emptyProperties) if (!s.at(p).empty())
        throw Failure(ActivationStatus::UnsupportedConfiguration, "unsupported service path sandbox: " + p);
}
ServiceState SystemdActivation::preflight() {
    auto s = query(remaining()); verifyConfiguration(s);
    const bool inactive=profile_==ActivationProfile::UbuntuSshSocket && s.at("ActiveState")=="inactive" && s.at("SubState")=="dead" && s.at("MainPID")=="0";
    if ((!inactive && (s.at("ActiveState") != "active" || s.at("SubState") != "running")) || !s.at("Job").empty())
        throw Failure(ActivationStatus::UnsupportedConfiguration, "service must be stable in supported activation profile");
    if(!inactive) processToken(s, namespace_);
    originalInvocation_ = s.at("InvocationID");
    if (!inactive && (originalInvocation_.size() != 32 || originalInvocation_ == std::string(32, '0') ||
        !std::all_of(originalInvocation_.begin(), originalInvocation_.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); })))
        throw Failure(ActivationStatus::UnsupportedConfiguration, "service InvocationID is unavailable");
    configuration_ = s.properties;
    for (const auto& key : {"ActiveState", "SubState", "MainPID", "InvocationID", "Job", "Result"}) configuration_.erase(key);
    return s;
}
void SystemdActivation::restart() {
    auto before = query(remaining()); verifyConfiguration(before);
    if (before.at("ActiveState") != "active" || before.at("InvocationID") != originalInvocation_ || !before.at("Job").empty())
        throw Failure(ActivationStatus::InterferenceDetected, "service changed before requested restart");
    const auto result = execute(executable_, {"--system", "--no-pager", "--no-ask-password", "--no-block", "--job-mode=fail", "restart", "--", unit_}, remaining());
    if (!result.success()) throw Failure(result.timedOut ? ActivationStatus::TimedOut : ActivationStatus::RestartFailed,
        "systemctl restart failed: " + result.error + result.standardError);
    auto queued = query(remaining());
    if (digits(queued.at("Job"))) job_ = queued.at("Job");
    verifyConfiguration(queued);
}
ServiceState SystemdActivation::current() const {
    auto s = query(remaining()); verifyConfiguration(s); return s;
}
bool SystemdActivation::ready(const ServiceState& s) const {
    if (s.at("ActiveState") == "failed") throw Failure(ActivationStatus::RestartFailed, "notify service failed: " + s.at("Result"));
    return s.at("ActiveState") == "active" && s.at("SubState") == "running" && s.at("Job").empty() &&
           !s.at("InvocationID").empty() && s.at("InvocationID") != originalInvocation_ && s.at("MainPID") != "0";
}
void SystemdActivation::confirm(const ServiceState& s) const {
    if (!ready(s)) throw Failure(ActivationStatus::ReadinessUnconfirmed, "notify readiness not established");
    const auto process = processToken(s, namespace_);
    auto again = current();
    if (!ready(again) || again.at("InvocationID") != s.at("InvocationID") || processToken(again, namespace_) != process)
        throw Failure(ActivationStatus::ReadinessUnconfirmed, "service identity/readiness changed during confirmation");
}
std::string SystemdActivation::cancelPendingJob() {
    if (job_.empty()) return {};
    try {
        auto s = query(std::chrono::milliseconds(1000));
        if (s.at("Job") != job_) return {};
        auto result = execute(executable_, {"--system", "--no-ask-password", "cancel", "--", job_}, std::chrono::milliseconds(1000));
        if (!result.success()) return "pending restart job cancellation failed: " + result.error + result.standardError;
    } catch (const std::exception& e) { return std::string("pending job cancellation unproven: ") + e.what(); }
    return {};
}
} // namespace fic::service::detail
