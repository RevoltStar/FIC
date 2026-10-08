#include "incident/SshAccessContainmentBackend.h"

#include <fic/core/fs/SecureStateFile.h>
#include <fic/core/process/VerifiedProcessExecutor.h>
#include <fic/core/runtime/FicPathDefaults.h>
#include <fic/core/runtime/SystemBootInfo.h>

#include <algorithm>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

namespace fic::incident {
namespace {
constexpr std::uintmax_t kWitnessLimit = 2048;

SshCommandRunner commandRunner(SshCommandRunner runner) {
    if (runner) return runner;
    return [](const std::string& executable, const std::vector<std::string>& args,
              const ProcessOptions& options) {
        return VerifiedProcessExecutor::execute(executable, args, options);
    };
}

bool unitState(const std::string& systemctl, const std::string& unit,
               const SshCommandRunner& runner, std::string& state,
               std::string& error) {
    ProcessOptions clean;
    clean.clearEnvironment = true;
    const auto result = runner(systemctl,
                               {"show", "--property=ActiveState", unit}, clean);
    if (!result.success()) {
        error = "cannot inspect SSH listener " + unit;
        return false;
    }
    const std::string prefix = "ActiveState=";
    if (result.standardOutput.rfind(prefix, 0) != 0 ||
        result.standardOutput.empty() || result.standardOutput.back() != '\n' ||
        result.standardOutput.find('\n') != result.standardOutput.size() - 1) {
        error = "SSH listener state is unproven: " + unit;
        return false;
    }
    state = result.standardOutput.substr(prefix.size(),
                                         result.standardOutput.size() - prefix.size() - 1);
    if (state != "active" && state != "inactive" && state != "activating" &&
        state != "deactivating" && state != "failed") {
        error = "SSH listener state is unproven: " + unit;
        return false;
    }
    return true;
}

bool change(const std::string& systemctl, const std::string& action,
            const std::string& unit, const SshCommandRunner& runner,
            std::string& error) {
    ProcessOptions clean;
    clean.clearEnvironment = true;
    if (!runner(systemctl, {action, unit}, clean).success()) {
        error = "SSH " + action + " failed: " + unit;
        return false;
    }
    std::string state;
    if (!unitState(systemctl, unit, runner, state, error)) return false;
    if (state != (action == "start" ? "active" : "inactive")) {
        error = "SSH " + action + " did not reach expected state: " + unit;
        return false;
    }
    return true;
}

void emergencyStop(const std::string& systemctl,
                   const platform::SshPlatformConfig& platform,
                   const SshCommandRunner& runner) {
    ProcessOptions clean;
    clean.clearEnvironment = true;
    for (const auto& unit : platform.socketUnits)
        (void)runner(systemctl, {"stop", unit}, clean);
    for (const auto& unit : platform.serviceUnits)
        (void)runner(systemctl, {"stop", unit}, clean);
}
} // namespace

SshAccessContainmentBackend::SshAccessContainmentBackend()
    : SshAccessContainmentBackend({
          std::filesystem::path(fic::core::path_defaults::RUNTIME_DIR) /
              "incident-ssh-block",
          SystemBootInfo::get_boot_id(), 0, 0, 0755}) {}

SshAccessContainmentBackend::SshAccessContainmentBackend(WitnessOptions options)
    : options_(std::move(options)) {}

bool SshAccessContainmentBackend::load(
    const platform::SshPlatformConfig& platform, std::string& error) {
    services_.clear();
    sockets_.clear();
    witnessState_.reset();
    if (options_.bootId.empty() || options_.bootId.size() > 64 ||
        options_.path.filename() != "incident-ssh-block") {
        error = "invalid SSH block witness identity";
        return false;
    }
    fic::core::SecureStateFileExpectation expected;
    expected.owner = options_.owner;
    expected.group = options_.group;
    expected.exactMode = 0600;
    expected.maxSize = kWitnessLimit;
    expected.requireSingleLink = true;
    expected.parentOwner = options_.owner;
    expected.parentGroup = options_.group;
    expected.exactParentMode = options_.parentMode;
    const auto read = fic::core::readSecureFileBounded(
        options_.path, expected, kWitnessLimit);
    if (read.status == fic::core::SecureStateReadStatus::Missing) {
        error.clear();
        return true;
    }
    if (read.status != fic::core::SecureStateReadStatus::Proven) {
        error = "SSH block witness is untrusted: " + read.detail;
        return false;
    }
    if (read.content.empty() || read.content.back() != '\n') {
        error = "SSH block witness is incomplete";
        return false;
    }
    std::istringstream lines(read.content);
    std::string version, boot, line;
    if (!std::getline(lines, version) || version != "fic-ssh-block-v1" ||
        !std::getline(lines, boot) || boot.rfind("boot=", 0) != 0 ||
        boot.size() <= 5 || boot.size() > 69) {
        error = "SSH block witness has invalid header";
        return false;
    }
    StopMap services, sockets;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string kind, unit, state, extra;
        if (!(fields >> kind >> unit >> state) || fields >> extra) {
            error = "SSH block witness has malformed entry";
            return false;
        }
        const bool service = kind == "service";
        const bool socket = kind == "socket";
        const auto& allowed = service ? platform.serviceUnits : platform.socketUnits;
        if ((!service && !socket) ||
            std::find(allowed.begin(), allowed.end(), unit) == allowed.end() ||
            (state != "intent" && state != "stopped")) {
            error = "SSH block witness contains unknown unit or state";
            return false;
        }
        auto& target = service ? services : sockets;
        if (!target.emplace(unit, state == "intent" ? StopState::Intent :
                                                   StopState::Stopped).second) {
            error = "SSH block witness contains duplicate unit";
            return false;
        }
    }
    if (!lines.eof()) {
        error = "SSH block witness parsing did not reach EOF";
        return false;
    }
    if (boot.substr(5) != options_.bootId) {
        AtomicRemoveResult removed;
        if (!AtomicFileWriter::removeIfCurrentState(
                options_.path.string(), read.targetState, &error, &removed) ||
            !removed.removed || !removed.durabilityConfirmed) {
            error = "stale SSH block witness could not be discarded: " + error;
            return false;
        }
        error.clear();
        return true;
    }
    services_ = std::move(services);
    sockets_ = std::move(sockets);
    witnessState_ = read.targetState;
    error.clear();
    return true;
}

bool SshAccessContainmentBackend::save(std::string& error) {
    if (services_.empty() && sockets_.empty()) {
        if (!witnessState_) return true;
        AtomicRemoveResult removed;
        if (!AtomicFileWriter::removeIfCurrentState(
                options_.path.string(), *witnessState_, &error, &removed) ||
            !removed.removed || !removed.durabilityConfirmed) {
            error = "SSH block witness removal is unproven: " + error;
            return false;
        }
        witnessState_.reset();
        return true;
    }
    std::string content = "fic-ssh-block-v1\nboot=" + options_.bootId + "\n";
    const auto append = [&](const StopMap& map, const char* kind) {
        for (const auto& [unit, state] : map)
            content += std::string(kind) + " " + unit + " " +
                (state == StopState::Intent ? "intent\n" : "stopped\n");
    };
    append(services_, "service");
    append(sockets_, "socket");
    if (content.size() > kWitnessLimit) {
        error = "SSH block witness exceeds size limit";
        return false;
    }
    AtomicWriteOptions options;
    options.createIfMissing = !witnessState_;
    options.exclusiveCreate = !witnessState_;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = 0600;
    options.fileOwner = options_.owner;
    options.fileGroup = options_.group;
    if (witnessState_) options.expectedTargetState = *witnessState_;
    AtomicWriteResult written;
    if (!AtomicFileWriter::writeWithResult(
            options_.path.string(), content, options, &error, &written) ||
        !written.durabilityConfirmed || !written.installedTargetState) {
        error = "SSH block witness write is unproven: " + error;
        return false;
    }
    witnessState_ = written.installedTargetState;
    error.clear();
    return true;
}

bool SshAccessContainmentBackend::block(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    std::string& error, SshCommandRunner runner) {
    std::filesystem::path systemctl;
    if (!executables.resolve(platform::ExecutableId::Systemctl, systemctl, error))
        return false;
    runner = commandRunner(std::move(runner));
    if (!load(platform, error)) {
        emergencyStop(systemctl.string(), platform, runner);
        return false;
    }
    std::set<std::string> freshServices, freshSockets;
    const auto plan = [&](const std::string& unit, StopMap& owned,
                          std::set<std::string>& fresh) {
        std::string state;
        if (!unitState(systemctl.string(), unit, runner, state, error)) return false;
        if ((state == "active" || state == "activating") && !owned.count(unit)) {
            owned[unit] = StopState::Intent;
            fresh.insert(unit);
        }
        return true;
    };
    for (const auto& unit : platform.socketUnits)
        if (!plan(unit, sockets_, freshSockets)) {
            emergencyStop(systemctl.string(), platform, runner);
            return false;
        }
    for (const auto& unit : platform.serviceUnits)
        if (!plan(unit, services_, freshServices)) {
            emergencyStop(systemctl.string(), platform, runner);
            return false;
        }
    if ((!freshSockets.empty() || !freshServices.empty()) && !save(error)) {
        emergencyStop(systemctl.string(), platform, runner);
        return false;
    }

    bool issuedStop = false;
    const auto stop = [&](const std::string& unit, StopMap& owned,
                          std::set<std::string>& fresh) {
        std::string state;
        if (!unitState(systemctl.string(), unit, runner, state, error)) return false;
        if (state == "inactive") {
            if (owned.count(unit) && owned.at(unit) == StopState::Intent) {
                if (!fresh.count(unit) || !issuedStop) {
                    error = "SSH stop ownership is ambiguous after crash: " + unit;
                    return false;
                }
                owned[unit] = StopState::Stopped;
                return save(error);
            }
            return true;
        }
        if (state == "failed") {
            if (owned.count(unit) && owned.at(unit) == StopState::Intent) {
                error = "SSH stop ownership is ambiguous in failed state: " + unit;
                return false;
            }
            return true;
        }
        if (state == "deactivating") {
            if (!change(systemctl.string(), "stop", unit, runner, error))
                return false;
            if (owned.count(unit) && owned.at(unit) == StopState::Intent) {
                if (!fresh.count(unit)) {
                    error = "SSH stop ownership is ambiguous after crash: " + unit;
                    return false;
                }
                issuedStop = true;
                owned[unit] = StopState::Stopped;
                return save(error);
            }
            return true;
        }
        if (!owned.count(unit)) {
            owned[unit] = StopState::Intent;
            if (!save(error)) return false;
        }
        if (!change(systemctl.string(), "stop", unit, runner, error)) return false;
        issuedStop = true;
        owned[unit] = StopState::Stopped;
        return save(error);
    };
    for (const auto& unit : platform.socketUnits)
        if (!stop(unit, sockets_, freshSockets)) {
            emergencyStop(systemctl.string(), platform, runner);
            return false;
        }
    for (const auto& unit : platform.serviceUnits)
        if (!stop(unit, services_, freshServices)) {
            emergencyStop(systemctl.string(), platform, runner);
            return false;
        }
    error.clear();
    return true;
}

bool SshAccessContainmentBackend::restore(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    std::string& error, SshCommandRunner runner) {
    if (!load(platform, error)) return false;
    if (services_.empty() && sockets_.empty()) {
        error.clear();
        return true;
    }
    for (const auto& [unit, state] : services_)
        if (state == StopState::Intent) {
            error = "SSH stop ownership is ambiguous after crash: " + unit;
            return false;
        }
    for (const auto& [unit, state] : sockets_)
        if (state == StopState::Intent) {
            error = "SSH stop ownership is ambiguous after crash: " + unit;
            return false;
        }
    std::filesystem::path systemctl;
    if (!executables.resolve(platform::ExecutableId::Systemctl, systemctl, error))
        return false;
    runner = commandRunner(std::move(runner));
    const auto restoreMap = [&](StopMap& owned) {
        while (!owned.empty()) {
            const auto unit = owned.begin()->first;
            std::string state;
            if (!unitState(systemctl.string(), unit, runner, state, error)) return false;
            if (state == "inactive") {
                if (!change(systemctl.string(), "start", unit, runner, error))
                    return false;
            } else if (state != "active") {
                error = "SSH restore state is unproven: " + unit + "=" + state;
                return false;
            }
            owned.erase(unit);
            if (!save(error)) return false;
        }
        return true;
    };
    // A socket-activated service must receive its listener before it starts.
    if (!restoreMap(sockets_) || !restoreMap(services_)) return false;
    error.clear();
    return true;
}

} // namespace fic::incident
