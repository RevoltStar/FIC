#include "modules/net/submodules/SshRuntime.h"
#include "modules/net/submodules/SshConfigAudit.h"

#include <fic/core/VerifiedProcessExecutor.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <set>
#include <sstream>
#include <system_error>
#include <utility>

#include <unistd.h>

namespace {

std::string trimCopy(std::string value) {
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), value.end());
    return value;
}

std::string lowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string processFailure(const ProcessResult& result) {
    if (!result.error.empty()) {
        return result.error;
    }
    if (result.timedOut) {
        return "command timed out";
    }
    if (!result.standardError.empty()) {
        return trimCopy(result.standardError);
    }
    return "exit code " + std::to_string(result.exitCode);
}

bool parseDecimal(const std::string& value, int& result) {
    const std::string trimmed = trimCopy(value);
    if (trimmed.empty()) {
        return false;
    }
    const char* begin = trimmed.data();
    const char* end = begin + trimmed.size();
    const auto parsed = std::from_chars(begin, end, result);
    return parsed.ec == std::errc() && parsed.ptr == end;
}

bool explicitListenPort(const std::string& value, int& port) {
    std::istringstream fields(value);
    std::string address;
    if (!(fields >> address)) {
        return false;
    }

    std::string portText;
    if (!address.empty() && address.front() == '[') {
        const std::size_t closingBracket = address.rfind(']');
        if (closingBracket == std::string::npos ||
            closingBracket + 1 >= address.size() ||
            address[closingBracket + 1] != ':') {
            return false;
        }
        portText = address.substr(closingBracket + 2);
    } else {
        const std::size_t colon = address.rfind(':');
        if (colon == std::string::npos ||
            address.find(':') != colon) {
            return false;
        }
        portText = address.substr(colon + 1);
    }
    return parseDecimal(portText, port);
}

int permitRootLoginRank(std::string value) {
    value = lowerCopy(trimCopy(std::move(value)));
    if (value == "no") {
        return 0;
    }
    if (value == "forced-commands-only") {
        return 1;
    }
    if (value == "prohibit-password" || value == "without-password") {
        return 2;
    }
    if (value == "yes") {
        return 3;
    }
    return -1;
}

bool conditionalValueIsSafe(const std::string& parameter,
                            const std::string& actual,
                            const std::string& expected) {
    const std::string normalizedParameter = lowerCopy(parameter);
    if (normalizedParameter == "permitrootlogin") {
        const int actualRank = permitRootLoginRank(actual);
        const int expectedRank = permitRootLoginRank(expected);
        return actualRank >= 0 && expectedRank >= 0 && actualRank <= expectedRank;
    }
    if (normalizedParameter == "maxauthtries") {
        int actualValue = 0;
        int expectedValue = 0;
        return parseDecimal(actual, actualValue) &&
               parseDecimal(expected, expectedValue) &&
               actualValue > 0 &&
               actualValue <= expectedValue;
    }
    return lowerCopy(trimCopy(actual)) == lowerCopy(trimCopy(expected));
}

} // namespace

SshRuntime::SshRuntime(SshRuntimeOptions options, SshCommandRunner runner)
    : options_(std::move(options)),
      runner_(std::move(runner)) {
    if (!runner_) {
        runner_ = [](const std::string& executable,
                     const std::vector<std::string>& arguments,
                     const ProcessOptions& processOptions) {
            return VerifiedProcessExecutor::execute(executable, arguments, processOptions);
        };
    }
}

bool SshRuntime::findExecutable(const std::vector<std::string>& candidates,
                                std::string& executable,
                                std::string& error) const {
    for (const std::string& candidate : candidates) {
        if (!candidate.empty() && candidate.front() == '/' &&
            ::access(candidate.c_str(), X_OK) == 0) {
            executable = candidate;
            error.clear();
            return true;
        }
    }
    error = "required executable is unavailable";
    return false;
}

bool SshRuntime::loadEffectiveConfiguration(EffectiveConfiguration& configuration,
                                            std::string& error) const {
    std::string sshd;
    if (!findExecutable(options_.sshdCandidates, sshd, error)) {
        error = "sshd validation is unavailable: " + error;
        return false;
    }

    ProcessOptions processOptions;
    processOptions.clearEnvironment = true;
    const ProcessResult result = runner_(
        sshd,
        {"-T", "-f", options_.configPath.string()},
        processOptions
    );
    if (!result.success()) {
        error = "sshd effective configuration check failed: " + processFailure(result);
        return false;
    }

    configuration.clear();
    std::istringstream lines(result.standardOutput);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string name;
        if (!(fields >> name)) {
            continue;
        }
        std::string value;
        std::getline(fields, value);
        configuration[lowerCopy(name)].push_back(trimCopy(std::move(value)));
    }
    error.clear();
    return true;
}

bool SshRuntime::effectiveValues(const std::string& parameter,
                                 std::vector<std::string>& values,
                                 std::string& error) const {
    if (parameter.empty()) {
        error = "SSH parameter is empty";
        return false;
    }

    EffectiveConfiguration configuration;
    if (!loadEffectiveConfiguration(configuration, error)) {
        return false;
    }

    const auto found = configuration.find(lowerCopy(parameter));
    if (found != configuration.end() && !found->second.empty()) {
        values = found->second;
        error.clear();
        return true;
    }
    values.clear();
    error = "sshd -T output does not contain parameter " + parameter;
    return false;
}

bool SshRuntime::auditConditionalOverrides(const std::string& parameter,
                                           const std::string& expectedValue,
                                           std::string& error) const {
    const std::filesystem::path includeBase = options_.includeBasePath.empty()
        ? options_.configPath.parent_path()
        : options_.includeBasePath;
    if (!includeBase.is_absolute()) {
        error = "SSH Include base path must be absolute";
        return false;
    }

    SshConfigAuditOptions auditOptions;
    auditOptions.configPath = options_.configPath;
    auditOptions.includeBasePath = includeBase.lexically_normal();
    SshConfigAudit audit(std::move(auditOptions));

    std::vector<SshConditionalOccurrence> occurrences;
    if (!audit.findConditionalOccurrences(parameter, occurrences, error)) {
        error = "failed to audit conditional SSH configuration: " + error;
        return false;
    }

    for (const SshConditionalOccurrence& occurrence : occurrences) {
        if (!conditionalValueIsSafe(parameter, occurrence.value, expectedValue)) {
            error = "conditional SSH override " + occurrence.path.string() + ":" +
                    std::to_string(occurrence.line) + " under Match " +
                    occurrence.condition + " has value '" + occurrence.value +
                    "', which is weaker than or incompatible with expected value '" +
                    expectedValue + "'";
            return false;
        }
    }
    error.clear();
    return true;
}

bool SshRuntime::verifyPolicyValue(const std::string& parameter,
                                   const std::string& expectedValue,
                                   std::string& error) const {
    if (parameter.empty() || expectedValue.empty()) {
        error = "SSH parameter or expected value is empty";
        return false;
    }

    EffectiveConfiguration configuration;
    if (!loadEffectiveConfiguration(configuration, error)) {
        return false;
    }

    const std::string normalizedParameter = lowerCopy(parameter);
    const auto found = configuration.find(normalizedParameter);
    if (found == configuration.end() || found->second.empty()) {
        error = "sshd -T output does not contain parameter " + parameter;
        return false;
    }

    if (normalizedParameter == "port") {
        int expectedPort = 0;
        if (!parseDecimal(expectedValue, expectedPort) ||
            expectedPort < 1 || expectedPort > 65535) {
            error = "invalid expected SSH port '" + expectedValue + "'";
            return false;
        }

        std::set<int> effectivePorts;
        for (const std::string& value : found->second) {
            int port = 0;
            if (!parseDecimal(value, port) || port < 1 || port > 65535) {
                error = "sshd -T returned invalid port '" + value + "'";
                return false;
            }
            effectivePorts.insert(port);
        }
        if (effectivePorts.size() != 1 || *effectivePorts.begin() != expectedPort) {
            std::string actual;
            for (int port : effectivePorts) {
                if (!actual.empty()) {
                    actual += ", ";
                }
                actual += std::to_string(port);
            }
            error = "effective SSH ports are [" + actual +
                    "], expected the single port " + std::to_string(expectedPort);
            return false;
        }

        const auto listenAddresses = configuration.find("listenaddress");
        if (listenAddresses != configuration.end()) {
            for (const std::string& value : listenAddresses->second) {
                int listenPort = 0;
                if (explicitListenPort(value, listenPort) && listenPort != expectedPort) {
                    error = "effective ListenAddress '" + value +
                            "' uses port " + std::to_string(listenPort) +
                            ", expected " + std::to_string(expectedPort);
                    return false;
                }
            }
        }
    } else {
        if (found->second.size() != 1) {
            error = "sshd -T returned " + std::to_string(found->second.size()) +
                    " effective values for scalar parameter " + parameter;
            return false;
        }
        if (lowerCopy(trimCopy(found->second.front())) !=
            lowerCopy(trimCopy(expectedValue))) {
            error = "effective SSH value '" + found->second.front() +
                    "' does not match expected value '" + expectedValue + "'";
            return false;
        }
    }

    return auditConditionalOverrides(parameter, expectedValue, error);
}

SshActivationResult SshRuntime::activateIfRunning() const {
    SshActivationResult activation;
    std::string systemctl;
    std::string error;
    if (!findExecutable(options_.systemctlCandidates, systemctl, error)) {
        activation.message = "SSH runtime activation is unavailable: " + error;
        return activation;
    }

    ProcessOptions processOptions;
    processOptions.clearEnvironment = true;
    std::string activeUnit;
    for (const std::string& unit : options_.serviceUnits) {
        const ProcessResult status = runner_(
            systemctl,
            {"is-active", "--quiet", unit},
            processOptions
        );
        if (!status.started) {
            activation.message = "failed to inspect SSH service " + unit +
                                 ": " + processFailure(status);
            return activation;
        }
        if (status.success()) {
            activeUnit = unit;
            break;
        }
        if (status.timedOut || !status.error.empty() ||
            (status.exitCode != 3 && status.exitCode != 4)) {
            activation.message = "failed to inspect SSH service " + unit +
                                 ": " + processFailure(status);
            return activation;
        }
    }

    if (activeUnit.empty()) {
        activation.ok = true;
        activation.message = "SSH service is not active; runtime reload is not required";
        return activation;
    }

    activation.serviceActive = true;
    const ProcessResult reload = runner_(
        systemctl,
        {"reload", activeUnit},
        processOptions
    );
    if (!reload.success()) {
        activation.message = "failed to reload " + activeUnit +
                             ": " + processFailure(reload);
        return activation;
    }

    const ProcessResult status = runner_(
        systemctl,
        {"is-active", "--quiet", activeUnit},
        processOptions
    );
    if (!status.success()) {
        activation.message = activeUnit + " is not active after reload: " +
                             processFailure(status);
        return activation;
    }

    activation.ok = true;
    activation.reloaded = true;
    activation.message = activeUnit + " reloaded successfully";
    return activation;
}
