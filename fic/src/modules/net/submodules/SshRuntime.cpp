#include "modules/net/submodules/SshRuntime.h"

#include <fic/core/VerifiedProcessExecutor.h>

#include <algorithm>
#include <cctype>
#include <sstream>
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

bool SshRuntime::effectiveValue(const std::string& parameter,
                                std::string& value,
                                std::string& error) const {
    if (parameter.empty()) {
        error = "SSH parameter is empty";
        return false;
    }

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

    const std::string expectedName = lowerCopy(parameter);
    std::istringstream lines(result.standardOutput);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string name;
        if (!(fields >> name)) {
            continue;
        }
        if (lowerCopy(name) != expectedName) {
            continue;
        }
        std::getline(fields, value);
        value = trimCopy(std::move(value));
        error.clear();
        return true;
    }

    error = "sshd -T output does not contain parameter " + parameter;
    return false;
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
