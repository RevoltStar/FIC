#include "modules/net/submodules/SshRuntime.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>

namespace {

class TemporaryTree {
public:
    TemporaryTree() {
        std::string pattern = "/tmp/fic-ssh-runtime-tests-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        root = created;
    }

    ~TemporaryTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }

    std::filesystem::path executable(const std::string& name) const {
        const std::filesystem::path path = root / name;
        std::ofstream stream(path);
        stream << "#!/bin/sh\nexit 0\n";
        stream.close();
        ::chmod(path.c_str(), 0755);
        return path;
    }

    std::filesystem::path root;
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

ProcessResult success(std::string output = {}) {
    ProcessResult result;
    result.started = true;
    result.exitCode = 0;
    result.standardOutput = std::move(output);
    return result;
}

ProcessResult inactive() {
    ProcessResult result;
    result.started = true;
    result.exitCode = 3;
    return result;
}

SshRuntimeOptions options(const TemporaryTree& tree) {
    SshRuntimeOptions value;
    value.configPath = tree.root / "sshd_config";
    value.sshdCandidates = {tree.executable("sshd").string()};
    value.systemctlCandidates = {tree.executable("systemctl").string()};
    return value;
}

void testEffectiveValueUsesSshdOutput() {
    TemporaryTree tree;
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>& arguments,
           const ProcessOptions&) {
            require(arguments.size() == 3 && arguments[0] == "-T" && arguments[1] == "-f",
                    "sshd must be invoked in extended test mode");
            return success("port 2222\npermitrootlogin prohibit-password\n");
        }
    );

    std::string value;
    std::string error;
    require(runtime.effectiveValue("Port", value, error), error);
    require(value == "2222", "wrong effective SSH value");
}

void testInactiveServiceDoesNotRequireReload() {
    TemporaryTree tree;
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return inactive();
        }
    );

    const SshActivationResult result = runtime.activateIfRunning();
    require(result.ok && !result.serviceActive && !result.reloaded,
            "inactive SSH service must not require runtime reload");
}

void testActiveServiceIsReloadedAndVerified() {
    TemporaryTree tree;
    int reloads = 0;
    SshRuntime runtime(
        options(tree),
        [&reloads](const std::string&,
                   const std::vector<std::string>& arguments,
                   const ProcessOptions&) {
            if (!arguments.empty() && arguments[0] == "reload") {
                ++reloads;
            }
            return success();
        }
    );

    const SshActivationResult result = runtime.activateIfRunning();
    require(result.ok && result.serviceActive && result.reloaded,
            "active SSH service must be reloaded");
    require(reloads == 1, "SSH service must be reloaded exactly once");
}

void testReloadFailureIsReported() {
    TemporaryTree tree;
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>& arguments,
           const ProcessOptions&) {
            if (!arguments.empty() && arguments[0] == "reload") {
                ProcessResult result;
                result.started = true;
                result.exitCode = 1;
                result.standardError = "reload rejected";
                return result;
            }
            return success();
        }
    );

    const SshActivationResult result = runtime.activateIfRunning();
    require(!result.ok && result.serviceActive && !result.reloaded,
            "reload failure must make SSH activation unsuccessful");
}

void testServiceInspectionFailureIsReported() {
    TemporaryTree tree;
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            ProcessResult result;
            result.started = true;
            result.exitCode = 1;
            result.standardError = "systemd unavailable";
            return result;
        }
    );

    const SshActivationResult result = runtime.activateIfRunning();
    require(!result.ok && !result.serviceActive,
            "systemctl failure must not be treated as an inactive SSH service");
}

} // namespace

int main() {
    const std::vector<std::pair<const char*, void (*)()>> tests = {
        {"effective value", testEffectiveValueUsesSshdOutput},
        {"inactive service", testInactiveServiceDoesNotRequireReload},
        {"active reload", testActiveServiceIsReloadedAndVerified},
        {"reload failure", testReloadFailureIsReported},
        {"service inspection failure", testServiceInspectionFailureIsReported}
    };

    std::size_t failures = 0;
    for (const auto& [name, test] : tests) {
        try {
            test();
        } catch (const std::exception& exception) {
            ++failures;
            std::cerr << "FAIL: " << name << ": " << exception.what() << '\n';
        }
    }
    return failures == 0 ? 0 : 1;
}
