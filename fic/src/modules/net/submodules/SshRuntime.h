#ifndef SSHRUNTIME_H
#define SSHRUNTIME_H

#include <fic/core/ProcessExecutor.h>

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

struct SshRuntimeOptions {
    std::filesystem::path configPath = "/etc/ssh/sshd_config";
    std::vector<std::string> sshdCandidates = {
        "/usr/sbin/sshd",
        "/usr/bin/sshd"
    };
    std::vector<std::string> systemctlCandidates = {
        "/usr/bin/systemctl",
        "/bin/systemctl"
    };
    std::vector<std::string> serviceUnits = {
        "ssh.service",
        "sshd.service"
    };
};

struct SshActivationResult {
    bool ok = false;
    bool serviceActive = false;
    bool reloaded = false;
    std::string message;
};

using SshCommandRunner = std::function<ProcessResult(
    const std::string&,
    const std::vector<std::string>&,
    const ProcessOptions&
)>;

class SshRuntime {
public:
    explicit SshRuntime(SshRuntimeOptions options = {},
                        SshCommandRunner runner = {});

    bool effectiveValue(const std::string& parameter,
                        std::string& value,
                        std::string& error) const;
    SshActivationResult activateIfRunning() const;

private:
    SshRuntimeOptions options_;
    SshCommandRunner runner_;

    bool findExecutable(const std::vector<std::string>& candidates,
                        std::string& executable,
                        std::string& error) const;
};

#endif // SSHRUNTIME_H
