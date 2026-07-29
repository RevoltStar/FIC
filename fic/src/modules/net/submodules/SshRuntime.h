#ifndef SSHRUNTIME_H
#define SSHRUNTIME_H

#include <fic/core/ProcessExecutor.h>

#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <vector>

struct SshRuntimeOptions {
    std::filesystem::path configPath;
    std::filesystem::path includeBasePath;
    std::vector<std::string> sshdCandidates;
    std::vector<std::string> systemctlCandidates;
    std::vector<std::string> serviceUnits;
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
    explicit SshRuntime(SshRuntimeOptions options,
                        SshCommandRunner runner = {});

    bool effectiveValues(const std::string& parameter,
                         std::vector<std::string>& values,
                         std::string& error) const;
    bool verifyPolicyValue(const std::string& parameter,
                           const std::string& expectedValue,
                           std::string& error) const;
    SshActivationResult activateIfRunning() const;

private:
    using EffectiveConfiguration = std::map<std::string, std::vector<std::string>>;

    SshRuntimeOptions options_;
    SshCommandRunner runner_;

    bool loadEffectiveConfiguration(EffectiveConfiguration& configuration,
                                    std::string& error) const;
    bool auditConditionalOverrides(const std::string& parameter,
                                   const std::string& expectedValue,
                                   std::string& error) const;
    bool findExecutable(const std::vector<std::string>& candidates,
                        std::string& executable,
                        std::string& error) const;
};

#endif // SSHRUNTIME_H
