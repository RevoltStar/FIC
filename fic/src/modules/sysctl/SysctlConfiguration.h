#ifndef SYSCTLCONFIGURATION_H
#define SYSCTLCONFIGURATION_H
#include "platform/PlatformProfile.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
struct SysctlSourceLocation {std::filesystem::path path;std::string displayPath;size_t line=0;};
struct SysctlValueObservation {bool found=false;std::string value;SysctlSourceLocation source;};
struct SysctlOperationResult {
    bool ok=false,changed=false,conflict=false,targetMissing=false;
    // True only when the operation demonstrably did not publish persistent state.
    bool noEffect=true;
    std::string message;
    std::vector<std::string> diagnostics;
};
struct SysctlConfigurationOptions {
    fic::platform::SysctlPlatformConfig platform;
    std::vector<std::filesystem::path> directories={"/etc/sysctl.d","/run/sysctl.d","/usr/local/lib/sysctl.d","/usr/lib/sysctl.d","/lib/sysctl.d"};
    std::filesystem::path procpsMainPath="/etc/sysctl.conf"; // retained source compatibility; never parsed
    bool enforceOwnership=true;
};
// A dedicated FIC artifact and a metadata-only native loader topology proof.
// No foreign effective-value parser. Caller supplies journal ownership authority.
class SysctlConfiguration {
public:
    explicit SysctlConfiguration(SysctlConfigurationOptions options={});
    static std::mutex& mutationMutex();
    bool load(std::string& error); // supported loader + topology + own artifact
    bool loadManaged(std::string& error); // release does not depend on foreign config
    bool verifyPriority(std::string& error) const;
    bool verifyCurrent(std::string& error) const;
    SysctlValueObservation inspect(const std::string& key) const {return inspectManagedValue(key);}
    SysctlValueObservation inspectManagedValue(const std::string& key) const;
    const std::map<std::string,std::string>& managedValues() const {return values_;}
    const std::optional<AtomicTargetState>& snapshot() const {return snapshot_;}
    bool existed() const {return snapshot_.has_value();}
    static bool inspectManagedSettings(const std::string&,bool&,std::string&);
    SysctlOperationResult ensureManagedValue(const std::string&,const std::string&);
    SysctlOperationResult removeManagedKey(const std::string&,const std::string&,bool deleteEmpty=true);
private:
    SysctlConfigurationOptions options_;
    std::optional<AtomicTargetState> snapshot_;
    std::map<std::string,std::string> values_;
    std::map<std::string,std::string> topology_;
    bool directorySafe(const std::filesystem::path&,std::string&) const;
    bool topology(std::map<std::string,std::string>&,std::string&) const;
    SysctlOperationResult publish(const std::map<std::string,std::string>&,bool);
};
#endif
