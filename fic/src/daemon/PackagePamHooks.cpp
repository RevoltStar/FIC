#include "daemon/PackagePamHooks.h"
#include "incident/AltIncidentAccessGateTopology.h"
#include "incident/PamIncidentAccessGateVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include <fic/core/fs/RootControlledDirectory.h>
#include <fic/core/fs/SecureStateFile.h>
#include <fic/core/process/ProcessExecutor.h>
#include <algorithm>
#include <array>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
namespace fic::daemon {
namespace {
constexpr std::array<const char*,14> profiles{{"fic-faillock-notify","fic-faillock-authfail",
    "fic-faillock-preauth-required","fic-faillock-authsucc","fic-faillock-hook-preauth",
    "fic-faillock-hook-authfail","fic-faillock-hook-authsucc","fic-faillock-hook-account",
    "fic-pwquality","fic-pwhistory","fic-password-quality-hook","fic-password-history-hook",
    "fic-password-history-initial-hook","fic-incident-access"}};
bool fail(std::string& error,const std::string& why){error=why;return false;}
bool read(const std::filesystem::path& file,std::string& content,std::string& error) {
    const int parent=fic::core::openRootControlledDirectory(file.parent_path(),error);
    if(parent<0)return false;
    ::close(parent);
    fic::core::SecureStateFileExpectation expected;expected.owner=0;expected.parentOwner=0;expected.forbiddenMode=0022;
    const auto result=fic::core::readSecureFileBounded(file,expected,1024*1024);
    if(result.status!=fic::core::SecureStateReadStatus::Proven)return fail(error,"unproven package PAM file: "+file.string()+": "+result.detail);
    content=result.content;return true;
}
bool pamAuthUpdate(const fic::platform::PlatformProfile& platform) {
    return platform.packageManager.kind==fic::platform::PackageManagerKind::Dpkg &&
        platform.pam.incidentAccessGate.packageTopologyTarget.empty();
}
}
bool PackagePamHooks::inspectOtherHooks(bool& detached,std::string& error) const {
    detached=true;
    if(platform_.id=="alt-p11"&&!platform_.pam.incidentAccessGate.packageTopologyTarget.empty())return true;
    if(!pamAuthUpdate(platform_))return fail(error,"unsupported package PAM infrastructure platform");
    for(const char* facility:{"auth","account","password","session"}) {
        std::string content;if(!read(selection_/facility,content,error))return false;
        std::istringstream lines(content);std::string line;
        while(std::getline(lines,line))if(line.rfind("Module: fic-",0)==0) {
            const auto selected=line.substr(8);
            if(std::find(profiles.begin(),profiles.end(),selected)==profiles.end())
                return fail(error,"unknown FIC PAM selection requires explicit recovery: "+selected);
        }
        // A malformed or duplicate selection mentioning one of our profiles
        // cannot authorize removal. Gate selection is checked in its own stage.
        for(const auto* profile:profiles)if(std::string(profile)!="fic-incident-access"&&content.find(profile)!=std::string::npos)
            detached=false;
    }
    std::size_t files=0,total=0;
    if(platform_.pam.configDirectories.empty())return fail(error,"no package PAM configuration directories");
    for(std::size_t index=0;index<platform_.pam.configDirectories.size();++index) {
        const auto& directory=platform_.pam.configDirectories[index];
        struct stat directoryInfo{};
        if(::lstat(directory.c_str(),&directoryInfo)&&errno==ENOENT&&index>0)continue;
        const int parent=fic::core::openRootControlledDirectory(directory,error);
        if(parent<0)return false;
        ::close(parent);
        std::error_code ec;
        std::filesystem::directory_iterator it(directory,ec),end;
        if(ec)return fail(error,"cannot enumerate package PAM services");
        for(;it!=end;it.increment(ec)) {
            if(ec||++files>4096)return fail(error,"package PAM enumeration budget exceeded");
            auto physical=it->path();struct stat info{};
            if(::lstat(physical.c_str(),&info))return fail(error,"cannot inspect package PAM service");
            if(S_ISLNK(info.st_mode)) {
                if(info.st_uid||info.st_nlink!=1)return fail(error,"foreign PAM service alias");
                const auto target=std::filesystem::read_symlink(physical,ec);
                if(ec||target.empty()||target!=target.filename()||target=="."||target=="..")return fail(error,"escaping PAM service alias");
                physical=directory/target;
            }
            std::string content;if(!read(physical,content,error))return false;
            total+=content.size();if(total>16*1024*1024)return fail(error,"package PAM content budget exceeded");
            std::vector<fic::identity::pam::PamRule> rules;
            if(!fic::identity::pam::PamConfiguration::parseRulesContent(physical,content,rules,error))return false;
            for(const auto& rule:rules) {
                if(rule.includeKind!=fic::identity::pam::PamIncludeKind::None &&
                   std::filesystem::path(rule.includeTarget).filename().string().rfind("fic-",0)==0)
                    detached=false;
                const auto module=std::filesystem::path(rule.module).filename().string();
                if(module.rfind("pam_fic_",0)==0&&module!="pam_fic_access.so")
                    detached=false;
            }
        }
        if(ec)return fail(error,"incomplete package PAM enumeration");
    }
    error.clear();return true;
}
bool PackagePamHooks::proveDetached(std::string& error) const {
    bool detached=false;
    if(!inspectOtherHooks(detached,error))return false;
    if(!detached)return fail(error,"FIC PAM package hooks remain selected/attached");
    const auto proof=fic::incident::PamIncidentAccessGateVerifier::proveDetached(
        platform_.pam,selection_/"account",error);
    return proof==fic::incident::IncidentGateDetachProof::ProvenDetached;
}
bool PackagePamHooks::removeProfiles(bool incident,std::chrono::steady_clock::time_point deadline,std::string& error) const {
    std::filesystem::path executable;
    if(!executables_.resolve(fic::platform::ExecutableId::PamAuthUpdate,executable,error))return false;
    const auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now());
    if(remaining.count()<=0)return fail(error,"package PAM detach deadline exceeded");
    std::vector<std::string> args{"--package","--remove"};
    for(const auto* profile:profiles)if((std::string(profile)=="fic-incident-access")==incident)args.emplace_back(profile);
    ProcessOptions options;options.timeout=std::min(remaining,std::chrono::milliseconds(5000));options.maxOutputBytes=65536;
    options.clearEnvironment=true;options.environment={{"LANG","C"},{"LC_ALL","C"},{"PATH","/usr/sbin:/usr/bin:/sbin:/bin"}};
    const auto result=ProcessExecutor::execute(executable,args,options);
    if(!result.success())return fail(error,"package PAM detach failed: "+result.error+" "+result.standardError);
    if(std::chrono::steady_clock::now()>=deadline)return fail(error,"package PAM detach deadline exceeded");
    return true;
}
bool PackagePamHooks::detach(const DaemonInstanceLock& guard,std::chrono::steady_clock::time_point deadline,std::string& error) const {
    if(!guard.heldByCurrentProcess())return fail(error,"package PAM detach requires daemon admission");
    if(std::chrono::steady_clock::now()>=deadline)return fail(error,"package PAM detach deadline exceeded");
    if(platform_.id=="alt-p11"&&!platform_.pam.incidentAccessGate.packageTopologyTarget.empty()) {
        if(std::chrono::steady_clock::now()>=deadline)return fail(error,"package PAM detach deadline exceeded");
        return fic::incident::AltIncidentAccessGateTopology::detach(platform_.pam.incidentAccessGate.packageTopologyTarget,error)&&proveDetached(error);
    }
    if(!pamAuthUpdate(platform_))return fail(error,"unsupported package PAM infrastructure platform");
    // Never compensate partial release with unproven hook/ownership adoption.
    // The caller's durable fence and masks remain active on EVERY failure.
    bool detached=false;
    if(!inspectOtherHooks(detached,error))return false;
    const auto gate=fic::incident::PamIncidentAccessGateVerifier::proveDetached(platform_.pam,selection_/"account",error);
    if(gate==fic::incident::IncidentGateDetachProof::Unprovable)return false;
    if(gate==fic::incident::IncidentGateDetachProof::Referenced &&
       !fic::incident::PamIncidentAccessGateVerifier::prove(platform_.pam,error))return false;
    if(!detached&&(!removeProfiles(false,deadline,error)||!inspectOtherHooks(detached,error)))return false;
    if(!detached)return fail(error,"FIC PAM package hooks remain selected/attached after removal");
    if(gate!=fic::incident::IncidentGateDetachProof::ProvenDetached) {
        // A successful updater exit is insufficient: the protective gate must
        // still be physically effective after detaching all OTHER hooks.
        if(!fic::incident::PamIncidentAccessGateVerifier::prove(platform_.pam,error)||
           !removeProfiles(true,deadline,error))return false;
    }
    return proveDetached(error);
}
}
