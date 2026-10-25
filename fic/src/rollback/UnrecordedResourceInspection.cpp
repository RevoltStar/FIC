#include "rollback/UnrecordedResourceInspection.h"
#include "modules/net/ssh/SshResourceLock.h"
#include <fic/core/fs/RootControlledDirectory.h>
#include <fic/core/fs/SecureStateFile.h>
#include <cerrno>
#include <optional>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::rollback {
namespace {
using Path=std::filesystem::path;
// Missing parents are accepted only below a proven physical trusted ancestor.
bool parent(const Path& path,bool enforce,bool& exists,std::string& error) {
    exists=false;
    if(!path.is_absolute()||path.lexically_normal()!=path||path.string().find('\0')!=std::string::npos) {
        error="invalid ownership inspection path: "+path.string();return false;
    }
    Path nearest=path;struct stat info{};
    while(::lstat(nearest.c_str(),&info)!=0) {
        if(errno!=ENOENT||nearest==nearest.root_path()){error="unprovable resource ancestor: "+nearest.string();return false;}
        nearest=nearest.parent_path();
    }
    if(enforce) {
        const int fd=fic::core::openRootControlledDirectory(nearest,error);
        if(fd<0)return false;
        ::close(fd);
    } else {
        // Existing backend test seam; production always enforces ownership.
        Path current;
        for(const auto& component:nearest) {
            current/=component;
            if(::lstat(current.c_str(),&info)||!S_ISDIR(info.st_mode)) {
                error="non-physical resource ancestor: "+current.string();return false;
            }
        }
    }
    exists=nearest==path;return true;
}
bool staging(const Path& file,std::string& error) {
    std::error_code ec;
    std::filesystem::directory_iterator it(file.parent_path(),ec),end;
    if(ec){error="cannot enumerate resource staging: "+file.parent_path().string();return false;}
    const auto prefix="."+file.filename().string()+".tmp.";
    unsigned count=0;
    for(;it!=end;it.increment(ec)) {
        if(ec||++count>4096){error="resource staging inventory unproven";return false;}
        if(it->path().filename().string().rfind(prefix,0)==0) {
            error="unresolved resource staging artifact: "+it->path().string();return false;
        }
    }
    if(ec){error="resource staging inventory incomplete";return false;}return true;
}
bool read(const Path& file,bool enforce,std::optional<AtomicTargetState>& state,std::string& error) {
    state.reset();bool exists=false;
    if(!parent(file.parent_path(),enforce,exists,error))return false;
    if(!exists)return true;
    if(!staging(file,error))return false;
    fic::core::SecureStateFileExpectation expected;
    expected.requireSingleLink=true;
    if(enforce){expected.owner=0;expected.parentOwner=0;expected.forbiddenMode=0022;}
    const auto result=fic::core::readSecureFileBounded(file,expected,1024*1024);
    if(result.status==fic::core::SecureStateReadStatus::Unprovable){error=file.string()+": "+result.detail;return false;}
    if(result.status==fic::core::SecureStateReadStatus::Proven)state=result.targetState;
    return true;
}
bool noSudoMarkers(const Path& file,bool enforce,std::string& error) {
    std::optional<AtomicTargetState> state;
    if(!read(file,enforce,state,error))return false;
    if(state&&(state->content.find("#@FIC")!=std::string::npos||
               state->content.find("# FIC container")!=std::string::npos||
               state->content.find("# Managed by FIC")!=std::string::npos)) {
        error="SUDO physical FIC artifact has no active provenance: "+file.string();return false;
    }
    return true;
}
bool sudoDirectory(const Path& directory,bool enforce,std::string& error) {
    bool exists=false;if(!parent(directory,enforce,exists,error))return false;
    if(!exists)return true;
    std::error_code ec;
    std::filesystem::recursive_directory_iterator it(directory,ec),end;
    if(ec){error="cannot inspect sudoers directory";return false;}
    unsigned count=0;std::uintmax_t bytes=0;
    for(;it!=end;it.increment(ec)) {
        if(ec||++count>4096||it.depth()>16){error="sudoers inventory budget/error";return false;}
        struct stat info{};
        if(::lstat(it->path().c_str(),&info)){error="cannot inspect sudoers object";return false;}
        const auto name=it->path().filename().string();
        if(!name.empty()&&name.front()=='.'&&name.find(".tmp.")!=std::string::npos) {
            error="unresolved sudoers staging artifact: "+it->path().string();return false;
        }
        if(S_ISDIR(info.st_mode)) {
            bool present=false;if(!parent(it->path(),enforce,present,error)||!present)return false;
        } else {
            if(info.st_size<0||(bytes+=static_cast<std::uintmax_t>(info.st_size))>16*1024*1024) {
                error="sudoers inspection byte budget exceeded";return false;
            }
            if(!noSudoMarkers(it->path(),enforce,error))return false;
        }
    }
    if(ec){error="sudoers inventory incomplete";return false;}return true;
}
}
UnrecordedResourceState inspectUnrecordedResource(const PolicyRef& policy,
    const RollbackExecutorDeps& deps,MutationJournal& journal,std::string& error,
    ResourceInspectionPhase phase) {
    using State=UnrecordedResourceState;
    std::optional<MutationBackend> backend;
    if(policy.moduleName=="SYSCTL")backend=MutationBackend::Sysctl;
    if(policy.moduleName=="DAC"&&policy.submoduleName=="SudoEdit")backend=MutationBackend::Sudo;
    if(policy.moduleName=="NET"&&policy.submoduleName=="SshEdit")backend=MutationBackend::Ssh;
    if(!backend)return State::Continue;
    std::unique_lock<std::mutex> sudoLock(SudoersConfiguration::mutationMutex(),std::defer_lock);
    if(*backend==MutationBackend::Sudo)sudoLock.lock();
    if(!journal.usable()||!journal.lifecycleInitialized()) {
        error="unrecorded resource inspection requires proven journal/witness";return State::Error;
    }
    for(const auto& record:journal.records())
        if(record.isActive()&&record.undo.backend==*backend)return State::Continue;
    error.clear();
    if(*backend==MutationBackend::Sysctl) {
        const auto options=deps.sysctlOptions?deps.sysctlOptions():SysctlConfigurationOptions{};
        std::optional<AtomicTargetState> state;
        if(!read(options.platform.managedConfigPath,options.enforceOwnership,state,error))return State::Error;
        bool owned=false;
        if(state&&!SysctlConfiguration::inspectManagedSettings(state->content,owned,error))return State::Error;
        // The parser proves assignment syntax, not absence of the physical
        // artifact. Final uninstall requires the last-owner deletion contract;
        // even an empty/header-only orphan cannot be adopted or removed here.
        if(owned||(state&&phase==ResourceInspectionPhase::UninstallFinal)) {
            error="SYSCTL managed artifact has no active journal provenance: "+options.platform.managedConfigPath.string();
            return State::UnprovenOwnership;
        }
        return State::ProvenEmpty;
    }
    if(*backend==MutationBackend::Ssh) {
        if(!deps.sshOptions){error="SSH resource options unavailable";return State::Error;}
        const auto options=deps.sshOptions();
        std::set<Path> paths{options.configPath};
        // Retired records may still name a previous resource path. Do not lose
        // visibility of detached physical markers just because it is inactive.
        for(const auto& record:journal.records())if(record.undo.backend==*backend) {
            const auto& resource=record.resource;
            const auto last=resource.rfind(':');
            if(resource.rfind("ssh:",0)!=0||last<=4){error="unknown retired SSH resource";return State::Error;}
            paths.insert(resource.substr(4,last-4));
        }
        for(const auto& file:paths) {
            std::optional<AtomicTargetState> state;
            if(!read(file,options.enforceOwnership,state,error))return State::Error;
            if(state&&state->content.find("#@FIC")!=std::string::npos) {
                error="SSH physical FIC artifact has no active provenance: "+file.string();return State::UnprovenOwnership;
            }
        }
        return State::ProvenEmpty;
    }
    if(!deps.sudoersOptions){error="SUDO resource options unavailable";return State::Error;}
    const auto options=deps.sudoersOptions();
    std::optional<AtomicTargetState> main;
    if(!read(options.mainPath,options.enforceOwnership,main,error)||
       !noSudoMarkers(options.managedPath,options.enforceOwnership,error))return State::Error;
    if(!sudoDirectory(options.managedPath.parent_path(),options.enforceOwnership,error))return State::Error;
    if(main) {
        // Keep the existing include-graph parser. A no-op needs ownership proof,
        // not native provider semantic validation or an installed visudo.
        SudoersConfiguration config(options);
        if(!config.load(error))return State::Error;
        for(const auto& doc:config.graphDocuments()) {
            std::optional<AtomicTargetState> now;
            if(!read(doc.path,options.enforceOwnership,now,error)||!now||now->content!=doc.content) {
                if(error.empty())error="sudoers graph changed during ownership inspection";
                return State::Error;
            }
            if(!noSudoMarkers(doc.path,options.enforceOwnership,error))return State::Error;
        }
        if(!config.verifyIncludedDirectoryTopologyUnchanged(error))return State::Error;
    }
    std::set<Path> historical;
    for(const auto& record:journal.records())if(record.undo.backend==MutationBackend::Sudo) {
        const auto add=[&](const auto& proofs){for(const auto& proof:proofs)historical.insert(proof.canonicalPath);};
        if(const auto* p=std::get_if<UndoReleaseSudoScopedDefaults>(&record.undo.payload)) {
            add(p->previousProofs);add(p->targetProofs);
        }
        if(const auto* p=std::get_if<UndoReleaseSudoAuthentication>(&record.undo.payload)) {
            add(p->previousProofs);add(p->targetProofs);
        }
    }
    for(const auto& file:historical)if(!noSudoMarkers(file,options.enforceOwnership,error))return State::Error;
    return State::ProvenEmpty;
}
std::vector<ReleasedResourceInspection> inspectReleasedOptionalResources(
    const RollbackExecutorDeps& deps, MutationJournal& journal) {
    std::vector<ReleasedResourceInspection> results;
    for(const auto& policy:std::vector<PolicyRef>{{"NET","SshEdit","ssh_port"},
            {"DAC","SudoEdit","sudo_require_authentication"},{"SYSCTL","",""}}) {
        // Ordinary SSH rollback already holds this shared mutex; the final
        // read-only sweep runs separately and takes the same resource lock.
        std::unique_lock<std::mutex> sshLock(sshResourceMutex(),std::defer_lock);
        if(policy.moduleName=="NET")sshLock.lock();
        ReleasedResourceInspection result;
        result.domain=policy.moduleName=="NET"?"SSH":policy.moduleName=="DAC"?"SUDO":"SYSCTL";
        result.state=inspectUnrecordedResource(policy,deps,journal,result.detail,
            ResourceInspectionPhase::UninstallFinal);
        results.push_back(std::move(result));
    }
    return results;
}
}
