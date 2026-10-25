#include "daemon/DaemonInstanceLock.h"
#include "daemon/PackagePamHooks.h"
#include "daemon/PackageStateStore.h"
#include "daemon/PackageWritersQuiescence.h"
#include "daemon/UninstallLifecycle.h"
#include "daemon/UninstallOverride.h"
#include "platform/PlatformCompatibility.h"
#include <fic/core/process/ExclusivePidLock.h>
#include <fic/core/process/ProcessExecutor.h>
#include <fic/core/fs/SecureStateFile.h>
#include <fic/ipc/FicIpcClient.h>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
namespace {
using namespace fic::daemon;
using fic::core::PackageState;
bool inventory(std::vector<LegacyWriterImage>& images,std::string& error) {
    const auto& paths=fic::core::FicRuntimePaths::get();
    for(const auto* name:{"fic","fic-dick"}) {
        const auto file=paths.privateBinDir/name;struct stat info{};
        if(::lstat(file.c_str(),&info)) {
            if(errno==ENOENT)continue;
            error="cannot inspect installed writer image: "+file.string();return false;
        }
        if(info.st_size==0) {
            fic::core::SecureStateFileExpectation expected;
            expected.owner=0;expected.parentOwner=0;expected.forbiddenMode=0022;
            expected.requireSingleLink=true;
            const auto empty=fic::core::readSecureFileBounded(file,expected,0);
            if(empty.status!=fic::core::SecureStateReadStatus::Proven){error="untrusted empty writer image";return false;}
            // Empty files cannot be a current executable image. Canonical
            // process identities, units/cgroups and admission remain checked.
            continue;
        }
        LegacyWriterImage image;
        if(!captureLegacyWriterImage(file,image,error,false))return false;
        images.push_back(std::move(image));
    }
    return true;
}
void warning(const std::string& text){
    std::cerr<<"FIC emergency uninstall: "<<text<<std::endl;
    ::openlog("fic-package-infrastructure",LOG_PID,LOG_AUTHPRIV);
    ::syslog(LOG_WARNING,"FIC emergency uninstall: %s",text.c_str());
    ::closelog();
}
bool fixedCommand(const std::filesystem::path& file,const std::vector<std::string>& arguments,std::string& error) {
    LegacyWriterImage image;if(!captureLegacyWriterImage(file,image,error))return false;
    ProcessOptions options;options.timeout=std::chrono::seconds(30);options.maxOutputBytes=65536;
    options.clearEnvironment=true;options.environment={{"LANG","C"},{"LC_ALL","C"},{"PATH","/usr/sbin:/usr/bin:/sbin:/bin"}};
    const auto result=ProcessExecutor::execute(file,arguments,options);
    if(!result.success()){error="package infrastructure command failed: "+result.error+" "+result.standardError;return false;}
    return true;
}
}
int main(int argc,char** argv) {
    if(argc==2&&std::string(argv[1])=="--lifecycle-contract"){std::cout<<"1\n";return 0;}
    if(::geteuid()!=0||argc!=2){std::cerr<<"usage (root only): fic-package-infrastructure prepare-install|remove|prove-remove\n";return 2;}
    const std::string command=argv[1];
    if(command!="prepare-install"&&command!="remove"&&command!="prove-remove")return 2;
    std::string error;
    const auto fail=[&](const std::string& text){std::cerr<<"FIC package lifecycle refused: "<<text<<std::endl;return 1;};
    if(!fic::core::FicRuntimePaths::initializeProduction(error))return fail(error);
    const auto platform=fic::platform::makeBuildPlatformProfile();
    if(!fic::platform::validateHostCompatibility(platform,"/etc/os-release",error))return fail(error);
    const fic::platform::PlatformExecutableResolver executables(platform.executables);
    const auto& paths=fic::core::FicRuntimePaths::get();
    PackageWritersQuiescence writers(executables);
    std::vector<LegacyWriterImage> images;
    if(!inventory(images,error))return fail(error);
    const auto deadline=[](){return std::chrono::steady_clock::now()+std::chrono::seconds(30);};
    UninstallOverride override;
    if(command=="remove") {
        if(!readUninstallOverride(override,error))return fail(error);
        if(override.present)warning("/etc/fic-uninstall-overload is active; preserved OS settings may require manual cleanup");
        const bool alreadyRemoved=fic::core::readPackageState().state==PackageState::Removed;
        fic::ipc::Client daemon(fic::ipc::DEFAULT_SOCKET_PATH,std::chrono::minutes(10),0);
        if(!alreadyRemoved&&override.prepare!=UninstallRequirement::Skip) {
            const auto result=daemon.request({{"command","prepare_uninstall"}});
            if(!result.value("ok",false)) {
                if(override.prepare==UninstallRequirement::Required)return fail(result.value("message","prepare-uninstall failed"));
                warning("daemon preparation unproven: "+result.value("message","no response"));
            }
        }
        if(!alreadyRemoved&&override.rollback!=UninstallRollbackMode::Skip) {
            const auto result=daemon.request({{"command","rollback_all"}});
            std::cout<<result.dump(2)<<std::endl;
            if(!result.value("ok",false)) {
                if(result.value("error_code","")=="ROLLBACK_STATE_UNPROVEN"||
                   !result.contains("results")||!result["results"].is_array()||
                   !result.contains("summary")||!result["summary"].is_object())
                    return fail("global rollback provenance unavailable; use explicit ROLLBACK_TYPE=SKIP after reviewing/manual PAM repair");
                if(override.rollback==UninstallRollbackMode::Standard)return fail("ownership rollback incomplete");
                warning("ownership rollback incomplete; unresolved resources will remain; no adoption on reinstall");
            }
        } else if(!alreadyRemoved) warning("ROLLBACK_TYPE=SKIP: policy rollback was not requested or inspected");
        if(override.stop!=UninstallRequirement::Skip&&!writers.requestStopBeforeAdmission(deadline(),error)) {
            if(override.stop==UninstallRequirement::Required)return fail(error);
            warning("stop request failed; actual stopped-writer proof remains mandatory: "+error);
        }
    } else if(command=="prepare-install") {
        const auto before=fic::core::readPackageState();
        if(before.state==PackageState::Uninstalling)return fail("installation cannot cancel UNINSTALLING; complete removal first");
        if(before.state==PackageState::Installed&&
           !fixedCommand(paths.privateBinDir/"fic",{"--maintenance","check-persistent"},error))return fail(error);
        if(!writers.requestStopBeforeAdmission(deadline(),error))return fail(error);
    }
    DaemonInstanceLock guard;
    if(!guard.tryAcquire(paths.runtimeDir,error))return fail(error);
    if(command=="prepare-install") {
        if(!PackageStateStore().beginInstallation(guard,paths,error)||!writers.proveStopped(guard,images,deadline(),error))return fail(error);
        std::cout<<"INSTALLING: writers stopped; normal startup denied until infrastructure proofs\n";
        return 0;
    }
    if(command=="prove-remove") {
        const auto state=fic::core::readPackageState();
        if(state.file.status==fic::core::SecureStateReadStatus::Missing) {
            // The device dependency may have been installed by itself. It
            // cannot own policy configuration/journal or the main executable.
            // Do not confuse a damaged main installation with this empty case.
            for(const auto& file:{paths.privateBinDir/"fic",paths.configDir,paths.lockStatusFile,
                    paths.mutationJournalFile,std::filesystem::path(paths.mutationJournalFile.string()+".initialized")}) {
                struct stat info{};
                if(::lstat(file.c_str(),&info)==0||errno!=ENOENT)
                    return fail("main FIC state exists without a valid removal proof: "+file.string());
            }
            if(!PackagePamHooks(platform).proveDetached(error)||!PackageStateStore().fenceRemoval(guard,error)||
               !writers.proveStopped(guard,images,deadline(),error)||!PackageStateStore().completeRemoval(guard,error))return fail(error);
        } else if(state.state!=PackageState::Removed)
            return fail("remove the main fic package successfully before removing fic-dick");
        if(!writers.proveStopped(guard,images,deadline(),error)||!PackagePamHooks(platform).proveDetached(error))return fail(error);
        return 0;
    }
    // Emergency skips bypass daemon requests, never local writer exclusion.
    // This restrictive publication is not a successful daemon prepare proof.
    ExclusivePidLock trustBarrier(paths.commandHashFile.string()+".lock",paths.lockDebugLogFile.string(),false);
    if(!trustBarrier.tryAcquire())return fail("trust-sync still active; retry removal");
    if(!PackageStateStore().fenceRemoval(guard,error))return fail(error);
    if(!writers.proveStopped(guard,images,deadline(),error))return fail(error);
    const auto prelogin=paths.privateBinDir/"fic-prelogin-integration";
    struct stat preloginInfo{};
    if(::lstat(prelogin.c_str(),&preloginInfo)==0) {
        if(!fixedCommand(prelogin,{"deactivate"},error))return fail(error);
    } else {
        if(errno!=ENOENT)return fail("prelogin integration cannot be inspected");
        struct stat dropin{};
        if(::lstat("/etc/systemd/system/display-manager.service.d/50-fic-prelogin.conf",&dropin)==0||errno!=ENOENT)
            return fail("prelogin integration helper missing while a DM drop-in remains; manual repair required");
        if(!writers.provePreloginStopped(deadline(),error))return fail(error);
    }
    if(!PackagePamHooks(platform).detach(guard,deadline(),error)||!PackagePamHooks(platform).proveDetached(error))return fail(error);
    if(!writers.proveStopped(guard,images,deadline(),error))return fail(error);
    if(!PackageStateStore().completeRemoval(guard,error))return fail(error);
    std::cout<<"REMOVED: writers absent and PAM detached; policy configuration and journal retained\n";
    return 0;
}
