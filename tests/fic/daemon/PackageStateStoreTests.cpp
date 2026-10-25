#include "daemon/PackageStateStore.h"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
namespace fs=std::filesystem;
using namespace fic::daemon;
using fic::core::PackageState;
void require(bool ok,const std::string& error){if(!ok)throw std::runtime_error(error);}
int main(){
    if(::geteuid()!=0)return 77;
    char pattern[]="/run/fic-package-store-XXXXXX";
    const char* made=::mkdtemp(pattern);if(!made)return 1;
    const fs::path root=made,file=root/"lifecycle/status";
    struct Cleanup{fs::path path;~Cleanup(){std::error_code ec;fs::remove_all(path,ec);}} cleanup{root};
    try{
        std::string error;DaemonInstanceLock guard,empty;
        require(guard.tryAcquire(root/"runtime",error),error);
        fic::core::FicProductPaths paths;paths.configDir=root/"config";paths.mutationJournalFile=root/"journal";
        PackageStateStore store(file);
        require(fic::core::readPackageState(file).file.status==fic::core::SecureStateReadStatus::Missing&&
                !fic::core::requireInstalledPackage(error,file)&&!fs::exists(file.parent_path()),
                "absent lifecycle directory must be read-only Missing and deny startup");
        fs::create_directory(root/"foreign");::chmod((root/"foreign").c_str(),0777);
        fs::create_directory_symlink(root/"foreign",file.parent_path());
        require(fic::core::readPackageState(file).file.status!=fic::core::SecureStateReadStatus::Missing,
                "symlink lifecycle directory treated as missing");
        fs::remove(file.parent_path());fs::remove(root/"foreign");
        require(!store.beginInstallation(empty,paths,error)&&!fs::exists(file),"unguarded creation");
        fs::create_directory(paths.configDir);
        require(!store.beginInstallation(guard,paths,error)&&!fs::exists(file),"existing config adopted without proof");
        fs::remove(paths.configDir);
        std::ofstream(paths.mutationJournalFile.string()+".initialized")<<"witness";
        require(!store.beginInstallation(guard,paths,error),"orphan witness adopted");
        fs::remove(paths.mutationJournalFile.string()+".initialized");
        require(store.beginInstallation(guard,paths,error),error);
        require(fic::core::readPackageState(file).state==PackageState::Installing,"fresh not INSTALLING");
        require(!store.completeRemoval(guard,error),"INSTALLING treated as proven removal");
        require(store.beginInstallation(guard,paths,error),error);
        require(store.completeInstallation(guard,error),error);
        require(fic::core::requireInstalledPackage(error,file),error);
        fs::create_directory(paths.configDir);std::ofstream(paths.configDir/"settings")<<"ENABLE\n";
        require(store.beginInstallation(guard,paths,error),error);
        require(!fic::core::requireInstalledPackage(error,file),"upgrade admitted before completion");
        require(store.completeInstallation(guard,error),error);
        require(store.fenceRemoval(guard,error),error);
        require(!store.beginInstallation(guard,paths,error),"uninstall cancelled by install");
        require(store.fenceRemoval(guard,error),error);
        require(!store.completeRemoval(empty,error),"unguarded removal");
        AtomicFileWriter::setDirectoryFsyncHookForTests([](const std::string&){return false;});
        require(!store.completeRemoval(guard,error),"nondurable removal reported success");
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
        require(store.completeRemoval(guard,error),error);
        require(fic::core::readPackageState(file).state==PackageState::Removed,"remove proof absent");
        require(!fic::core::requireInstalledPackage(error,file),"removed state admits daemon");
        require(store.beginInstallation(guard,paths,error),error);
        require(fs::exists(paths.configDir/"settings"),"reinstall erased saved config");
        std::ofstream(file)<<"UNKNOWN\n";
        require(!store.beginInstallation(guard,paths,error)&&!store.fenceRemoval(guard,error),"unknown state repaired");
        const auto emergencyFile=root/"emergency/status";
        PackageStateStore emergency(emergencyFile);
        require(emergency.fenceRemoval(guard,error),error);
        require(fic::core::readPackageState(emergencyFile).state==PackageState::Uninstalling,
            "missing emergency state did not become restrictive");
        require(!emergency.beginInstallation(guard,paths,error),"emergency fence admitted install/cancel");
        require(fs::exists(paths.configDir/"settings"),"restrictive fence altered policy config");
        std::cout<<"PASS: fresh/upgrade/remove/reinstall transitions, no adoption/cancel, durability failure and retry\n";
    }catch(const std::exception& e){AtomicFileWriter::setDirectoryFsyncHookForTests({});std::cerr<<e.what()<<'\n';return 1;}
}
