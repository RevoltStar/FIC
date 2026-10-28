// Research entrypoint for the EXISTING generic engine, not an SSSD adapter.
#include "service/VerifiedConfigServiceActivator.h"
#include "service/VerifiedConfigServiceActivatorTestAccess.h"
#include "platform/PlatformExecutableResolver.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/integrity/CommandHashStore.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
using J=nlohmann::json;
namespace fs=std::filesystem;
using namespace fic::service;
std::string read(const std::string& path){std::ifstream f(path);return {std::istreambuf_iterator<char>(f),{}};}
int main(int argc,char** argv){
 J out;
 try {
  if(argc!=2||!getenv("FIC_SSSD_RESEARCH")||std::string(getenv("FIC_SSSD_RESEARCH"))!="1"||
    !fs::exists("/.dockerenv")||read("/proc/1/comm")!="systemd\n"||getuid()!=0)throw std::runtime_error("disposable research guard");
  const auto req=J::parse(read(argv[1]));
  auto paths=fic::core::FicProductPaths::production();
  paths.configDir="/run/sssd-research/config";paths.dataDir="/run/sssd-research/state";
  paths.logDir="/run/sssd-research/log";paths.runtimeDir="/run/sssd-research";
  paths.commandHashFile="/run/sssd-research/hashes";paths.lockDebugLogFile="/run/sssd-research/log/locks";
  for(auto p:{paths.configDir,paths.dataDir,paths.logDir})fs::create_directories(p);
  std::string error;if(!fic::core::FicRuntimePaths::initialize(paths,error))throw std::runtime_error(error);
  const auto profile=fic::platform::makeBuildPlatformProfile();fic::platform::PlatformExecutableResolver resolver(profile.executables);
  fs::path ctl;if(!resolver.resolve(fic::platform::ExecutableId::Systemctl,ctl,error)||!CommandHashStore::saveHash(ctl,error))throw std::runtime_error(error);
  ActivationRequest request;request.unit="sssd.service";request.timeout=std::chrono::milliseconds(req.value("timeout_ms",10000));
  for(const auto& p:req.at("paths")) {
   ControlledPath c;c.path=p.at("path").get<std::string>();c.kind=p.value("directory",false)?ControlledPathKind::Directory:ControlledPathKind::File;
   if(c.kind==ControlledPathKind::File)c.sha256=p.at("sha256");else c.manifest=p.at("manifest").get<FileManifest>();
   request.paths.push_back(c);
  }
  const auto action=req.value("action",std::string{});
  detail::TestHooks hooks;
  J observations=J::array();
  const int sourceFd=action=="preopened-write"?open("/etc/sssd/sssd.conf",O_RDWR|O_CLOEXEC):-1;
  hooks.checkpoint=[&](detail::TestPhase phase,const std::string&){
   using P=detail::TestPhase;
   if(phase==P::SnapshotReadOnly) {
    if(action=="replace-inode") {auto bytes=read("/etc/sssd/sssd.conf"); std::ofstream f("/etc/sssd/replacement");f<<bytes;f.close();chmod("/etc/sssd/replacement",0640);rename("/etc/sssd/replacement","/etc/sssd/sssd.conf");}
    if(action=="new-snippet") {std::ofstream f("/etc/sssd/conf.d/zzzzz-race.conf");f<<"[pam]\noffline_credentials_expiration=72\n";f.close();chmod("/etc/sssd/conf.d/zzzzz-race.conf",0600);}
    if(action=="environment-change") {std::ofstream f("/etc/default/sssd",std::ios::app);f<<"\n# deterministic pre-publication change\n";}
   }
   if(phase==P::Watching) {
    if(action=="ro-write") {errno=0;int fd=open("/etc/sssd/conf.d/zzzzz-race.conf",O_WRONLY|O_CREAT,0600);int e=errno;if(fd>=0)close(fd);observations.push_back({{"write_fd",fd},{"errno",e}});}
    if(action=="preopened-write") {errno=0;const char byte='#';auto n=pwrite(sourceFd,&byte,1,0);observations.push_back({{"write_count",n},{"errno",errno}});}
   }
  };
  const auto result=action.empty()?VerifiedConfigServiceActivator::activate(request):detail::activateForTests(request,hooks);
  if(sourceFd>=0)close(sourceFd);
  out={{"status",activationStatusName(result.status)},{"primary",activationStatusName(result.primaryStatus)},
   {"diagnostic",result.diagnostic},{"readiness",result.readinessConfirmed},{"cleanup_errors",result.cleanupErrors},{"residual_paths",result.residualPaths},{"hook_observations",observations}};
 }catch(const std::exception& e){out={{"error",e.what()}};}
 std::cout<<out.dump()<<'\n';return out.contains("error")?2:0;
}
