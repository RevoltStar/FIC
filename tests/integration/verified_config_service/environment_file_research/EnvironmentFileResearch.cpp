// Disposable systemd research, never a production activation implementation.
#include "service/VerifiedConfigMountSupport.h"
#include "service/VerifiedConfigLaunchContract.h"
#include "platform/PlatformExecutableResolver.h"
#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/process/ProcessExecutor.h>
#include <systemd/sd-daemon.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace d = fic::service::detail;
namespace fs = std::filesystem;
using Json = nlohmann::json;
using namespace fic::service;
const std::string root="/run/fic-env-research", unit="fic-env-research.service";
const std::string env=root+"/inputs/one.env", config=root+"/config/good.conf";
std::string executable, systemctl;
unsigned passed=0;
Json cases=Json::array();
void check(bool value,const std::string& why){if(!value)throw std::runtime_error(why+": "+std::strerror(errno));}
std::string read(const std::string& path){std::ifstream f(path);check(bool(f),"read "+path);return {std::istreambuf_iterator<char>(f),{}};}
void write(const std::string& path,const std::string& bytes){std::ofstream f(path);check(bool(f),"write "+path);f<<bytes;f.close();check(bool(f),"close "+path);}
std::string sha(const std::string& s){return fic::core::ContentDigest::sha256Hex(s);}
void event(const std::string& name,const Json& evidence=Json::object()){
 ++passed;cases.push_back({{"name",name},{"result","PASS"},{"evidence",evidence}});
 std::cout<<"PASS "<<name<<std::endl;
}
void waitFd(int fd){pollfd p{fd,POLLIN,0};check(::poll(&p,1,10000)>0&&(p.revents&POLLIN),"IPC barrier deadline");}
void send(int fd,const std::string& s){check(::send(fd,s.data(),s.size(),MSG_NOSIGNAL)==ssize_t(s.size()),"send barrier");}
std::string receive(int fd){waitFd(fd);char b[32768];auto n=::recv(fd,b,sizeof b,0);check(n>0,"receive barrier");return {b,std::size_t(n)};}
sockaddr_un address(){sockaddr_un a{};a.sun_family=AF_UNIX;auto p=root+"/control";check(p.size()<sizeof a.sun_path,"socket path");std::copy(p.begin(),p.end(),a.sun_path);return a;}
struct Gate{
 d::Fd server,connection;Json entry,report;
 Gate():server(::socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0)){
  auto a=address();::unlink(a.sun_path);check(::bind(server.get(),reinterpret_cast<sockaddr*>(&a),sizeof a)==0&&::listen(server.get(),5)==0,"server barrier");}
 ~Gate(){::unlink((root+"/control").c_str());}
 void accept(const std::string& role){waitFd(server.get());connection=d::Fd(::accept4(server.get(),nullptr,nullptr,SOCK_CLOEXEC));entry=Json::parse(receive(connection.get()));check(entry.at("role")==role,"fixture role "+role);}
 void go(){send(connection.get(),"GO");connection=d::Fd();}
 void readNow(){send(connection.get(),"READ");report=Json::parse(receive(connection.get()));}
 void notify(){send(connection.get(),"NOTIFY");check(receive(connection.get())=="READY_SENT","READY IPC acknowledgement");}
};
Json fixtureEnvironment(){Json e;for(const auto& key:{"FIC_ENV_WORD","FIC_ENV_CONFIG","SSHD_OPTS"}){const char* v=::getenv(key);e[key]=v?Json(v):Json(nullptr);}return e;}
int fixture(int argc,char** argv){
 const std::string role=argv[1];d::Fd fd(::socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0));auto a=address();
 check(::connect(fd.get(),reinterpret_cast<sockaddr*>(&a),sizeof a)==0,"fixture connect");
 Json args=Json::array();for(int i=0;i<argc;++i)args.push_back(argv[i]);
 Json entry{{"role",role},{"env",fixtureEnvironment()},{"argv",args},{"pid",::getpid()},{"namespace",d::namespaceIdentity(::getpid())}};
 send(fd.get(),entry.dump());
 if(role!="--fixture-main"){check(receive(fd.get())=="GO","pre/condition release");return 0;}
 check(receive(fd.get())=="READ","config read release");
 std::string path=::getenv("FIC_ENV_CONFIG")?::getenv("FIC_ENV_CONFIG"):config;
 for(int i=2;i+1<argc;++i){if(std::string(argv[i])=="-f")path=argv[++i];else if(std::string(argv[i])=="-o"){std::string v=argv[++i];if(v.rfind("FixtureConfig=",0)==0)path=v.substr(14);}}
 auto input=d::openAbsolute(path,O_RDONLY);auto id=d::identity(input.get());std::string bytes;char b[4096];
 for(;;){auto n=::read(input.get(),b,sizeof b);check(n>=0,"fixture config read");if(!n)break;bytes.append(b,n);}input=d::Fd();
 Json report=entry;report["config"]={{"path",path},{"sha256",sha(bytes)},{"mount_id",id.mount},{"inode",id.inode}};send(fd.get(),report.dump());
 auto next=receive(fd.get());if(next=="EXIT")return 23;
 if(next=="NOTIFY"){check(sd_notify(0,"READY=1")>0,"sd_notify");send(fd.get(),"READY_SENT");}
 else check(next=="SILENT","fixture READY command");
 for(;;){std::string command;try{command=receive(fd.get());}catch(...){for(;;)::pause();}if(command=="OBSERVE")send(fd.get(),report.dump());else throw std::runtime_error("unexpected fixture command");}
}
ProcessResult ctl(std::vector<std::string> args){ProcessOptions o;o.timeout=std::chrono::seconds(15);o.clearEnvironment=true;o.environment={{"PATH","/usr/sbin:/usr/bin:/sbin:/bin"},{"LANG","C"}};return ProcessExecutor::execute(systemctl,args,o);}
void must(std::vector<std::string> args){auto r=ctl(args);check(r.success(),"systemctl fixture command: "+r.standardError+r.error);}
std::string property(const std::string& key){auto r=ctl({"show","--value","--property="+key,unit});check(r.success(),"show fixture property");while(!r.standardOutput.empty()&&r.standardOutput.back()=='\n')r.standardOutput.pop_back();return r.standardOutput;}
void stop(){must({"stop",unit});ctl({"reset-failed",unit});}
std::string envBytes(const std::string& word="trusted",const std::string& path=config){return "FIC_ENV_WORD="+word+"\nFIC_ENV_CONFIG="+path+"\n";}
void reset(){stop();fs::remove_all(root+"/inputs");fs::create_directory(root+"/inputs");write(env,envBytes());write(config,"trusted configuration\n");write(root+"/config/evil.conf","foreign configuration\n");}
void install(std::vector<std::string> files={env},bool pre=false,bool condition=false,const std::string& extra=""){
 std::string s="[Unit]\nDescription=Disposable FIC EnvironmentFile research\nStartLimitIntervalSec=0\n[Service]\nType=notify\nNotifyAccess=main\nRestart=no\nTimeoutStartSec=2s\nTimeoutStopSec=2s\n";
 for(const auto& f:files)s+="EnvironmentFile="+f+"\n";
 if(condition)s+="ExecCondition="+executable+" --fixture-condition\n";
 if(pre)s+="ExecStartPre="+executable+" --fixture-pre\n";
 s+="ExecStart="+executable+" --fixture-main ${FIC_ENV_WORD} $SSHD_OPTS\n"+extra;
 write("/run/systemd/system/"+unit,s);must({"daemon-reload"});
}
void start(){must({"--no-block","start",unit});}
void ready(Gate& g){g.notify();must({"start",unit});check(property("ActiveState")=="active","notify state active");}
void restart(){must({"--no-block","restart",unit});}
void prime(bool pre=false){Gate g;start();if(pre){g.accept("--fixture-pre");g.go();}g.accept("--fixture-main");g.readNow();ready(g);}
void expect(const Gate& g,const std::string& word="trusted",const std::string& path=config){
 check(g.report.at("env").at("FIC_ENV_WORD")==word,"actual environment word");check(g.report.at("config").at("path")==path,"actual config path");
 check(g.report.at("config").at("sha256")==sha(read(path)),"actual read config digest");
 check(g.report.at("argv").size()>=3&&g.report.at("argv")[2]==word,"actual argv expansion");
}
// Experimental publication reuses real FIC traversal/copy/hash/identity helpers.
// It is not a second activator: no service integration, no recovery/API promises.
struct Snapshot{
 std::string workspace=root+"/snapshot";std::vector<std::pair<std::string,d::Identity>> published;bool mounted=false;
 Snapshot(const std::vector<std::pair<std::string,ControlledPathKind>>& paths){
  fs::create_directory(workspace);d::requireSafePublicationParent(workspace,false,ActivationStatus::UnsupportedConfiguration);
  check(::mount("fic-env-research",workspace.c_str(),"tmpfs",MS_NODEV|MS_NOSUID|MS_NOEXEC,"size=8388608,nr_inodes=8192,mode=0700")==0,"mount disposable snapshot tmpfs");mounted=true;
  try{
   std::uint64_t budget=8*1024*1024;unsigned i=0;
   for(const auto& [path,kind]:paths){d::requireSafePublicationParent(path,false,ActivationStatus::UnsupportedConfiguration);
    auto src=d::openAbsolute(path,O_RDONLY);auto tree=d::readTree(src.get(),kind,budget);auto dst=workspace+"/"+std::to_string(i++);
    if(kind==ControlledPathKind::Directory)fs::create_directory(dst);else write(dst,"");
    auto dest=d::openAbsolute(dst,kind==ControlledPathKind::File?O_RDWR:O_RDONLY);d::copyTree(src.get(),dest.get(),tree,kind);
    ControlledPath expected{dst,kind,"",{}};if(kind==ControlledPathKind::File)expected.sha256=sha(tree.files.at(""));else for(auto&[name,data]:tree.files)expected.manifest[name]=sha(data);
    d::verifyTree(dest.get(),expected,8*1024*1024);
   }
   check(::mount(nullptr,workspace.c_str(),nullptr,MS_REMOUNT|MS_RDONLY|MS_NODEV|MS_NOSUID|MS_NOEXEC,nullptr)==0,"RO tmpfs");
  }catch(...){cleanup();throw;}
 }
 void publish(const std::vector<std::string>& targets){
  unsigned i=0;for(const auto& target:targets){auto src=workspace+"/"+std::to_string(i++);check(::mount(src.c_str(),target.c_str(),nullptr,MS_BIND,nullptr)==0,"publish RO input");auto fd=d::openAbsolute(target,O_RDONLY);auto id=d::identity(fd.get());published.emplace_back(target,id);d::requireReadOnly(target,id,"tmpfs","fic-env-research");}
 }
 bool cleanup(){bool ok=true;for(auto it=published.rbegin();it!=published.rend();){
   try{auto fd=d::openAbsolute(it->first,O_RDONLY);auto now=d::identity(fd.get());check(now.mount==it->second.mount&&d::sameObject(now,it->second),"cleanup own identity");fd=d::Fd();if(::umount(it->first.c_str())!=0){ok=false;++it;}else {auto erase=std::next(it).base();it=std::vector<std::pair<std::string,d::Identity>>::reverse_iterator(published.erase(erase));}}
   catch(...){ok=false;++it;}}
  if(published.empty()&&mounted){if(::umount(workspace.c_str())==0){mounted=false;fs::remove(workspace);}else ok=false;}
  return ok&&published.empty()&&!mounted;
 }
 ~Snapshot(){if(mounted&&!cleanup())std::cerr<<"RESEARCH CLEANUP FAILED: residual fixture mounts\n";}
};
void single(){reset();install();Gate g;start();g.accept("--fixture-main");g.readNow();expect(g);ready(g);event("single-env-argv-config",g.report);}
void multiple(){reset();write(root+"/inputs/two.env","FIC_ENV_WORD=last\n");install({env,root+"/inputs/two.env"});Gate g;start();g.accept("--fixture-main");g.readNow();expect(g,"last");ready(g);event("multiple-environment-files-last-wins",g.report);}
void protectedInput(){reset();install();prime();auto oldInvocation=property("InvocationID");Snapshot snap({{env,ControlledPathKind::File},{config,ControlledPathKind::File}});snap.publish({env,config});Gate g;restart();g.accept("--fixture-main");
 int f=::open(env.c_str(),O_WRONLY|O_CLOEXEC);check(f<0&&errno==EROFS,"protected write EROFS");g.readNow();expect(g);check(g.report["config"]["mount_id"]==snap.published[1].second.mount,"actual config FD is published snapshot");ready(g);check(oldInvocation!=property("InvocationID"),"new InvocationID after controlled fixture restart");check(snap.cleanup(),"cleanup after READY");send(g.connection.get(),"OBSERVE");check(Json::parse(receive(g.connection.get()))==g.report,"running process stable after cleanup");event("RO-input-and-config-actual-read-mount-cleanup",g.report);}
void snapshotRace(){reset();install();auto original=d::openAbsolute(env,O_RDONLY);auto originalIdentity=d::identity(original.get());Snapshot snap({{env,ControlledPathKind::File}});std::string err;AtomicWriteOptions o;check(AtomicFileWriter::write(env,envBytes("foreign"),o,&err),"AtomicFileWriter concurrent replacement "+err);auto replaced=d::openAbsolute(env,O_RDONLY);check(!d::sameObject(originalIdentity,d::identity(replaced.get())),"existing production pre-bind identity check must reject replaced original");original=d::Fd();replaced=d::Fd();snap.publish({env});Gate g;start();g.accept("--fixture-main");g.readNow();expect(g);ready(g);check(snap.cleanup(),"cleanup snapshot race");check(read(env)==envBytes("foreign"),"underlying foreign write remains owned by writer");event("negative-original-replaced-production-CAS-refuses-despite-snapshot-bytes",g.report);}
void renameDuringRestart(){reset();install({env},true);prime(true);Snapshot snap({{env,ControlledPathKind::File}});snap.publish({env});Gate g;restart();g.accept("--fixture-pre");write(root+"/inputs/staged.env",envBytes("foreign"));errno=0;int r=::rename((root+"/inputs/staged.env").c_str(),env.c_str());check(r<0&&errno==EBUSY,"rename over bind mount EBUSY");g.go();g.accept("--fixture-main");g.readNow();expect(g);ready(g);check(snap.cleanup(),"cleanup rename");event("rename-original-during-start-pre-EBUSY",g.report);}
void afterManagerRead(){reset();install();Gate g;start();g.accept("--fixture-main");write(env,envBytes("foreign",root+"/config/evil.conf"));g.readNow();expect(g);ready(g);event("environment-copied-before-exec-not-late-path-read",g.report);}
void afterReady(){reset();install();Snapshot snap({{env,ControlledPathKind::File}});snap.publish({env});Gate g;start();g.accept("--fixture-main");g.readNow();expect(g);ready(g);check(snap.cleanup(),"cleanup before next persistent write");write(env,envBytes("later"));send(g.connection.get(),"OBSERVE");check(Json::parse(receive(g.connection.get()))==g.report,"process environment immutable by file replacement");Gate next;restart();next.accept("--fixture-main");next.readNow();expect(next,"later");ready(next);event("post-READY-write-affects-next-start-only",next.report);}
void optional(const std::string& mode){reset();fs::remove(env);install({"-"+env},true);Gate g;start();g.accept("--fixture-pre");check(g.entry["env"]["FIC_ENV_WORD"].is_null(),"pre optional absent");if(mode=="appears")write(env,envBytes("appeared"));g.go();g.accept("--fixture-main");g.readNow();if(mode=="appears")expect(g,"appeared");else check(g.report["env"]["FIC_ENV_WORD"].is_null(),"main optional absent");ready(g);event("optional-absence-"+mode,g.report);}
void optionalBefore(){reset();fs::remove(env);install({"-"+env});prime();check(!fs::exists(env),"observed absence");write(env,envBytes("appeared"));Gate g;restart();g.accept("--fixture-main");g.readNow();expect(g,"appeared");ready(g);event("negative-absence-check-before-restart-is-insufficient",g.report);}
void vanished(bool optional){reset();install({(optional?"-":"")+env});prime();fs::remove(env);if(optional){Gate g;restart();g.accept("--fixture-main");g.readNow();check(g.report["env"]["FIC_ENV_WORD"].is_null(),"optional vanished ignored");ready(g);}else{auto r=ctl({"restart",unit});check(!r.success(),"mandatory vanished start failed");}event(optional?"optional-file-vanishes-before-start":"mandatory-file-vanishes-start-fails");}
void directoryAbsence(){reset();fs::remove(env);install({"-"+env});Snapshot snap({{root+"/inputs",ControlledPathKind::Directory}});snap.publish({root+"/inputs"});check(::open(env.c_str(),O_CREAT|O_WRONLY|O_CLOEXEC,0644)<0&&errno==EROFS,"absence parent blocks creation");Gate g;start();g.accept("--fixture-main");g.readNow();check(g.report["env"]["FIC_ENV_WORD"].is_null(),"optional absent under directory snapshot");ready(g);check(snap.cleanup(),"absence directory cleanup");check(!fs::exists(env),"no placeholder left");event("optional-absence-protected-parent",g.report);}
void emptyOptional(bool optional){reset();write(env,"");install({(optional?"-":"")+env});Gate g;start();g.accept("--fixture-main");g.readNow();check(g.report["env"]["FIC_ENV_WORD"].is_null(),"empty environment file adds no variables");ready(g);event(optional?"optional-empty-file-environment-equivalence":"mandatory-empty-file-succeeds-unlike-absent",g.report);}
void symlink(){reset();fs::rename(env,root+"/inputs/real.env");fs::create_symlink(root+"/inputs/real.env",env);bool refused=false;try{auto fd=d::openAbsolute(env,O_RDONLY);}catch(const d::Failure&){refused=true;}check(refused,"FIC rejects symlink");install();Gate g;start();g.accept("--fixture-main");g.readNow();expect(g);ready(g);event("systemd-follows-symlink-FIC-source-refuses",g.report);}
void redirect(const std::string& flag){reset();write(env,envBytes()+"SSHD_OPTS="+(flag=="-f"?"-f ":"-o FixtureConfig=")+root+"/config/evil.conf\n");install();Gate g;start();g.accept("--fixture-main");g.readNow();expect(g,"trusted",root+"/config/evil.conf");ready(g);event("synthetic-SSHD_OPTS-"+flag+"-redirect",g.report);}
void phaseRead(){reset();install({env},true,true);Gate g;start();g.accept("--fixture-condition");check(g.entry["env"]["FIC_ENV_WORD"]=="trusted","condition env read");write(env,envBytes("pre"));g.go();g.accept("--fixture-pre");check(g.entry["env"]["FIC_ENV_WORD"]=="pre","pre env fresh");write(env,envBytes("main"));g.go();g.accept("--fixture-main");g.readNow();expect(g,"main");ready(g);event("condition-pre-start-each-loads-environment",g.report);}
void reload(){reset();write(root+"/inputs/two.env",envBytes("reloaded"));install({env},true);Gate g;start();g.accept("--fixture-pre");auto before=d::readLaunchContract(unit,std::chrono::steady_clock::now()+std::chrono::seconds(10));install({root+"/inputs/two.env"},true);auto after=d::readLaunchContract(unit,std::chrono::steady_clock::now()+std::chrono::seconds(10));check(before.at("launch.EnvironmentFiles")!=after.at("launch.EnvironmentFiles"),"typed launch-input list change detected");g.go();g.accept("--fixture-main");g.readNow();expect(g,"reloaded");ready(g);event("daemon-reload-changes-next-command-launch-inputs",g.report);}
void failed(bool timeout){reset();install();Gate g;start();g.accept("--fixture-main");g.readNow();send(g.connection.get(),timeout?"SILENT":"EXIT");auto r=ctl({"start",unit});check(!r.success()&&property("ActiveState")=="failed","start failure or READY deadline");event(timeout?"READY-timeout":"startup-exit-failure",{{"result",property("Result")}});}
void cleanupFailure(){reset();install();Snapshot snap({{env,ControlledPathKind::File}});snap.publish({env});Gate g;start();g.accept("--fixture-main");g.readNow();ready(g);d::Fd busy(::open(env.c_str(),O_RDONLY|O_CLOEXEC));check(!snap.cleanup(),"ordinary cleanup failure must not be success");busy=d::Fd();check(snap.cleanup(),"manual retry after busy fd release");event("cleanup-EBUSY-is-not-success");}
void mountSubstitution(){reset();install({env},true);prime(true);Snapshot snap({{env,ControlledPathKind::File}});snap.publish({env});auto expected=snap.published[0].second;d::MountObserver observer;Gate g;restart();g.accept("--fixture-pre");check(!observer.changed(),"observer baseline clean before deliberate mount ABA");
 auto foreign=root+"/inputs/foreign.env";write(foreign,envBytes("foreign"));check(::mount(foreign.c_str(),env.c_str(),nullptr,MS_BIND,nullptr)==0,"foreign overmount");g.go();g.accept("--fixture-main");check(::umount(env.c_str())==0,"restore original publication before endpoint checks");auto fd=d::openAbsolute(env,O_RDONLY);auto now=d::identity(fd.get());check(now.mount==expected.mount&&d::sameObject(now,expected),"same original publication restored");check(sha(read(env))==sha(envBytes()),"endpoint hashes restored");g.readNow();expect(g,"foreign");ready(g);check(observer.changed(),"sticky mount observer detected ABA");fd=d::Fd();check(snap.cleanup(),"cleanup after ABA");event("negative-mount-ABA-endpoint-hashes-and-ID-pass-observer-rejects",g.report);}
void staleFd(){reset();install({env},true);d::Fd held(::open(env.c_str(),O_WRONLY|O_CLOEXEC));check(bool(held),"original writer FD");Snapshot snap({{env,ControlledPathKind::File}});snap.publish({env});Gate g;start();g.accept("--fixture-pre");auto bad=envBytes("foreign");check(::ftruncate(held.get(),0)==0&&::write(held.get(),bad.data(),bad.size())==ssize_t(bad.size()),"write original FD behind snapshot");g.go();g.accept("--fixture-main");g.readNow();expect(g);ready(g);check(snap.cleanup(),"cleanup stale FD");check(read(env)==bad,"original mutation survives temporary protection");event("preopened-original-writer-cannot-change-published-snapshot",g.report);}
void wildcardSpecifier(){reset();write(root+"/inputs/two.env",envBytes("last"));install({root+"/inputs/*.env"});Gate g;start();g.accept("--fixture-main");g.readNow();expect(g,"last");ready(g);event("glob-sorted-files-last-wins",g.report);stop();install({"%t/fic-env-research/inputs/one.env"});Gate next;start();next.accept("--fixture-main");next.readNow();expect(next);ready(next);event("unit-specifier-resolved-before-load",next.report);}
void fixedEnvironmentAlternative(){
 reset();install({},false,false,"Environment=FIC_ENV_WORD=fixed\nEnvironment=FIC_ENV_CONFIG="+config+"\n");write(env,envBytes("foreign"));Gate g;start();g.accept("--fixture-main");g.readNow();expect(g,"fixed");ready(g);event("C-fixture-static-environment-ignores-external-file",g.report);
}
void actualReader(){
 reset();fs::remove(env);check(::mkfifo(env.c_str(),0600)==0,"reader probe FIFO");install();Gate g;int pair[2];check(::socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair)==0,"reader probe channel");
 pid_t child=::fork();check(child>=0,"reader observer fork");
 if(child==0){::close(pair[0]);::alarm(8);try{
  d::Fd writer(::open(env.c_str(),O_WRONLY|O_CLOEXEC));check(bool(writer),"FIFO writer meets reader");struct stat target{};check(::fstat(writer.get(),&target)==0,"FIFO stat");bool pid1=false;
  for(const auto& f:fs::directory_iterator("/proc/1/fd")){struct stat st{};if(::stat(f.path().c_str(),&st)==0&&st.st_dev==target.st_dev&&st.st_ino==target.st_ino)pid1=true;}
  auto bytes=envBytes("pid1-read");check(::write(writer.get(),bytes.data(),bytes.size())==ssize_t(bytes.size()),"FIFO synthetic bytes");
  send(pair[1],Json{{"reader_pid",pid1?1:0},{"reader_comm",read("/proc/1/comm")},{"namespace",d::namespaceIdentity(1)}}.dump());writer=d::Fd();::_exit(0);
 }catch(...){::_exit(1);}}
 ::close(pair[1]);d::Fd channel(pair[0]);start();auto observed=Json::parse(receive(channel.get()));int status=0;check(::waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"reader observer complete");check(observed["reader_pid"]==1,"EnvironmentFile actually open in PID1 while FIFO held");g.accept("--fixture-main");g.readNow();expect(g,"pid1-read");ready(g);event("actual-EnvironmentFile-reader-is-PID1-before-exec",observed);
}
void optionalObject(const std::string& kind){
 reset();fs::remove(env);
 if(kind=="directory")fs::create_directory(env);else if(kind=="dangling-symlink")fs::create_symlink(root+"/inputs/missing",env);else {write(env,"");check(::chmod(env.c_str(),0000)==0,"fixture mode000");}
 install({"-"+env});Gate g;start();g.accept("--fixture-main");g.readNow();check(g.report["env"]["FIC_ENV_WORD"].is_null(),"optional non-data object yields no variables");ready(g);event("optional-object-"+kind,g.report);
}
void absentVsEmptyVisible(){
 reset();fs::remove(env);install({"-"+env},true);Gate absent;start();absent.accept("--fixture-pre");check(!fs::exists(env),"absent visible to pre command");absent.go();absent.accept("--fixture-main");absent.readNow();ready(absent);auto absentEnv=absent.report["env"];stop();write(env,"");Gate empty;start();empty.accept("--fixture-pre");check(fs::exists(env)&&fs::is_regular_file(env),"empty placeholder visible to pre command");empty.go();empty.accept("--fixture-main");empty.readNow();ready(empty);check(empty.report["env"]==absentEnv,"empty/absent variable sets match only");event("empty-placeholder-not-equivalent-filesystem-observation",{{"same_environment",true},{"same_existence",false}});
}
int main(int argc,char**argv){
 try{
  if(argc>1&&std::string(argv[1]).rfind("--fixture-",0)==0)return fixture(argc,argv);
  check(::getenv("FIC_ENV_RESEARCH_DISPOSABLE")&&std::string(::getenv("FIC_ENV_RESEARCH_DISPOSABLE"))=="1"&&::getuid()==0&&fs::exists("/.dockerenv")&&read("/proc/1/comm")=="systemd\n","disposable root Docker/systemd guard");
  executable=fs::canonical("/proc/self/exe");auto profile=fic::platform::makeBuildPlatformProfile();fic::platform::PlatformExecutableResolver resolver(profile.executables);fs::path path;std::string why;check(resolver.resolve(fic::platform::ExecutableId::Systemctl,path,why),why);systemctl=path;
  check(d::namespaceIdentity(1)==d::namespaceIdentity(::getpid()),"manager namespace equality");
  check(!fs::exists(root),"fixture root already exists: refuse adoption");fs::create_directories(root+"/config");fs::create_directory(root+"/inputs");install();
  actualReader();single();multiple();protectedInput();snapshotRace();renameDuringRestart();staleFd();afterManagerRead();afterReady();
  optional("absent");optional("appears");optionalBefore();vanished(true);vanished(false);directoryAbsence();emptyOptional(true);emptyOptional(false);optionalObject("directory");optionalObject("dangling-symlink");optionalObject("mode000");absentVsEmptyVisible();symlink();redirect("-f");redirect("-o");phaseRead();reload();failed(false);failed(true);cleanupFailure();mountSubstitution();wildcardSpecifier();fixedEnvironmentAlternative();
  stop();fs::remove("/run/systemd/system/"+unit);must({"daemon-reload"});
  for(const auto& m:d::readMountInfo())check(m.source!="fic-env-research","leaked research mount");
  Json out{{"passed",passed},{"failed",0},{"kernel",read("/proc/sys/kernel/osrelease")},{"systemd",ctl({"--version"}).standardOutput},{"namespace",d::namespaceIdentity(1)},{"cases",cases}};
  std::cout<<"EVIDENCE "<<out.dump()<<std::endl;fs::remove_all(root);return 0;
 }catch(const std::exception&e){std::cerr<<"FAIL "<<e.what()<<std::endl;std::cout<<"EVIDENCE "<<Json{{"passed",passed},{"failed",1},{"cases",cases}}.dump()<<std::endl;return 1;}
}
