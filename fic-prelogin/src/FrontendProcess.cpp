#include "FrontendProcess.h"
#include "PreLoginGraphicsPaths.h"
#include <fic/core/fs/SecureStateFile.h>
#include <chrono>
#include <thread>
#include <filesystem>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <climits>
#include <unistd.h>
#include <signal.h>
#include <iostream>
namespace fic::prelogin {
FrontendProcess::FrontendProcess(pid_t child,int channel):child_(child),channel_(channel) {}
FrontendProcess::~FrontendProcess(){forceReap(); if(channel_>=0)::close(channel_);}
bool FrontendProcess::start(std::string& error) {
    if(child_>0 || channel_>=0 || ::geteuid()!=0) {error="invalid graphics broker state";return false;}
    const auto* account=::getpwnam("fic-prelogin");
    if(!account || account->pw_uid==0 || account->pw_gid==0 || std::string(account->pw_dir)!="/nonexistent" ||
        std::filesystem::path(account->pw_shell).filename()!="nologin") {error="dedicated fic-prelogin account is unavailable";return false;}
    const auto uid=account->pw_uid; const auto gid=account->pw_gid;
    const auto* ficGroup=::getgrnam("fic");
    if(!ficGroup || gid==ficGroup->gr_gid) {error="frontend account cannot belong to administrative fic group";return false;}
    const gid_t ficGid=ficGroup->gr_gid;
    std::vector<gid_t> groups;
    for(const auto name:{"video","render","input"}) {
        const auto* group=::getgrnam(name);
        if(group && group->gr_gid!=0 && group->gr_gid!=ficGid) groups.push_back(group->gr_gid);
    }
    if(!::getgrnam("video") || !::getgrnam("input")) {
        error="graphics video/input groups are unavailable";return false;
    }
    // Package path and every canonical parent must be root-owned/non-writable.
    std::error_code ec; auto path=std::filesystem::canonical(graphicsPaths::FRONTEND,ec);
    if(ec) {error="graphics frontend is missing";return false;}
    for(auto dir=path.parent_path();!dir.empty();dir=dir.parent_path()) {
        struct stat s{};
        if(::lstat(dir.c_str(),&s)!=0 || !S_ISDIR(s.st_mode) || s.st_uid!=0 || (s.st_mode&0022)) {
            error="untrusted graphics executable directory";return false;
        }
        if(dir==dir.root_path())break;
    }
    const int executable=::open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    struct stat info{};
    if(executable<0 || ::fstat(executable,&info)!=0 || !S_ISREG(info.st_mode) || info.st_uid!=0 ||
        (info.st_mode&06022) || !(info.st_mode&0001)) {
        if(executable>=0)::close(executable);error="untrusted graphics executable";return false;
    }
    int sockets[2];
    if(::socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,sockets)!=0) {
        ::close(executable);error="cannot create private graphics channel";return false;
    }
    const pid_t parent=::getpid();
    child_=::fork();
    if(child_==0) {
        const int image=::fcntl(executable,F_DUPFD_CLOEXEC,6); if(image<0)_exit(126);
        ::close(sockets[0]);
        if(::dup2(sockets[1],3)<0 || ::fcntl(3,F_SETFD,0)<0) _exit(126);
        if(sockets[1]!=3)::close(sockets[1]);
        // Pin the executable without retaining other broker descriptors.
        if(::syscall(SYS_close_range,4,image-1,0)<0 || ::syscall(SYS_close_range,image+1,UINT_MAX,0)<0) {
            const long maximum=::sysconf(_SC_OPEN_MAX);
            for(int fd=4;fd<maximum;++fd)if(fd!=image)::close(fd);
        }
        if(::setgroups(groups.size(),groups.data())!=0 || ::setgid(gid)!=0 || ::setuid(uid)!=0 ||
            ::prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0 || ::prctl(PR_SET_PDEATHSIG,SIGKILL)!=0 || ::getppid()!=parent ||
            ::chdir("/")!=0) _exit(126);
        char name[]="fic-prelogin-frontend";char* arguments[]={name,nullptr};char* environment[]={nullptr};
        ::fexecve(image,arguments,environment);_exit(127);
    }
    ::close(executable);::close(sockets[1]);
    if(child_<0){::close(sockets[0]);error="cannot fork graphics frontend";return false;}
    channel_=sockets[0];return true;
}
bool FrontendProcess::running() {
    if(child_<=0)return false;
    const auto result=::waitpid(child_,&status_,WNOHANG);
    if(result==child_){child_=-1;return false;}
    if(result<0 && errno!=EINTR){child_=-1;protocolFailed_=true;return false;}
    return true;
}
std::optional<Action> FrontendProcess::action() {
    if(channel_<0)return {};
    char data[2];const auto bytes=::recv(channel_,data,sizeof(data),MSG_DONTWAIT|MSG_TRUNC);
    if(bytes<0 && (errno==EAGAIN || errno==EINTR))return {};
    if(bytes==1) {
        if(data[0]=='V'){
            ready_=true;
            std::cerr << "fic-prelogin broker: renderer readiness acknowledged\n";
            return {};
        }
        if(data[0]=='H')return Action::Handoff;
        if(data[0]=='R')return Action::Reboot;
        if(data[0]=='P')return Action::PowerOff;
    }
    protocolFailed_=true;return {};
}
void FrontendProcess::render(const PreLoginController& controller) {
    const auto& o=controller.observation();
    std::string detail=o.error,mode="не подтверждён",severity="не подтверждена",startup="Результат первого применения не подтверждён";
    if(o.verified) {
        const auto& s=*o.verified;mode=s.access.mode+(s.access.modeProven?"":" (не подтверждён)");
        severity=s.access.severity+(s.access.stateProven?"":" (не подтверждена)");detail=s.diagnostic;
        startup=s.completed?(s.applyOk?"Первое применение: успешно":"Первое применение: ошибка"):
            s.started?"Первое применение: выполняется":"Первое применение: ещё не началось";
    } else if(!o.systemd.text.empty()) detail=o.systemd.text+"\n"+detail;
    const auto data=ipc::json{{"state",uiStateToken(controller.state())},{"detail",detail},{"mode",mode},{"severity",severity},{"startup",startup}}.dump();
    if(channel_>=0 && ::send(channel_,data.data(),data.size(),MSG_DONTWAIT|MSG_NOSIGNAL)<0 && errno!=EAGAIN && errno!=EINTR)
        protocolFailed_=true;
}
bool FrontendProcess::awaitExit(int milliseconds) {
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(milliseconds);
    while(running()) {
        if(std::chrono::steady_clock::now()>=deadline)return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return true;
}
void FrontendProcess::forceReap() {
    if(child_<=0)return;
    ::kill(child_,SIGKILL);
    while(::waitpid(child_,&status_,0)<0 && errno==EINTR){}
    child_=-1;
}
bool FrontendProcess::cleanup(std::string& error) {
    if(child_<=0 && channel_<0)return true; // Frontend was never started.
    const char quit='Q';
    const bool sent=channel_>=0 && ::send(channel_,&quit,1,MSG_NOSIGNAL)==1;
    bool exited=awaitExit(3000);
    if(!exited)forceReap();
    if(channel_>=0){::close(channel_);channel_=-1;}
    const bool clean=sent && exited && !protocolFailed_ && WIFEXITED(status_) && WEXITSTATUS(status_)==0;
    if(!clean)error="graphics frontend cleanup did not prove a normal process exit";
    return clean;
}
}
