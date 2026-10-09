// Disposable VM-only daemon fixture. Uses the production serializer and real
// Unix framing; no policy apply/authentication implementation exists here.
#include <fic/ipc/FicReadinessStatus.h>
#include <fic/core/runtime/SystemBootInfo.h>
#include "FicIpcWire.h"
#include <systemd/sd-daemon.h>
#include <filesystem>
#include <fstream>
#include <csignal>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
namespace {
volatile sig_atomic_t stopping = 0;
void stop(int) { stopping = 1; }
std::string line(const char* path) { std::ifstream file(path); std::string result; std::getline(file,result); return result; }
}
int main() {
    if (::geteuid()!=0 || line("/sys/class/dmi/id/product_name")!="FIC-Prelogin-Disposable" ||
        !std::filesystem::exists("/etc/fic-prelogin-test-vm")) return 2;
    ::signal(SIGTERM,stop); ::signal(SIGINT,stop);
    ::sd_notify(0,"READY=1\nSTATUS=Applying startup policies");
    std::filesystem::create_directories("/run/fic");
    const char* path=fic::ipc::path_defaults::DAEMON_SOCKET;
    ::unlink(path);
    int fd=::socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0); sockaddr_un address{}; address.sun_family=AF_UNIX;
    std::strncpy(address.sun_path,path,sizeof(address.sun_path)-1);
    if (::bind(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))!=0 || ::listen(fd,8)!=0) return 1;
    ::chmod(path,0600);
    while (!stopping) {
        pollfd descriptor{fd,POLLIN,0}; if (::poll(&descriptor,1,250)<=0) continue;
        int client=::accept4(fd,nullptr,nullptr,SOCK_CLOEXEC); if (client<0) continue;
        char data[1024]; const int bytes=::recv(client,data,sizeof(data),0);
        fic::ipc::json request, response; std::string error;
        if (bytes>0 && fic::ipc::parse_request_json(std::string(data,bytes),request,error) &&
            fic::ipc::request_has_only_fields(request,{"command"},error)) {
            const auto stage=line("/run/fic-prelogin-tests/case");
            fic::ipc::PreLoginStatus s;
            s.bootId=SystemBootInfo::get_boot_id(); s.daemonPid=::getpid();
            s.started=stage!="INITIALIZING"; s.completed=stage=="READY" || stage=="FAILED" || stage=="ISOLATE" || stage=="STALE";
            s.applyOk=s.completed && stage!="FAILED"; s.lifecycleCompleted=s.completed;
            s.access.state=s.completed ? "READY" : stage=="DEGRADED" ? "DEGRADED" : "APPLYING";
            s.access.mode="ACTIVE"; s.access.modeProven=true; s.access.stateProven=true; s.access.provenance="PROVEN";
            s.access.severity=stage=="ISOLATE" ? "ISOLATE" : "UNLOCKED";
            s.access.loginAllowed=fic::ipc::computedLoginAllowed(s.access);
            if (stage=="STALE") s.bootId="11111111-1111-4111-8111-111111111111";
            if (stage=="FAILED") s.diagnostic="Startup policy apply completed with errors";
            const auto command=request.at("command").get<std::string>();
            response=command=="prelogin_status" ? fic::ipc::serializePreLoginStatus(s) : command=="access_gate_status" ?
                fic::ipc::serializeAccessGateStatus(s.access) : fic::ipc::make_error_response("fixture is read-only");
        } else response=fic::ipc::make_error_response(error);
        const auto text=response.dump(); const auto frame=fic::ipc::wire::responseFrame(text,0,text.size());
        ::send(client,frame.data(),frame.size(),MSG_NOSIGNAL); ::close(client);
    }
    ::close(fd); ::unlink(path); return 0;
}
