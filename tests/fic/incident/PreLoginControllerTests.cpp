#include "PreLoginController.h"
#include "PreLoginStatusProvider.h"
#include <fic/ipc/FicIpcClient.h>
#include <fic/core/runtime/SystemBootInfo.h>
#include "FicIpcWire.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <thread>
#include <filesystem>
#include <iostream>

using namespace fic::prelogin;
namespace {
void require(bool condition, const std::string& error) { if (!condition) throw std::runtime_error(error); }
const std::string boot = "11111111-1111-4111-8111-111111111111";
struct Provider : StatusProvider { Observation value; int reads = 0; Observation read() override { ++reads; return value; } };
struct Gui : GuiLifecycle { int closes = 0; bool ok = true; bool cleanup(std::string& error) override { ++closes; if (!ok) error = "cleanup failed"; return ok; } };
struct Power : PowerController { std::vector<Action> actions; bool execute(Action a, std::string&) override { actions.push_back(a); return true; } };
fic::ipc::PreLoginStatus success() {
    fic::ipc::PreLoginStatus s;
    s.bootId = boot; s.daemonPid = ::getpid();
    s.started = s.completed = s.applyOk = s.lifecycleCompleted = true;
    s.access.state = "READY"; s.access.modeProven = s.access.stateProven = true;
    s.access.severity = "UNLOCKED"; s.access.provenance = "PROVEN"; s.access.loginAllowed = true;
    return s;
}
void lifecycle() {
    for (const auto state : {"INITIALIZING", "APPLYING", "READY", "DEGRADED", "STOPPING", "missing", "crashed"}) {
        Provider provider; Gui gui; Power power;
        if (std::string(state) != "missing" && std::string(state) != "crashed") {
            auto s = success(); s.access.state = state; s.applyOk = false;
            s.access.loginAllowed = fic::ipc::computedLoginAllowed(s.access);
            provider.value.verified = s;
        }
        const auto before = provider.value;
        PreLoginController controller(provider, gui, power, boot);
        controller.poll(); require(!controller.finished(), "failed/unavailable startup auto-handoff");
        controller.request(Action::Handoff); controller.request(Action::Handoff); controller.poll();
        require(controller.finished() && controller.exitCode() == 0 && gui.closes == 1 && power.actions.empty(),
                "manual handoff unavailable or repeated");
        require(!before.verified || provider.value.verified->access.severity == before.verified->access.severity,
                "handoff altered severity");
    }
    { Provider p; Gui g; Power w; p.value.systemd = {true, 123, "active", "running", "READY=1"};
      PreLoginController c(p,g,w,boot); c.poll(); require(!c.finished(), "systemd READY auto-handoff"); }
    { Provider p; Gui g; Power w; p.value.verified = success();
      PreLoginController c(p,g,w,boot); c.poll(); require(c.finished() && c.exitCode()==0, "verified success didn't hand off"); }
    { Provider p; Gui g; Power w; p.value.verified = success(); p.value.verified->bootId = "22222222-2222-4222-8222-222222222222";
      PreLoginController c(p,g,w,boot); c.poll(); require(!c.finished() && !c.observation().verified, "stale boot adopted"); }
    { Provider p; Gui g; Power w; g.ok = false;
      PreLoginController c(p,g,w,boot); c.request(Action::Handoff); require(c.finished() && c.exitCode()!=0, "cleanup false success"); }
    for (const auto action : {Action::Reboot, Action::PowerOff}) {
        Provider p; Gui g; Power w; PreLoginController c(p,g,w,boot); c.request(action);
        require(g.closes==1 && w.actions==std::vector<Action>{action}, "power action wasn't cleanup-first and restricted");
    }
    for (const auto mode : {"ACTIVE", "PASSIVE", "OFF"}) {
        for (const auto severity : {"UNLOCKED", "SOFT", "STANDARD", "HARD", "ISOLATE"}) {
            auto s = success(); s.access.mode = mode; s.access.severity = severity;
            s.access.loginAllowed = fic::ipc::computedLoginAllowed(s.access);
            Provider p; Gui g; Power w; p.value.verified = s; PreLoginController c(p,g,w,boot); c.poll();
            const bool allowed = std::string(mode)!="ACTIVE" || std::string(severity)=="UNLOCKED" || std::string(severity)=="SOFT";
            require(c.finished()==allowed, "mode/severity auto contract");
        }
    }
    std::cout << "L1-L8 L12-L22 lifecycle/manual/auto/cleanup/power PASS\n";
}
class Socket {
public:
    std::filesystem::path root; std::string path; int fd;
    Socket() {
        char pattern[]="/tmp/fic-prelogin-ipc-XXXXXX"; root=::mkdtemp(pattern); path=(root/"socket").string();
        fd=::socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0); sockaddr_un a{}; a.sun_family=AF_UNIX;
        std::strncpy(a.sun_path,path.c_str(),sizeof(a.sun_path)-1);
        require(::bind(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0 && ::listen(fd,1)==0,"fixture socket");
    }
    ~Socket() {::close(fd); std::filesystem::remove_all(root);}
    std::thread answer(std::string data, bool hold=false) {
        return std::thread([=] {
            int client=::accept(fd,nullptr,nullptr); char request[1024]; ::recv(client,request,sizeof(request),0);
            if (hold) std::this_thread::sleep_for(std::chrono::milliseconds(350));
            if (!data.empty()) {
                auto frame=fic::ipc::wire::responseFrame(data,0,data.size()); ::send(client,frame.data(),frame.size(),MSG_NOSIGNAL);
            }
            ::close(client);
        });
    }
};
void transport() {
    auto s=success(); Socket fixture;
    PreLoginStatusProvider provider(fixture.path,::geteuid());
    { auto server=fixture.answer(fic::ipc::serializePreLoginStatus(s).dump());
      auto value=provider.read(); server.join(); require(value.verified.has_value(), "production serializer/real IPC rejected: "+value.error); }
    for (const auto kind : {"version","extra","missing","inconsistent","wrong-pid","wrong-type","large-diagnostic"}) {
        auto value=fic::ipc::serializePreLoginStatus(s);
        if (std::string(kind)=="version") value["api_version"]=fic::ipc::API_VERSION+1;
        if (std::string(kind)=="extra") value["extra"]=true;
        if (std::string(kind)=="missing") value.erase("startup_apply_completed");
        if (std::string(kind)=="inconsistent") value["startup_apply_started"]=false;
        if (std::string(kind)=="wrong-pid") value["daemon_pid"]=::getpid()+1;
        if (std::string(kind)=="wrong-type") value["startup_apply_ok"]=1;
        if (std::string(kind)=="large-diagnostic") value["diagnostic"]=std::string(4097,'x');
        auto server=fixture.answer(value.dump()); auto reply=provider.read(); server.join(); require(!reply.verified,"accepted "+std::string(kind));
    }
    for (const auto text : {"{", "{\"ok\":true,\"ok\":false}"}) {
        auto server=fixture.answer(text); auto reply=provider.read(); server.join(); require(!reply.verified,"malformed/duplicate JSON accepted");
    }
    { auto server=fixture.answer("",true); auto reply=provider.read(); server.join(); require(!reply.verified,"timeout accepted"); }
    { auto server=fixture.answer(""); auto reply=provider.read(); server.join(); require(!reply.verified,"closed/restarted connection accepted"); }
    { PreLoginStatusProvider wrong(fixture.path,::geteuid()+1); auto server=fixture.answer("");
      auto reply=wrong.read(); server.join(); require(!reply.verified,"wrong UID accepted"); }
    { PreLoginStatusProvider missing(fixture.path+"-missing",::geteuid()); require(!missing.read().verified,"missing daemon accepted"); }
    ::setenv("FIC_SOCKET_PATH",fixture.path.c_str(),1);
    // No fixture accept thread: a production query must not follow the env.
    require(!PreLoginStatusProvider().read().verified, "environment endpoint override");
    ::unsetenv("FIC_SOCKET_PATH");
    std::cout << "L9-L11 producer/consumer real transport/credentials/timeout/schema PASS\n";
}
}
int main() {
    try { lifecycle(); transport(); return 0; }
    catch (const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
