#include "PreLoginController.h"
#include "PreLoginObservationLog.h"
#include <sstream>
#include <algorithm>
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
#include <atomic>
#include <tuple>
#include <cerrno>
#include <systemd/sd-bus.h>

using namespace fic::prelogin;
namespace {
void require(bool condition, const std::string& error) { if (!condition) throw std::runtime_error(error); }
std::chrono::steady_clock::time_point testNow{};
const std::string boot = "11111111-1111-4111-8111-111111111111";
struct Provider : StatusProvider { Observation value; int reads = 0; Observation read() override { ++reads; return value; } };
struct Gui : GuiLifecycle { int closes = 0; bool ok = true, ready = true; bool readyForHandoff() const override { return ready; } bool cleanup(std::string& error) override { ++closes; if (!ok) error = "cleanup failed"; return ok; } };
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
    { Provider p; Gui g; Power w; p.value.verified = success(); g.ready = false;
      PreLoginController c(p,g,w,boot,[]{return testNow;}); c.poll(); require(!c.finished(), "auto-handoff before renderer ready");
      g.ready = true; c.poll(); require(c.countdownSeconds()==5, "countdown not started after renderer ready");
      testNow += std::chrono::seconds(5); c.poll(); require(c.finished() && c.exitCode()==0, "renderer readiness didn't release auto handoff"); }

    for (const auto state : {"INITIALIZING", "APPLYING", "READY", "DEGRADED", "STOPPING", "missing", "crashed"}) {
        Provider provider; Gui gui; Power power;
        if (std::string(state) != "missing" && std::string(state) != "crashed") {
            auto s = success(); s.access.state = state; s.applyOk = false;
            s.access.loginAllowed = fic::ipc::computedLoginAllowed(s.access);
            provider.value.verified = s;
        }
        const auto before = provider.value;
        PreLoginController controller(provider, gui, power, boot,[]{return testNow;});
        controller.poll(); require(!controller.finished(), "failed/unavailable startup auto-handoff");
        controller.request(Action::Handoff); controller.request(Action::Handoff); controller.poll();
        require(controller.finished() && controller.exitCode() == 0 && gui.closes == 1 && power.actions.empty(),
                "manual handoff unavailable or repeated");
        require(!before.verified || provider.value.verified->access.severity == before.verified->access.severity,
                "handoff altered severity");
    }
    { Provider p; Gui g; Power w; p.value.systemd = {true, 123, "active", "running", "READY=1"};
      PreLoginController c(p,g,w,boot,[]{return testNow;}); c.poll(); require(!c.finished(), "systemd READY auto-handoff"); }
    { Provider p; Gui g; Power w; p.value.verified = success();
      PreLoginController c(p,g,w,boot,[]{return testNow;}); c.poll(); require(c.countdownSeconds()==5 && !c.finished(), "success skipped countdown");
      testNow += std::chrono::milliseconds(4999); c.poll(); require(c.countdownSeconds()==1 && !c.finished(), "handoff before five seconds");
      testNow += std::chrono::milliseconds(1); c.poll(); require(c.finished() && c.exitCode()==0, "verified success didn't hand off"); }
    { Provider p; Gui g; Power w; p.value.verified = success(); p.value.verified->bootId = "22222222-2222-4222-8222-222222222222";
      PreLoginController c(p,g,w,boot,[]{return testNow;}); c.poll(); require(!c.finished() && !c.observation().verified, "stale boot adopted"); }
    { Provider p; Gui g; Power w; g.ok = false;
      PreLoginController c(p,g,w,boot,[]{return testNow;}); c.request(Action::Handoff); require(c.finished() && c.exitCode()!=0, "cleanup false success"); }
    for (const auto action : {Action::Reboot, Action::PowerOff}) {
        Provider p; Gui g; Power w;
        p.value.systemd={true,123,"failed","failed","failed"};
        PreLoginController c(p,g,w,boot,[]{return testNow;}); c.poll(); c.request(action);
        require(g.closes==1 && w.actions==std::vector<Action>{action}, "power action wasn't cleanup-first and restricted");
    }
    for (const auto mode : {"ACTIVE", "PASSIVE", "OFF"}) {
        for (const auto severity : {"UNLOCKED", "SOFT", "STANDARD", "HARD", "ISOLATE"}) {
            auto s = success(); s.access.mode = mode; s.access.severity = severity;
            s.access.loginAllowed = fic::ipc::computedLoginAllowed(s.access);
            Provider p; Gui g; Power w; p.value.verified = s; PreLoginController c(p,g,w,boot,[]{return testNow;}); c.poll();
            const bool allowed = std::string(mode)!="ACTIVE" || std::string(severity)=="UNLOCKED" || std::string(severity)=="SOFT";
            testNow += std::chrono::seconds(5); c.poll();
            require(c.finished()==allowed, "mode/severity auto contract");
        }
    }
    { Provider p; Gui g; Power w; p.value.verified=success();
      PreLoginController c(p,g,w,boot,[]{return testNow;}); c.poll();
      testNow += std::chrono::seconds(4); p.value.verified.reset(); c.poll();
      require(!c.countdownSeconds() && !c.finished(), "daemon loss retained countdown");
      p.value.verified=success(); c.poll(); require(c.countdownSeconds()==5, "readiness recovery did not restart countdown");
      testNow += std::chrono::seconds(4); p.value.verified->daemonPid++; c.poll();
      require(c.countdownSeconds()==5, "new daemon inherited countdown");
      g.ready=false; c.poll(); require(!c.countdownSeconds(), "renderer loss retained countdown");
      g.ready=true; c.poll(); c.request(Action::Handoff);
      require(c.finished() && c.exitCode()==0, "manual handoff waits for countdown"); }
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
// Private peer, not a system bus mock: the observer executes real sd-bus
// GetUnit/Properties.Get calls, including D-Bus error-to-errno translation.
class SystemdPeer {
public:
    sd_bus* server=nullptr;sd_bus* client=nullptr;
    std::atomic<int> failure{-1}; // GetUnit, ActiveState, SubState, StatusText, MainPID, invalid reply
    std::atomic<unsigned int> pid{static_cast<unsigned int>(::getpid())};
    std::atomic<bool> stop{false};std::thread worker;
    const std::string errorText="injected peer failure "+std::string(489,'x')+"Ж"+std::string(5000,'x');
    static int dispatch(sd_bus_message* message,void* data,sd_bus_error*) {
        auto& self=*static_cast<SystemdPeer*>(data);
        const int fault=self.failure.load();
        if(sd_bus_message_is_method_call(message,"org.freedesktop.systemd1.Manager","GetUnit")) {
            const char* unit=nullptr;
            if(sd_bus_message_read(message,"s",&unit)<0||!unit||std::string(unit)!="fic.service")return -EINVAL;
            if(fault==0)return sd_bus_reply_method_errorf(message,SD_BUS_ERROR_ACCESS_DENIED,"%s",self.errorText.c_str());
            if(fault==5)return sd_bus_reply_method_return(message,"s","wrong object-path type");
            return sd_bus_reply_method_return(message,"o","/org/freedesktop/systemd1/unit/fic_2eservice");
        }
        if(!sd_bus_message_is_method_call(message,"org.freedesktop.DBus.Properties","Get"))return 0;
        const char *interface=nullptr,*property=nullptr;
        if(sd_bus_message_read(message,"ss",&interface,&property)<0||!property)return -EINVAL;
        const std::string name=property;
        const int index=name=="ActiveState"?1:name=="SubState"?2:name=="StatusText"?3:name=="MainPID"?4:-2;
        if(fault==index)return sd_bus_reply_method_errorf(message,
            index==4?SD_BUS_ERROR_TIMEOUT:SD_BUS_ERROR_ACCESS_DENIED,"%s",self.errorText.c_str());
        if(name=="MainPID")return sd_bus_reply_method_return(message,"v","u",self.pid.load());
        const char* value=name=="ActiveState"?"activating":name=="SubState"?"start":
            name=="StatusText"?"Applying startup policies":nullptr;
        if(!value)return -EINVAL;
        return sd_bus_reply_method_return(message,"v","s",value);
    }
    SystemdPeer() {
        int channel[2];require(::socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,channel)==0,"private D-Bus socketpair");
        require(sd_bus_new(&server)>=0&&sd_bus_new(&client)>=0,"private D-Bus allocation");
        sd_id128_t id;require(sd_id128_randomize(&id)>=0,"private D-Bus id");
        require(sd_bus_set_fd(server,channel[0],channel[0])>=0&&sd_bus_set_server(server,1,id)>=0&&
            sd_bus_set_fd(client,channel[1],channel[1])>=0,"private D-Bus setup");
        require(sd_bus_add_object(server,nullptr,"/org/freedesktop/systemd1",dispatch,this)>=0&&
            sd_bus_add_object(server,nullptr,"/org/freedesktop/systemd1/unit/fic_2eservice",dispatch,this)>=0,
            "private systemd objects");
        require(sd_bus_start(server)>=0&&sd_bus_start(client)>=0,"private D-Bus start");
        worker=std::thread([this]{
            while(!stop.load()) {
                int result;do{result=sd_bus_process(server,nullptr);}while(result>0);
                if(result<0)break;
                sd_bus_wait(server,10000);
            }
        });
    }
    ~SystemdPeer(){stop=true;worker.join();sd_bus_flush_close_unref(client);sd_bus_flush_close_unref(server);}
    PreLoginSystemdIntegration::OpenBus open(){return [this](sd_bus** out){*out=sd_bus_ref(client);return 0;};}
};
void observationFailures() {
    PreLoginSystemdIntegration unavailable([](sd_bus**){return -ECONNREFUSED;});
    auto failed=unavailable.observe();
    require(!failed.available&&failed.error.find("operation=sd_bus_open_system")!=std::string::npos&&
        failed.error.find("code="+std::to_string(-ECONNREFUSED))!=std::string::npos,"system bus open error lost");
    SystemdPeer peer;PreLoginSystemdIntegration observer(peer.open());
    auto good=observer.observe();
    require(good.available&&good.pid==static_cast<unsigned int>(getpid())&&good.active=="activating"&&
        good.text=="Applying startup policies"&&good.error.empty(),"private systemd observation failed: "+good.error);
    std::uint64_t timeout=0;require(sd_bus_get_method_call_timeout(peer.client,&timeout)>=0&&timeout==250000,
        "D-Bus timeout changed");
    for(int fault=0;fault<6;++fault){
        peer.failure=fault;failed=observer.observe();
        require(!failed.available&&failed.pid==0&&failed.active.empty()&&failed.text.empty(),"partial/stale systemd observation published");
        const std::string property=fault==1?"ActiveState":fault==2?"SubState":fault==3?"StatusText":"MainPID";
        require(failed.error.find(fault==5?"operation=GetUnit.read":fault==0?"operation=GetUnit":"operation=get_property")!=std::string::npos,
            "D-Bus operation diagnostic lost");
        if(fault>0&&fault<5)require(failed.error.find("property="+property)!=std::string::npos,"D-Bus property diagnostic lost");
        require(failed.error.find("code=-")!=std::string::npos&&failed.error.size()<=1024,"D-Bus code/bound lost");
        require(!nlohmann::json{{"detail",failed.error}}.dump().empty(),"bounded diagnostic is not UTF-8 JSON");
        if(fault<5)require(failed.error.find("injected peer failure")!=std::string::npos,"sd_bus_error text lost");
        if(fault==4)require(failed.error.find("code="+std::to_string(-ETIMEDOUT))!=std::string::npos,"MainPID timeout code lost");
        peer.failure=-1;require(observer.observe().available,"next D-Bus poll did not recover");
    }
    Socket socket;
    PreLoginStatusProvider missing(socket.path+"-missing",::geteuid(),peer.open());
    Gui gui;Power power;PreLoginController c(missing,gui,power,boot,[]{return testNow;});
    c.poll();require(c.state()==UiState::Applying&&!c.countdownSeconds()&&!c.observation().verified,"startup fallback state");
    peer.failure=4;c.poll();
    require(c.state()==UiState::Unavailable&&!c.observation().verified&&!c.countdownSeconds()&&
        c.observation().error.find("property=MainPID")!=std::string::npos&&
        c.observation().error.find("code="+std::to_string(-ETIMEDOUT))!=std::string::npos&&
        c.observation().error.find("IPC:")!=std::string::npos&&c.observation().error.size()<=4096,
        "fallback D-Bus error lost behind expected absent IPC");
    peer.failure=-1;c.poll();require(c.state()==UiState::Applying&&!c.countdownSeconds()&&
        c.observation().error.find("D-Bus")==std::string::npos,"fallback observation did not recover");
    PreLoginStatusProvider provider(socket.path,::geteuid(),peer.open());
    {auto server=socket.answer(fic::ipc::serializePreLoginStatus(success()).dump());auto value=provider.read();server.join();
     require(value.verified.has_value(),"verified peer identity rejected");}
    peer.pid=::getpid()+1;
    {auto server=socket.answer(fic::ipc::serializePreLoginStatus(success()).dump());auto value=provider.read();server.join();
     require(!value.verified&&value.error.find("peer identity")!=std::string::npos,"systemd/IPC PID mismatch accepted");}
    std::cout<<"D-Bus per-operation/property/errno/bounds/Observation/IPC failure/recovery PASS\n";
}
void observationLogging() {
    struct Channel : std::stringbuf {
        int records=0;
        int sync() override { ++records; return std::stringbuf::sync(); }
    } channel;
    std::ostream output(&channel);
    PreLoginObservationLog log(output);
    SystemdStatus status;
    const std::string a="systemd D-Bus operation=get_property property=MainPID code=-110: timed out";
    const std::string b="systemd D-Bus operation=GetUnit code=-13: Access denied";
    status.error=a;
    log.record(status);log.record(status);log.record(status);
    require(channel.records==1,"identical errors wrote duplicate journal records");
    require(channel.str()=="fic-prelogin broker: "+a+"\n","journal channel lost diagnostic");
    status.error=b;log.record(status);log.record(status);
    require(channel.records==2,"changed cause not recorded exactly once");
    status={true,123,"activating","start","Starting daemon"};log.record(status);
    require(channel.records==2,"successful observation logged an error");
    status={};status.error=a;log.record(status);
    require(channel.records==3,"same error after recovery suppressed");
    const auto records=channel.str();
    require(std::count(records.begin(),records.end(),'\n')==3&&
        records=="fic-prelogin broker: "+a+"\nfic-prelogin broker: "+b+"\nfic-prelogin broker: "+a+"\n",
        "unexpected journal channel contents");
    // Real provider, missing IPC socket, healthy private sd-bus: no D-Bus log.
    SystemdPeer peer; Socket socket;
    PreLoginStatusProvider provider(socket.path+"-missing",::geteuid(),peer.open());
    const auto observed=provider.read();
    require(!observed.verified&&observed.systemd.available&&observed.systemd.error.empty()&&
        !observed.error.empty(),"missing IPC fixture did not exercise healthy fallback");
    Provider progress;Gui view;Power power;progress.value=observed;
    PreLoginController controller(progress,view,power,boot);controller.poll();
    require(controller.state()==UiState::Applying&&!controller.countdownSeconds(),"missing IPC failed normal progress");
    log.record(observed.systemd);
    require(channel.records==3,"missing administrative IPC logged as D-Bus failure");
    peer.failure=4;const auto failed=provider.read();log.record(failed.systemd);log.record(failed.systemd);
    require(channel.records==4&&channel.str().find(failed.systemd.error)!=std::string::npos,
        "actual sd-bus diagnostic not registered exactly once");
    peer.failure=-1;const auto recovered=provider.read();log.record(recovered.systemd);
    require(recovered.systemd.error.empty()&&recovered.error.find("systemd D-Bus")==std::string::npos,
        "recovery retained old D-Bus error");
    log.record(failed.systemd);require(channel.records==5,"actual D-Bus recovery did not reset suppression");
    std::cout<<"Broker journal channel duplicate/change/recovery/missing IPC PASS\n";
}
void observationStates() {
    Provider p;Gui g;Power w;PreLoginController c(p,g,w,boot,[]{return testNow;});
    p.value.systemd={true,123,"activating","start","Applying startup policies"};
    c.poll();require(c.state()==UiState::Applying&&!c.countdownSeconds(),"unverified applying state");
    p.value={};p.value.systemd.active="failed";p.value.systemd.error="systemd D-Bus operation=get_property property=MainPID code=-110";p.value.error=p.value.systemd.error;
    c.poll();require(c.state()==UiState::Unavailable&&!c.finished()&&!c.countdownSeconds(),"unavailable became startup failure/success");
    p.value.systemd={true,123,"activating","start","Applying startup policies"};
    c.poll();require(c.state()==UiState::Applying,"applying not restored");
    p.value.verified=success();c.poll();require(c.state()==UiState::Succeeded&&c.countdownSeconds()==5,"verified success not restored");
    testNow+=std::chrono::seconds(4);p.value={};c.poll();
    require(c.state()==UiState::Unavailable&&!c.countdownSeconds()&&!c.finished()&&g.closes==0,"unavailable retained countdown");
    testNow+=std::chrono::seconds(10);c.poll();require(!c.finished(),"handoff during observation outage");
    p.value.verified=success();c.poll();require(c.countdownSeconds()==5,"restored status inherited countdown");
    testNow+=std::chrono::seconds(4);c.poll();require(!c.finished()&&c.countdownSeconds()==1,"handoff too early after recovery");
    testNow+=std::chrono::seconds(1);c.poll();require(c.finished()&&g.closes==1,"handoff not allowed after renewed confirmation");
    for(const auto& [active,text,state]:std::vector<std::tuple<std::string,std::string,UiState>>{
        {"inactive","",UiState::Waiting},{"activating","Starting daemon",UiState::Starting},
        {"activating","Applying startup policies",UiState::Applying},
        {"active","READY=1",UiState::Unavailable},{"failed","Failed",UiState::ServiceFailed}}){
        Provider source;Gui view;Power power;source.value.systemd={true,123,active,"sub",text};
        PreLoginController controller(source,view,power,boot,[]{return testNow;});controller.poll();
        require(controller.state()==state&&!controller.countdownSeconds()&&!controller.finished(),"systemd-only state/handoff changed");
    }
    {
        Provider source; Gui view; Power power;
        source.value.systemd={true,123,"failed","failed","Service failed"};
        PreLoginController controller(source,view,power,boot,[]{return testNow;});
        controller.poll();
        require(std::string(uiStateToken(controller.state()))=="DAEMON_SERVICE_FAILED" &&
            controller.state()!=UiState::Failed,"confirmed systemd failure classified as unavailable/apply failure");
        testNow+=std::chrono::seconds(10);controller.poll();
        require(!controller.finished()&&!controller.countdownSeconds(),"systemd failure allowed auto handoff");
        source.value.verified=success();controller.poll();
        require(controller.state()==UiState::Succeeded&&controller.countdownSeconds()==5,"systemd displaced verified IPC");
        source.value.verified.reset();controller.poll();
        require(!controller.countdownSeconds(),"systemd failure retained countdown");
        controller.request(Action::Handoff);
        require(controller.finished()&&controller.exitCode()==0&&view.closes==1,"service failure blocked manual handoff");
    }
    p.value={};p.value.systemd={true,123,"failed","failed","failed"};p.value.verified=success();p.value.verified->applyOk=false;p.value.verified->diagnostic="confirmed apply failure";
    PreLoginController failed(p,g,w,boot,[]{return testNow;});failed.poll();
    require(failed.state()==UiState::Failed&&failed.observation().verified->diagnostic=="confirmed apply failure"&&
        !failed.countdownSeconds(),"real startup failure hidden");
    p.value.verified->access.state="DEGRADED";
    PreLoginController degraded(p,g,w,boot);degraded.poll();require(degraded.state()==UiState::Degraded,"degraded collapsed into unavailability");
    std::cout<<"Applying/unavailable/recovery/success/systemd states/countdown/failure distinction PASS\n";
}
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
    try { lifecycle(); observationStates(); observationLogging(); transport(); observationFailures(); return 0; }
    catch (const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
