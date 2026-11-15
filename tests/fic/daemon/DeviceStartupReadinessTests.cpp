#include "daemon/DeviceStartupReadiness.h"
#include "FicIpcWire.h"
#include <fic/ipc/FicIpcClient.h>
#include <fic/ipc/FicReadinessStatus.h>
#include <fic/version/ProductVersion.h>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <sys/stat.h>
using namespace std::chrono_literals;
using namespace fic::daemon;
using J = nlohmann::json;
void require(bool value,const char* reason) { if(!value) throw std::runtime_error(reason); }
J status() { return {{"api_version",fic::ipc::API_VERSION},{"ok",true},{"message","ready"},
    {"product_version",fic::version::PRODUCT_VERSION},{"database_schema_version",fic::version::DEVICE_DB_SCHEMA_VERSION}}; }
struct Server {
    std::filesystem::path dir;std::string path,previous;bool hadPrevious=false;pid_t pid;
    Server(std::string reply,bool silent=false,bool untrusted=false,int delay=0) {
        char name[]="/tmp/fic-device-startup-XXXXXX";dir=::mkdtemp(name);::chmod(dir.c_str(),0777);path=(dir/"socket").string();
        if(auto p=std::getenv("FIC_DEVICE_SOCKET_PATH")){hadPrevious=true;previous=p;}
        ::setenv("FIC_DEVICE_SOCKET_PATH",path.c_str(),1);pid=::fork();require(pid>=0,"fork");
        if(!pid) {
            if(untrusted && (::setgid(65534)||::setuid(65534))) ::_exit(2);
            if(delay) std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            int fd=::socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);sockaddr_un a{};a.sun_family=AF_UNIX;std::strncpy(a.sun_path,path.c_str(),sizeof(a.sun_path)-1);
            if(::bind(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))||::listen(fd,16))::_exit(3);::chmod(path.c_str(),0666);
            for(;;) {int c=::accept(fd,nullptr,nullptr);if(c<0)::_exit(4);char data[65536];if(::recv(c,data,sizeof data,0)>0) {
                if(silent)std::this_thread::sleep_for(10s);
                else {auto frame=fic::ipc::wire::responseFrame(reply,0,reply.size());::send(c,frame.data(),frame.size(),MSG_NOSIGNAL);}
            }::close(c);}
        }
    }
    ~Server(){::kill(pid,SIGTERM);int result;::waitpid(pid,&result,0);std::filesystem::remove_all(dir);
        if(hadPrevious)::setenv("FIC_DEVICE_SOCKET_PATH",previous.c_str(),1);else::unsetenv("FIC_DEVICE_SOCKET_PATH");}
};
volatile std::sig_atomic_t stopped=0;
void stop(int){stopped=1;}
int main(int argc,char** argv) {
    if(argc==2 && std::string(argv[1])=="--prelogin-status") {
        fic::ipc::PreLoginStatus value;std::string error;
        try {
            J reply;std::cin>>reply;
            require(fic::ipc::parsePreLoginStatus(reply,value,error),"invalid actual prelogin status");
            std::cout<<J{{"may_auto_handoff",fic::ipc::mayAutoHandoff(value,value.bootId)}}<<'\n';return 0;
        }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
    }
    if(::geteuid()!=0){std::cout<<"root peer fixtures required\n";return 77;}
    try {
        auto noStop=[] {return false;};
        {Server s(status().dump());require(waitForDeviceStartup(noStop,800ms).ready(),"compatible status refused");}
        {Server s(status().dump(),false,false,180);auto r=waitForDeviceStartup(noStop,1s);require(r.ready()&&r.elapsed>=150ms,"delayed socket not awaited");}
        for(int kind=0;kind<9;++kind) {auto j=status();
            if(kind==0)j["product_version"]="wrong";
            if(kind==1)j["database_schema_version"]=999;
            if(kind==2)j["ok"]=false;
            if(kind==3)j["ok"]="true";
            if(kind==4)j.erase("message");
            if(kind==5)j["database_schema_version"]="2";
            if(kind==6)j["api_version"]=999;
            if(kind==7)j=J::array();
            Server s(kind==8?"SECRET_NOT_JSON":j.dump());auto r=waitForDeviceStartup(noStop,180ms);
            require(r.state==DeviceStartupState::TimedOut,"malformed/incompatible status admitted");
            require(r.diagnostic.find("SECRET")==std::string::npos,"untrusted value leaked to audit diagnostic");
        }
        {Server s(status().dump(),false,true);require(!waitForDeviceStartup(noStop,180ms).ready(),"non-root peer admitted");}
        {Server s(status().dump(),true);auto r=waitForDeviceStartup(noStop,180ms);require(!r.ready()&&r.elapsed<500ms,"unresponsive listener exceeded deadline");}
        {Server s(status().dump(),false,false,10000);require(!waitForDeviceStartup(noStop,100ms).ready(),"missing socket admitted");}
        {Server s(status().dump(),true);auto old=std::signal(SIGTERM,stop);stopped=0;
            std::thread signal([]{std::this_thread::sleep_for(120ms);::kill(::getpid(),SIGTERM);});
            auto r=waitForDeviceStartup([]{return stopped!=0;},3s);signal.join();std::signal(SIGTERM,old);
            require(r.state==DeviceStartupState::Stopped&&r.elapsed<1500ms,"SIGTERM not bounded/classified");}
        std::cout<<"startup device IPC success/delay/schema/API/peer/deadline/SIGTERM PASS\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
