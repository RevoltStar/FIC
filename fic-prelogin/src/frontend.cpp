#include "QtPreLoginView.h"
#include "PreLoginGraphicsPaths.h"
#include <QApplication>
#include <QCoreApplication>
#include <QSocketNotifier>
#include <QTimer>
#include <QEventLoop>
#include <filesystem>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#include <systemd/sd-device.h>
#include <cerrno>
#include <sys/mman.h>
#include <fcntl.h>
#include <regex>
#include <iostream>
namespace {
bool trusted(const std::filesystem::path& path, bool directory) {
    std::error_code error;
    const auto canonical=std::filesystem::canonical(path,error); if(error) return false;
    for(auto item=canonical; !item.empty();item=item.parent_path()) {
        struct stat s{};
        if(::lstat(item.c_str(),&s)!=0 || s.st_uid!=0 || (s.st_mode&0022) ||
            (item==canonical && !directory ? !S_ISREG(s.st_mode) : !S_ISDIR(s.st_mode))) return false;
        if(item==item.root_path()) break;
    }
    return true;
}
}
// Select only a primary DRM node on seat0. Keep the QPA device choice in an
// immutable anonymous descriptor, never a user-selected config path.
int seatConfiguration() {
    sd_device_enumerator* devices=nullptr;
    if(sd_device_enumerator_new(&devices)<0)return -1;
    std::string card;
    if(sd_device_enumerator_add_match_subsystem(devices,"drm",true)>=0) {
        for(auto* device=sd_device_enumerator_get_device_first(devices);device;
            device=sd_device_enumerator_get_device_next(devices)) {
            if(sd_device_get_is_initialized(device)<=0) continue;
            const char* node=nullptr;const char* seat=nullptr;
            const int seatResult=sd_device_get_property_value(device,"ID_SEAT",&seat);
            const bool seat0=seatResult==-ENOENT || (seatResult>=0 && std::string(seat)=="seat0");
            if(sd_device_get_devname(device,&node)>=0 && std::regex_match(node,std::regex("/dev/dri/card[0-9]+")) && seat0) {
                if(card.empty())card=node;
                sd_device* pci=nullptr;const char* boot=nullptr;
                if(sd_device_get_parent_with_subsystem_devtype(device,"pci",nullptr,&pci)>=0 &&
                    sd_device_get_sysattr_value(pci,"boot_vga",&boot)>=0 && std::string(boot)=="1") {
                    card=node;break;
                }
            }
        }
    }
    sd_device_enumerator_unref(devices);
    if(card.empty())return -1;
    int fd=memfd_create("fic-prelogin-kms",MFD_CLOEXEC|MFD_ALLOW_SEALING);if(fd<0)return -1;
    const auto json=nlohmann::json{{"device",card},{"hwcursor",false}}.dump();
    if(::write(fd,json.data(),json.size())!=static_cast<ssize_t>(json.size()) ||
        ::fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)<0) {::close(fd);return -1;}
    ::lseek(fd,0,SEEK_SET);
    const auto path="/proc/self/fd/"+std::to_string(fd);
    ::setenv("QT_QPA_EGLFS_KMS_CONFIG",path.c_str(),1);
    std::cerr<<"fic-prelogin seat0 drm-device="<<card<<"\n";
    return fd;
}
int main(int argc,char** argv) {
    using namespace fic::prelogin;
    if(argc!=1 || ::geteuid()==0) return 2;
    int type=0; socklen_t length=sizeof(type); ucred peer{}; socklen_t size=sizeof(peer);
    if(::getsockopt(3,SOL_SOCKET,SO_TYPE,&type,&length)!=0 || type!=SOCK_SEQPACKET ||
        ::getsockopt(3,SOL_SOCKET,SO_PEERCRED,&peer,&size)!=0 || size!=sizeof(peer) ||
        peer.uid!=0 || peer.pid!=::getppid()) return 2;
    // No caller-selected QPA, plugins, dynamic loader, Mesa or input settings.
    ::clearenv(); ::setenv("LANG","C.UTF-8",1); ::setenv("HOME","/nonexistent",1);
    ::setenv("QT_QPA_PLATFORM","eglfs",1); ::setenv("QT_QPA_EGLFS_INTEGRATION","eglfs_kms",1);
    ::setenv("QT_QPA_EGLFS_ALWAYS_SET_MODE","1",1);
    ::setenv("QT_STYLE_OVERRIDE","Fusion",1); // Avoid desktop style plugins and their helpers.
    // Limit plugin search before QPA initialization; the executable directory is also package-owned.
    if(!trusted(graphicsPaths::PLUGINS,true) ||
        !trusted(std::filesystem::path(graphicsPaths::PLUGINS)/"platforms/libqeglfs.so",false) ||
        !trusted(std::filesystem::path(graphicsPaths::PLUGINS)/"egldeviceintegrations/libqeglfs-kms-integration.so",false)) {
        std::cerr<<"Package-owned system Qt EGLFS/KMS plugins are missing/untrusted\n"; return 1;
    }
    const int kms=seatConfiguration();
    if(kms<0) {std::cerr<<"No proven seat0 DRM node; use console recovery\n";return 1;}
    QCoreApplication::setLibraryPaths({QString::fromUtf8(graphicsPaths::PLUGINS)});
    int result=1;
    {
        QApplication app(argc,argv);
        QCoreApplication::setLibraryPaths({QString::fromUtf8(graphicsPaths::PLUGINS)});
        if(QApplication::platformName()!=QStringLiteral("eglfs")) return 1;
        QtPreLoginView view([&](char action){
            if(::send(3,&action,1,MSG_NOSIGNAL)!=1) app.exit(1);
        });
        QSocketNotifier channel(3,QSocketNotifier::Read);
        std::string lastState;
        QObject::connect(&channel,&QSocketNotifier::activated,&app,[&]{
            char packet[16384]; const auto bytes=::recv(3,packet,sizeof(packet),MSG_DONTWAIT|MSG_TRUNC);
            if(bytes<0 && (errno==EAGAIN || errno==EINTR)) return;
            if(bytes==1 && packet[0]=='Q') {channel.setEnabled(false); view.hide(); app.exit(0);return;}
            if(bytes<=0 || bytes>static_cast<ssize_t>(sizeof(packet))) {app.exit(1);return;}
            const auto value=nlohmann::json::parse(packet,packet+bytes,nullptr,false);
            if(value.is_discarded() || !view.display(value)) {app.exit(1);return;}
            const auto state=value.at("state").get<std::string>();
            if(state!=lastState) {std::cerr<<"fic-prelogin view-state="<<state<<"\n";lastState=state;}
        });
        view.showFullScreen();
        // EGLFS Widgets enqueue their initial compositor work. Drain those
        // events before announcing readiness: quitting before the first flush
        // can strand an initial KMS page flip. Exclude socket notifiers from
        // this dispatcher pass; QPA initialization may run nested dispatch.
        QEventLoop initialFrame;
        initialFrame.processEvents(QEventLoop::ExcludeSocketNotifiers);
        const char ready='V';
        if(::send(3,&ready,1,MSG_NOSIGNAL)!=1) return 1;
        std::cerr<<"fic-prelogin frontend: uid="<<::geteuid()<<" qpa=eglfs integration=eglfs_kms\n";
        result=app.exec();
    } // Widgets, input handlers, QApplication and QPA/GBM/EGL are destroyed.
    ::close(kms);
    ::close(3);
    return result; // Broker additionally waits for process death before handoff.
}
