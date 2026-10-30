#include "service/sssd/SssdServiceAdmission.h"
#include "platform/PlatformProfile.h"
#include "platform/PlatformCompatibility.h"
#include <nlohmann/json.hpp>
#include <fcntl.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cerrno>
namespace fic::service::sssd {
namespace {
using J=nlohmann::json;
namespace d=fic::service::detail;
[[noreturn]] void unsupported(const std::string& s) {throw d::Failure(ActivationStatus::UnsupportedConfiguration,"SSSD: "+s);}
J value(const d::LaunchContract& c,const std::string& key,const std::string& sig) {
    try {const auto j=J::parse(c.at("launch."+key));
        if(j.at("signature")!=sig)unsupported("property type: "+key);
        const auto v=j.at("value");
        if((sig=="s"||sig=="o")&&!v.is_string())unsupported("string property: "+key);
        if(sig=="b"&&!v.is_boolean())unsupported("boolean property: "+key);
        if(sig=="u"&&(!v.is_number_unsigned()||v.get<std::uint64_t>()>UINT32_MAX))unsupported("uint property: "+key);
        if(sig.rfind("a",0)==0&&!v.is_array())unsupported("array property: "+key);
        return v;
    } catch(const J::exception&) {unsupported("malformed property: "+key);} catch(const std::out_of_range&) {unsupported("missing property: "+key);}
}
void equal(const d::LaunchContract& c,const std::string& k,const std::string& sig,const J& expected) {
    if(value(c,k,sig)!=expected)unsupported("unsupported launch field: "+k);
}
J commands(const std::vector<std::vector<std::string>>& argv,bool pre) {
    J out=J::array();for(const auto& a:argv)out.push_back(J::array({a.at(0),a,pre?J::array({"ignore-failure","privileged"}):J::array()}));return out;
}
// Loaded DropInPaths and NeedDaemonReload alone miss a newly created override
// on some systemd versions. Recheck the full native lookup negative set without
// loading units or enumerating unrelated service trees.
std::string unitLookup(const d::LaunchContract& c,const LaunchProfile& profile) {
    const auto paths=value(c,"UnitPath","as");if(paths.empty()||paths.size()>32)unsupported("unit lookup unavailable");
    const std::set<std::string> allowed{
        "/etc/systemd/system.control","/run/systemd/system.control","/run/systemd/transient",
        "/run/systemd/generator.early","/etc/systemd/system","/etc/systemd/system.attached",
        "/run/systemd/system","/run/systemd/system.attached","/run/systemd/generator",
        "/usr/local/lib/systemd/system","/usr/lib/systemd/system","/lib/systemd/system","/run/systemd/generator.late"};
    J observed=J::array();
    for(const auto& entry:paths) {
        if(!entry.is_string()||!allowed.count(entry.get<std::string>()))unsupported("unknown systemd unit lookup path");
        const auto base=entry.get<std::string>();
        for(const auto& leaf:{"sssd.service","sssd.service.d","service.d"}) {
            auto path=base+"/"+leaf;
            if(path==profile.fragment)continue;
            if((path=="/usr/lib/systemd/system/sssd.service"&&profile.fragment=="/lib/systemd/system/sssd.service")||
               (path=="/lib/systemd/system/sssd.service"&&profile.fragment=="/usr/lib/systemd/system/sssd.service")) {
                // A second vendor lookup entry is equivalent only with a proven
                // usr-merge alias, never merely because both names look native.
                auto root=d::openAbsolute("/",O_PATH|O_DIRECTORY);std::uint64_t budget=1024*1024;
                const auto alias=J::parse(d::fingerprintUnitSource(root.get(),path,budget));
                const auto original=J::parse(c.at("launch.file:"+profile.fragment));
                if(alias.at("canonical")!=original.at("canonical")||alias.at("file")!=original.at("file"))unsupported("distinct competing vendor unit source");
                observed.push_back(J::array({path,alias,"same-vendor-object"}));continue;
            }
            auto fd=d::openAbsolute("/",O_PATH|O_DIRECTORY);J chain=J::array();
            const auto parts=std::filesystem::path(path).relative_path();bool absent=false;
            for(const auto& component:parts) {
                const auto id=d::identity(fd.get());if(id.uid||(id.mode&0022))unsupported("untrusted unit lookup ancestor");
                chain.push_back(J::array({id.mount,id.device,id.inode,id.mode,id.uid,id.gid}));
                d::Fd next(::openat(fd.get(),component.c_str(),O_PATH|O_NOFOLLOW|O_CLOEXEC));
                if(!next) {if(errno!=ENOENT)unsupported("unit lookup cannot prove absence");absent=true;break;}
                if(S_ISLNK(d::identity(next.get()).mode)) {
                    // /lib is the sole vendor alias; use the same independently
                    // fingerprinted usr-merge contract as the loaded fragment.
                    if(component!="lib"||base!="/lib/systemd/system")unsupported("unit lookup symlink");
                    char target[64];const auto n=::readlinkat(next.get(),"",target,sizeof target);
                    const std::string alias=n>0&&n<ssize_t(sizeof target)?std::string(target,n):"";
                    if(alias!="usr/lib"&&alias!="/usr/lib")unsupported("unit lookup alias target");
                    const auto link=d::identity(next.get());chain.push_back(J::array({link.mount,link.device,link.inode,link.uid,alias}));
                    next=d::openAbsolute("/usr/lib",O_PATH|O_DIRECTORY);
                }
                fd=std::move(next);
            }
            if(!absent) {
                const auto id=d::identity(fd.get());
                if(std::string(leaf)=="sssd.service"||!S_ISDIR(id.mode)||id.uid||(id.mode&0022))unsupported("unapproved unit override: "+path);
                d::Fd directory(::openat(fd.get(),".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
                if(!directory)unsupported("cannot inspect drop-in directory");
                std::uint64_t budget=1024*1024;const auto tree=d::readTree(directory.get(),ControlledPathKind::Directory,budget);
                if(tree.attributes.size()!=1||!tree.files.empty())unsupported("unapproved nonempty drop-in directory: "+path);
                const auto& st=tree.attributes.at("");
                chain.push_back(J::array({id.mount,id.device,id.inode,st.st_mode,st.st_uid,st.st_gid,
                    st.st_mtim.tv_sec,st.st_mtim.tv_nsec,st.st_ctim.tv_sec,st.st_ctim.tv_nsec}));
            }
            observed.push_back(J::array({path,chain,absent?"absent":"empty-directory"}));
        }
    }
    return observed.dump();
}
// Closed native /bin tools used by the recorded precommands. Observe aliases
// through no-follow descriptors; only usr-merge and stock sh->dash/bash allowed.
std::string nativeTool(int root,const std::string& leaf,std::uint64_t& budget,bool ubuntu26) {
    auto bin=d::openAbsolute("/bin",O_PATH);std::string base="/bin";J aliases=J::array();
    const auto alias=[&](int fd) {
        const auto id=d::identity(fd);struct stat st{};char text[128];
        const auto n=::readlinkat(fd,"",text,sizeof text);
        if(id.uid||::fstat(fd,&st)||n<=0||n==sizeof text)unsupported("untrusted native executable alias");
        aliases.push_back(J::array({id.mount,id.device,id.inode,id.mode,id.uid,id.gid,
            st.st_mtim.tv_sec,st.st_mtim.tv_nsec,st.st_ctim.tv_sec,st.st_ctim.tv_nsec,std::string(text,n)}));
        return std::string(text,n);
    };
    if(S_ISLNK(d::identity(bin.get()).mode)) {
        const auto target=alias(bin.get());if(target!="usr/bin"&&target!="/usr/bin")unsupported("unsupported /bin alias");base="/usr/bin";
    }
    auto source=d::openAbsolute(base+"/"+leaf,O_PATH);auto canonical=base+"/"+leaf;
    if(S_ISLNK(d::identity(source.get()).mode)) {
        const auto target=alias(source.get());
        if(leaf=="sh"&&(target=="dash"||target=="bash"))canonical=base+"/"+target;
        else if(ubuntu26&&(leaf=="chown"||leaf=="chmod")&&target=="../lib/cargo/bin/coreutils/"+leaf)canonical="/usr/lib/cargo/bin/coreutils/"+leaf;
        else unsupported("unsupported native tool alias");
    }
    auto file=d::openAbsolute(canonical,O_RDONLY);const auto id=d::identity(file.get());
    if(!(id.mode&0111))unsupported("native tool not executable");
    return J{{"aliases",aliases},{"source",d::fingerprintUnitSource(root,canonical,budget)}}.dump();
}
std::string processIdentity(const d::LaunchContract& c) {
    const auto pid=value(c,"MainPID","u").get<unsigned>();
    if(!pid||pid>INT32_MAX)unsupported("active MainPID required");
    const auto base="/proc/"+std::to_string(pid);
    struct stat live{}, disk{};
    auto file=d::openAbsolute("/usr/sbin/sssd",O_RDONLY);
    if(::stat((base+"/exe").c_str(),&live)||::fstat(file.get(),&disk)||live.st_dev!=disk.st_dev||live.st_ino!=disk.st_ino)
        unsupported("MainPID executable differs from trusted SSSD");
    if(d::namespaceIdentity(pid)!=d::namespaceIdentity(::getpid())||d::namespaceIdentity(1)!=d::namespaceIdentity(::getpid()))unsupported("incompatible service/manager mount namespace");
    struct stat serviceRoot{},ownRoot{};
    if(::stat((base+"/root").c_str(),&serviceRoot)||::stat("/",&ownRoot)||serviceRoot.st_dev!=ownRoot.st_dev||serviceRoot.st_ino!=ownRoot.st_ino)unsupported("incompatible runtime root");
    std::ifstream f(base+"/stat");std::string text;std::getline(f,text);auto end=text.rfind(')');
    if(end==std::string::npos)unsupported("process identity unavailable");
    std::istringstream fields(text.substr(end+1));std::string field;
    for(int i=3;i<=22;++i)if(!(fields>>field))unsupported("process start identity unavailable");
    const auto invocation=value(c,"InvocationID","ay");
    if(invocation.size()!=16||std::all_of(invocation.begin(),invocation.end(),[](const J& b){return b==0;}))unsupported("missing invocation identity");
    for(const auto& b:invocation)if(!b.is_number_unsigned()||b.get<unsigned>()>255)unsupported("invalid invocation bytes");
    return std::to_string(pid)+":"+field+":"+invocation.dump();
}
}
LaunchProfile launchProfile(const std::string& p) {
    LaunchProfile x{p,"/usr/lib/systemd/system/sssd.service","/etc/default/sssd","","","/run/sssd.pid",{}};
    if(p=="debian-12")x.fragment="/lib/systemd/system/sssd.service";
    else if(p=="ubuntu-24.04") {} // Native usr-merged unit source.
    else if(p=="alt-p11")x.environment="/etc/sysconfig/sssd";
    else if(p=="debian-13"||p=="ubuntu-26.04") {
        x.user=x.group=p=="debian-13"?"root":"sssd";x.pidFile="";
        const auto owner=x.user+":"+x.group;
        x.preCommands={{"/bin/chown","-f","-R",owner,"/etc/sssd"},{"/bin/chmod","-f","-R","g+r","/etc/sssd"},
            {"/bin/sh","-c","/bin/chown -f "+owner+" /var/lib/sss/db/*.ldb"},
            {"/bin/chown","-f","-R",owner,"/var/lib/sss/gpo_cache"},
            {"/bin/sh","-c","/bin/chown -f "+owner+" /var/log/sssd/*.log"}};
        if(p=="ubuntu-26.04")x.preCommands={
            {"/bin/chown","-f","-R","-H","root:sssd","/etc/sssd"},
            {"/bin/chmod","-f","-R","g+r","/etc/sssd"},
            {"/bin/chmod","-f","g+x","/etc/sssd"},{"/bin/chmod","-f","g+x","/etc/sssd/conf.d"},
            {"/bin/chmod","-f","g+x","/etc/sssd/pki"},
            {"/bin/sh","-c","/bin/chown -f -h sssd:sssd /var/lib/sss/db/*.ldb"},
            {"/bin/chown","-f","-R","-h","sssd:sssd","/var/lib/sss/gpo_cache"},
            {"/bin/sh","-c","/bin/chown -f -h sssd:sssd /var/log/sssd/*.log*"}};
    } else unsupported("unknown platform profile");
    const std::map<std::string,std::string> digests{{"debian-12","5c2164b66d61bdd2a1d7e7d3b78c5e4a939cd57a62e44d2c2a3cddd480db43d5"},{"debian-13","de718691081fbceb07b5338f5dabec659b76bc404769356bc8c3ae27b375984e"},{"ubuntu-24.04","5c2164b66d61bdd2a1d7e7d3b78c5e4a939cd57a62e44d2c2a3cddd480db43d5"},{"ubuntu-26.04","5d782f35931160e062a42000ae6636a1f46ad94618a564e718a7094767815da1"},{"alt-p11","b26ae44bc2527d6f730b749a7202f1967544294802245c9ef2fd846fab18fe6f"}};
    x.unitSha256=digests.at(p);return x;
}
void validateLaunchProfile(const d::LaunchContract& c,const LaunchProfile& p) {
    equal(c,"Id","s","sssd.service");equal(c,"LoadState","s","loaded");
    equal(c,"Type","s","notify");equal(c,"NotifyAccess","s","main");
    equal(c,"RootDirectory","s","");equal(c,"RootImage","s","");
    equal(c,"SourcePath","s","");equal(c,"DropInPaths","as",J::array());
    equal(c,"FragmentPath","s",p.fragment);
    if(!c.count("launch.file:"+p.fragment))unsupported("missing unit source fingerprint");
    try {
        const auto source=J::parse(c.at("launch.file:"+p.fragment));
        if(source.at("original")!=p.fragment||source.at("file").at(10)!=p.unitSha256)unsupported("unreviewed native unit source");
    }catch(const J::exception&){unsupported("malformed unit fingerprint");}
    equal(c,"User","s",p.user);equal(c,"Group","s",p.group);equal(c,"PIDFile","s",p.pidFile);
    equal(c,"SupplementaryGroups","as",J::array());equal(c,"Environment","as",J::array({"DEBUG_LOGGER=--logger=files"}));
    equal(c,"EnvironmentFiles","a(sb)",J::array({J::array({p.environment,true})}));
    equal(c,"ExecStartEx","a(sasasttttuii)",commands({{"/usr/sbin/sssd","-i","${DEBUG_LOGGER}"}},false));
    equal(c,"ExecStartPreEx","a(sasasttttuii)",commands(p.preCommands,true));
    for(const auto& k:{"ExecConditionEx","ExecStartPostEx","ExecReloadEx","ExecStopEx","ExecStopPostEx"})equal(c,k,"a(sasasttttuii)",J::array());
    for(const auto& k:{"ReadWritePaths","ReadOnlyPaths","InaccessiblePaths"})equal(c,k,"as",J::array());
    for(const auto& k:{"BindPaths","BindReadOnlyPaths"})equal(c,k,"a(ssbt)",J::array());
    equal(c,"TemporaryFileSystem","a(ss)",J::array());equal(c,"MountFlags","t",0);
    for(const auto& k:{"PrivateMounts","PrivateDevices","ProtectClock","ProtectKernelTunables","ProtectKernelModules","ProtectKernelLogs","ProtectControlGroups"})equal(c,k,"b",false);
    // PrivateTmp/ProtectHostname changed from b to s in newer systemd.
    for(const auto& k:{"PrivateTmp","ProtectHostname"}) {
        const auto raw=c.find(std::string("launch.")+k);if(raw==c.end())unsupported("missing sandbox property");
        auto j=J::parse(raw->second);if(j.at("signature")=="b")equal(c,k,"b",false);else equal(c,k,"s","no");
    }
    J manager;
    try {manager=J::parse(c.at("launch.ManagerEnvironment"));}catch(const std::exception&){unsupported("manager environment unavailable");}
    if(!manager.is_array())unsupported("manager environment schema");
    for(const auto& entry:manager) {
        if(!entry.is_string())unsupported("manager environment entry type");
        const auto text=entry.get<std::string>();const auto eq=text.find('=');
        if(eq==text.npos)unsupported("manager environment assignment");
        const auto key=text.substr(0,eq);
        const auto val=text.substr(eq+1);
        const bool locale=(key=="LANG"||key=="LC_ALL")&&(val=="C"||val=="C.UTF-8"||val=="POSIX");
        const bool path=key=="PATH"&&(val=="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"||val=="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        if(!locale&&!path)unsupported("unsupported manager launch variable/value: "+key);
    }
    equal(c,"ProtectHome","s","no");equal(c,"ProtectSystem","s","no");
    // Reuse the generic negative-input validation without granting a new engine
    // profile. Only fields already proven above are projected for this read-only check.
    auto copy=c;
    copy["launch.PIDFile"]=J{{"signature","s"},{"value",""}}.dump();
    std::vector<ControlledPath> env{{p.environment,ControlledPathKind::File,std::string(64,'0'),{}}};
    d::validateLaunchContract(copy,&env);
}
AdmissionState classifyService(const d::LaunchContract& c) {
    const auto active=value(c,"ActiveState","s"),sub=value(c,"SubState","s");
    const auto job=value(c,"Job","(uo)");
    if(!job.is_array()||job.size()!=2||!job[0].is_number_unsigned()||!job[1].is_string())unsupported("invalid Job type");
    if(job[0]!=0||active=="activating"||active=="deactivating"||active=="reloading")return AdmissionState::Transitioning;
    if(active=="failed")return AdmissionState::Failed;
    if(active=="inactive"&&sub=="dead")return AdmissionState::Stopped;
    if(active=="active"&&sub=="running"&&value(c,"MainPID","u")!=0)return AdmissionState::Candidate;
    return AdmissionState::Unknown;
}
static SssdLaunchReference admitImpl(Deadline deadline
#ifdef FIC_SSSD_I1_TESTING
    , const std::function<void(const SssdLaunchReference&)>& checkpoint
#endif
) {
    if(::geteuid()!=0)unsupported("root read-only admission required");
    const auto platform=fic::platform::makeBuildPlatformProfile();std::string platformError;
    if(!fic::platform::validateHostCompatibility(platform,"/etc/os-release",platformError))unsupported("platform mismatch: "+platformError);
    SssdLaunchReference out;out.profile=launchProfile(platform.id);
    out.contract=d::readSssdLaunchContract(deadline);validateLaunchProfile(out.contract,out.profile);
    if(classifyService(out.contract)!=AdmissionState::Candidate)unsupported("service is stopped, failed, transitioning or unknown");
    out.processIdentity=processIdentity(out.contract);
    out.environmentFingerprint=detail_i1::environmentReference(out.profile.environment);
    out.unitLookupFingerprint=unitLookup(out.contract,out.profile);
#ifdef FIC_SSSD_I1_TESTING
    if(checkpoint)checkpoint(out);
#endif
    auto root=d::openAbsolute("/",O_PATH|O_DIRECTORY);std::uint64_t budget=64*1024*1024;
    for(const auto& name:{"/usr/sbin/sssd","/usr/sbin/sssctl","/usr/libexec/sssd/sssd_be","/usr/libexec/sssd/sssd_nss","/usr/libexec/sssd/sssd_pam"}) {
        auto file=d::openAbsolute(name,O_RDONLY);const auto id=d::identity(file.get());
        if(id.uid||!(id.mode&0111)||(id.mode&0022))unsupported("untrusted/missing executable");
        out.executables[name]=d::fingerprintUnitSource(root.get(),name,budget);
    }
    if(!out.profile.preCommands.empty())for(const auto& tool:{"chown","chmod","sh"})out.executables[std::string("/bin/")+tool]=nativeTool(root.get(),tool,budget,out.profile.platform=="ubuntu-26.04");
    out.activationLimit=out.profile.pidFile.empty()?"I3 consumer/runtime/semantics/P proofs not implemented":"I3 requires closed PIDFile support; generic engine remains Unsupported";
    if(d::readSssdLaunchContract(deadline)!=out.contract||processIdentity(out.contract)!=out.processIdentity||detail_i1::environmentReference(out.profile.environment)!=out.environmentFingerprint||unitLookup(out.contract,out.profile)!=out.unitLookupFingerprint)
        throw d::Failure(ActivationStatus::InterferenceDetected,"SSSD launch changed during admission");
    return out;
}
SssdLaunchReference admit(Deadline deadline) {
    return admitImpl(deadline
#ifdef FIC_SSSD_I1_TESTING
        ,{}
#endif
    );
}
#ifdef FIC_SSSD_I1_TESTING
SssdLaunchReference detail_i1::admitForTests(Deadline deadline,const std::function<void(const SssdLaunchReference&)>& checkpoint) {
    return admitImpl(deadline,checkpoint);
}
#endif
void detail_i1::verifyExecutables(const SssdLaunchReference& ref){
    auto root=d::openAbsolute("/",O_PATH|O_DIRECTORY);std::uint64_t budget=128*1024*1024;
    for(const auto& [path,expected]:ref.executables){
        const auto observed=path.rfind("/bin/",0)==0?nativeTool(root.get(),path.substr(5),budget,ref.profile.platform=="ubuntu-26.04"):d::fingerprintUnitSource(root.get(),path,budget);
        if(observed!=expected)throw d::Failure(ActivationStatus::InterferenceDetected,"SSSD executable/alias source changed");
    }
}
void revalidate(const SssdLaunchReference& ref,Deadline deadline) {
    try {const auto now=admit(deadline);
        if(now.profile.platform!=ref.profile.platform||now.contract!=ref.contract||now.executables!=ref.executables||now.processIdentity!=ref.processIdentity||now.environmentFingerprint!=ref.environmentFingerprint||now.unitLookupFingerprint!=ref.unitLookupFingerprint)
            throw d::Failure(ActivationStatus::InterferenceDetected,"SSSD launch reference changed");
    } catch(const d::Failure& e) {if(e.status==ActivationStatus::TimedOut)throw;throw d::Failure(ActivationStatus::InterferenceDetected,e.what());}
}
} // namespace fic::service::sssd
