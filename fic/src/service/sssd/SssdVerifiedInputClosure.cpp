#include "service/sssd/SssdVerifiedInputClosure.h"
#include <fic/core/integrity/ContentDigest.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <sstream>
#include <algorithm>
#include <nlohmann/json.hpp>
namespace fic::service::sssd {
namespace {
namespace d=fic::service::detail;
[[noreturn]] void unsupported(const std::string& s) {throw d::Failure(ActivationStatus::UnsupportedConfiguration,"SSSD inputs: "+s);}
void remaining(Deadline deadline) {if(std::chrono::steady_clock::now()>=deadline)throw d::Failure(ActivationStatus::TimedOut,"SSSD capture deadline exceeded");}
std::string trim(std::string x) {const auto a=x.find_first_not_of(" \t\r"),b=x.find_last_not_of(" \t\r");return a==x.npos?"":x.substr(a,b-a+1);}
bool name(const std::string& s,bool section) {return !s.empty()&&std::all_of(s.begin(),s.end(),[&](unsigned char c){return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||(section&&(c=='/'||c=='.'||c=='@'));});}
bool sameStat(const struct stat& a,const struct stat& b) {
    return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_mode==b.st_mode&&a.st_uid==b.st_uid&&a.st_gid==b.st_gid&&a.st_size==b.st_size&&a.st_nlink==b.st_nlink&&
        a.st_mtim.tv_sec==b.st_mtim.tv_sec&&a.st_mtim.tv_nsec==b.st_mtim.tv_nsec&&a.st_ctim.tv_sec==b.st_ctim.tv_sec&&a.st_ctim.tv_nsec==b.st_ctim.tv_nsec;
}
void equalSources(const std::map<std::string,Source>& a,const std::map<std::string,Source>& b) {
    bool same=a.size()==b.size();
    for(const auto& [path,x]:a) {
        auto it=b.find(path);if(it==b.end()){same=false;break;}const auto& y=it->second;
        if(x.present!=y.present||x.identity.mount!=y.identity.mount||!d::sameObject(x.identity,y.identity)||x.tree.files!=y.tree.files||x.tree.attributes.size()!=y.tree.attributes.size()){same=false;break;}
        for(const auto& [p,st]:x.tree.attributes)if(!y.tree.attributes.count(p)||!sameStat(st,y.tree.attributes.at(p))){same=false;break;}
    }
    if(!same)throw d::Failure(ActivationStatus::InterferenceDetected,"SSSD input graph/metadata/absence changed");
}
std::string rooted(const std::string& root,const std::string& p){return root+p;}
Source readSource(const std::string& path,ControlledPathKind kind,std::uint64_t& budget) {
    auto fd=d::openAbsolute(path,O_RDONLY);Source out;out.present=true;out.identity=d::identity(fd.get());out.tree=d::readTree(fd.get(),kind,budget);
    for(const auto& [name,st]:out.tree.attributes) {
        if(st.st_uid!=0||(st.st_mode&0022)||(S_ISREG(st.st_mode)&&st.st_nlink!=1))unsupported("untrusted owner/mode/hardlink: "+path+"/"+name);
    }
    auto visible=d::openAbsolute(path,O_PATH);const auto id=d::identity(visible.get());
    if(id.mount!=out.identity.mount||!d::sameObject(id,out.identity))throw d::Failure(ActivationStatus::InterferenceDetected,"SSSD source resolution changed");
    return out;
}
// Absence only means ENOENT at a pinned, trusted immediate parent. All other
// errors fail closed. Parent metadata/identity participates in both full passes.
Source optionalEnvironment(const std::string& path,std::uint64_t& budget) {
    auto parent=d::openAbsolute(std::filesystem::path(path).parent_path(),O_RDONLY|O_DIRECTORY);
    struct stat st{};const auto leaf=std::filesystem::path(path).filename().string();
    if(::fstatat(parent.get(),leaf.c_str(),&st,AT_SYMLINK_NOFOLLOW)==0)return readSource(path,ControlledPathKind::File,budget);
    if(errno!=ENOENT)unsupported("cannot prove optional absence");
    Source s;s.identity=d::identity(parent.get());if(s.identity.uid||(s.identity.mode&0022))unsupported("untrusted absence parent");
    if(::fstat(parent.get(),&st))unsupported("absence parent stat");s.tree.attributes[""]=st;return s;
}
std::map<std::string,Source> observe(const SssdLaunchReference& launch,const std::string& root,Deadline deadline) {
    remaining(deadline);std::uint64_t budget=8*1024*1024;std::map<std::string,Source> out;
    out["/etc/sssd"]=readSource(rooted(root,"/etc/sssd"),ControlledPathKind::Directory,budget);
    const auto& tree=out.at("/etc/sssd").tree;
    for(const auto& [name,st]:tree.attributes) {
        if(name.rfind("conf.d/",0)==0&&(name.substr(7).find('/')!=std::string::npos||!S_ISREG(st.st_mode)))unsupported("nested/nonregular conf.d entries");
        if(name=="sssd.conf"&&!S_ISREG(st.st_mode))unsupported("main must be regular");
        if(name=="conf.d"&&!S_ISDIR(st.st_mode))unsupported("conf.d must be a directory");
        if(S_ISREG(st.st_mode)&&(name=="sssd.conf"||name.rfind("conf.d/",0)==0)) {
            const bool groupRead=launch.profile.platform=="debian-13"||launch.profile.platform=="ubuntu-26.04";
            if((st.st_mode&0111)||(st.st_mode&0007)||(!groupRead&&(st.st_mode&0070)))unsupported("configuration access mode outside native profile");
        }
    }
    out[launch.profile.environment]=optionalEnvironment(rooted(root,launch.profile.environment),budget);
    remaining(deadline);return out;
}
void environment(const Source& env) {
    if(!env.present)return;
    std::istringstream in(env.tree.files.at(""));std::string line;
    while(std::getline(in,line)){line=trim(line);if(line.empty()||line[0]=='#')continue;
        if(line!="DAEMON_OPTS=\"-D --logger=files\""&&line!="DAEMON_OPTS=\"-D -f\""&&line!="DEBUG_LOGGER=--logger=files"&&line!="DEBUG_LOGGER=\"--logger=files\""&&line!="DEBUG_LOGGER='--logger=files'")unsupported("unsupported EnvironmentFile assignment");}
}
SssdInputReference captureGraph(const SssdLaunchReference& launch,const std::string& root,Deadline deadline
#ifdef FIC_SSSD_I1_TESTING
    ,const std::function<void()>& checkpoint
#endif
) {
    SssdInputReference out;out.launch=launch;out.sources=observe(launch,root,deadline);
#ifdef FIC_SSSD_I1_TESTING
    if(checkpoint)checkpoint();
#endif
    try {equalSources(out.sources,observe(launch,root,deadline));}
    catch(const d::Failure& e){if(e.status==ActivationStatus::TimedOut)throw;throw d::Failure(ActivationStatus::InterferenceDetected,e.what());}
    const auto& tree=out.sources.at("/etc/sssd").tree;std::map<std::string,std::string> bytes;
    out.inputs.unit="sssd.service";
    if(tree.files.count("sssd.conf"))out.order.push_back("/etc/sssd/sssd.conf");else out.negativeDependencies.push_back("/etc/sssd/sssd.conf");
    if(!tree.attributes.count("conf.d"))out.negativeDependencies.push_back("/etc/sssd/conf.d");
    for(const auto& [p,content]:tree.files) {
        bytes["/etc/sssd/"+p]=content;
        if(p.rfind("conf.d/",0)==0&&detail_i1::loadedSnippet(p.substr(7))) {
            out.order.push_back("/etc/sssd/"+p);
            if(p.substr(7)>"zzzz-fic.conf")out.laterForeignSnippets.push_back("/etc/sssd/"+p);
        }
    }
    if(out.order.empty())unsupported("neither main nor loadable snippets present");
    out.ini=detail_i1::project(out.order,bytes);
    environment(out.sources.at(launch.profile.environment));
    if(!out.sources.at(launch.profile.environment).present)out.negativeDependencies.push_back(launch.profile.environment);
    out.engineNeedsNegativeDependencySupport=!out.negativeDependencies.empty();
    if(tree.files.count("sssd.conf"))out.inputs.paths.push_back({"/etc/sssd/sssd.conf",ControlledPathKind::File,fic::core::ContentDigest::sha256Hex(tree.files.at("sssd.conf")),{}});
    if(tree.attributes.count("conf.d")) {
        ControlledPath p{"/etc/sssd/conf.d",ControlledPathKind::Directory,{},{}};
        for(const auto& [path,content]:tree.files)if(path.rfind("conf.d/",0)==0)p.manifest[path.substr(7)]=fic::core::ContentDigest::sha256Hex(content);
        out.inputs.paths.push_back(std::move(p));
    }
    const auto& env=out.sources.at(launch.profile.environment);if(env.present)out.inputs.paths.push_back({launch.profile.environment,ControlledPathKind::File,fic::core::ContentDigest::sha256Hex(env.tree.files.at("")),{}});
    d::validateRequest(out.inputs);return out;
}
void consumerExecutables(SssdInputReference& ref,Deadline deadline) {
    auto root=d::openAbsolute("/",O_PATH|O_DIRECTORY);std::uint64_t budget=64*1024*1024;
    const auto section=ref.ini.find("sssd");if(section==ref.ini.end())unsupported("missing sssd section");
    detail_i1::validateConsumerIdentity(ref.ini,ref.launch.profile.platform);
    auto services=section->second.find("services");if(services==section->second.end())return; // Native socket responders; no runtime consumer proof in I1.
    std::istringstream in(services->second.value);std::string service;
    while(std::getline(in,service,',')) {
        remaining(deadline);service=trim(service);
        if(service!="nss"&&service!="pam"&&service!="ssh"&&service!="sudo"&&service!="autofs"&&service!="pac"&&service!="ifp")unsupported("unknown responder");
        const auto path="/usr/libexec/sssd/sssd_"+service;
        ref.consumers[path]=d::fingerprintUnitSource(root.get(),path,budget);
    }
}
}
namespace detail_i1 {
void validateConsumerIdentity(const IniProjection& ini,const std::string& platform) {
    const auto section=ini.find("sssd");if(section==ini.end())unsupported("missing sssd section");
    // ALT's native socket responders run as _sssd even when services is absent.
    // monitor.c defaults a missing config user to root; active monitor != proof
    // of compatibility with that consumer profile. Privileged alternatives are
    // outside this closed profile, not silently inferred from missing inputs.
    if(platform=="alt-p11"&&!section->second.count("user"))
        unsupported("ALT native consumer profile requires explicit user=_sssd");
    if(auto it=section->second.find("user");it!=section->second.end()) {
        const auto expected=platform=="alt-p11"?"_sssd":(platform=="ubuntu-26.04"?"sssd":"root");
        if(it->second.value!=expected)unsupported("unsupported configuration user identity");
    }
}
SssdInputReference snapshotGraph(const SssdLaunchReference& launch,Deadline deadline){
    auto out=captureGraph(launch,"",deadline
#ifdef FIC_SSSD_I1_TESTING
        ,{}
#endif
    );consumerExecutables(out,deadline);return out;
}
void verifyPersistentSources(const SssdInputReference& before,Deadline deadline){
    equalSources(before.sources,observe(before.launch,"",deadline));
}
std::string environmentReference(const std::string& path) {
    std::uint64_t budget=1024*1024;const auto s=optionalEnvironment(path,budget);environment(s);
    nlohmann::json out={{"present",s.present},{"mount",s.identity.mount}};
    const auto& st=s.tree.attributes.at("");out["metadata"]=nlohmann::json::array({st.st_dev,st.st_ino,st.st_uid,st.st_gid,st.st_mode,st.st_nlink,st.st_size,
        st.st_mtim.tv_sec,st.st_mtim.tv_nsec,st.st_ctim.tv_sec,st.st_ctim.tv_nsec});
    if(s.present)out["digest"]=fic::core::ContentDigest::sha256Hex(s.tree.files.at(""));return out.dump();
}
bool loadedSnippet(const std::string& name) {return !name.empty()&&name[0]!='.'&&name.size()>5&&name.substr(name.size()-5)==".conf"&&name.find('/')==name.npos;}
IniProjection project(const std::vector<std::string>& order,const std::map<std::string,std::string>& bytes) {
    IniProjection out;
    for(const auto& path:order) {
        auto it=bytes.find(path);if(it==bytes.end())unsupported("missing projection bytes");
        for(unsigned char c:it->second)if((c<32&&c!='\n'&&c!='\r'&&c!='\t')||c>=127)unsupported("unsupported INI encoding/control byte");
        std::istringstream in(it->second);std::string line,section;
        while(std::getline(in,line)) {
            line=trim(line);if(line.empty()||line[0]=='#'||line[0]==';')continue;
            if(line[0]=='[') {if(line.back()!=']')unsupported("INI section syntax");section=trim(line.substr(1,line.size()-2));if(!name(section,true))unsupported("INI section name");out[section];continue;}
            auto equal=line.find('=');if(section.empty()||equal==line.npos)unsupported("INI assignment syntax");
            auto k=trim(line.substr(0,equal)),v=trim(line.substr(equal+1));
            if(!name(k,false)||v.empty()||v.find_first_of("\\\"'#;")!=v.npos)unsupported("unsupported INI assignment/continuation/quoting");
            out[section][k]={v,path};
        }
    }
    return out;
}
#ifdef FIC_SSSD_I1_TESTING
SssdInputReference captureForTests(const SssdLaunchReference& launch,const std::string& root,Deadline deadline,const std::function<void()>& checkpoint){return captureGraph(launch,root,deadline,checkpoint);}
#endif
}
SssdInputReference capture(Deadline deadline) {
    auto launch=admit(deadline);
    auto out=captureGraph(launch,"",deadline
#ifdef FIC_SSSD_I1_TESTING
        ,{}
#endif
    );consumerExecutables(out,deadline);
    revalidate(launch,deadline);
    // Close the interval spent validating consumer executables as well.
    equalSources(out.sources,observe(launch,"",deadline));return out;
}
void revalidate(const SssdInputReference& ref,Deadline deadline) {
    try {auto now=capture(deadline);
        if(now.consumers!=ref.consumers||now.launch.contract!=ref.launch.contract||now.launch.executables!=ref.launch.executables||now.launch.processIdentity!=ref.launch.processIdentity||now.launch.environmentFingerprint!=ref.launch.environmentFingerprint||now.launch.unitLookupFingerprint!=ref.launch.unitLookupFingerprint)throw d::Failure(ActivationStatus::InterferenceDetected,"SSSD launch changed");
        equalSources(ref.sources,now.sources);
    }catch(const d::Failure& e){if(e.status==ActivationStatus::TimedOut)throw;throw d::Failure(ActivationStatus::InterferenceDetected,e.what());}
}
} // namespace fic::service::sssd
