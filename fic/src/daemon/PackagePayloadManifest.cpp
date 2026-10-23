#include "daemon/PackagePayloadManifest.h"
#include <fic/core/fs/RootControlledDirectory.h>
#include <fic/core/fs/SecureStateFile.h>
#include <fic/core/integrity/ContentDigest.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>
namespace fic::daemon {
namespace {
bool fail(std::string& error,const std::string& why){error=why;return false;}
bool knownPackage(const std::string& name) {
    const std::set<std::string> names{"fic","fic-runtime","fic-dick","fic-cli","fic-gui","fic-session-agent","fic-prelogin"};
    return names.count(name);
}
bool field(const std::string& value,std::size_t limit) {
    return !value.empty()&&value.size()<=limit&&std::all_of(value.begin(),value.end(),[](unsigned char c){return c>=32&&c!=127;});
}
bool pathValid(const std::filesystem::path& path) {
    if(!path.is_absolute()||path.lexically_normal()!=path||path.filename().empty()||!field(path.string(),4096))return false;
    for(const auto& component:path)if(component=="."||component=="..")return false;
    return true;
}
bool managedSlot(const std::filesystem::path& path) {
    const std::set<std::string> names{"fic-faillock-preauth","fic-faillock-authfail","fic-faillock-authsucc",
        "fic-faillock-account","fic-password-quality","fic-password-history","fic-password-history-initial"};
    return path.parent_path()=="/etc/pam.d"&&names.count(path.filename().string());
}
// Only standard first-component usr-merge links, with exact declared targets.
// No generic canonical()/realpath fallback or adoption of nested symlinks.
bool physicalPath(const std::filesystem::path& input,std::filesystem::path& output,std::string& error) {
    output=input;auto it=input.begin();++it;
    if(it==input.end())return fail(error,"invalid payload path");
    const auto first=*it;
    if(first!="lib"&&first!="lib64"&&first!="bin"&&first!="sbin")return true;
    const auto prefix=std::filesystem::path("/")/first;
    struct stat info{};
    if(::lstat(prefix.c_str(),&info))return fail(error,"payload root prefix is unprovable");
    if(!S_ISLNK(info.st_mode))return true;
    std::error_code ec;const auto target=std::filesystem::read_symlink(prefix,ec);
    const auto relative=std::filesystem::path("usr")/first;
    if(ec||info.st_uid||info.st_gid||info.st_nlink!=1||(target!=relative&&target!=std::filesystem::path("/")/relative))
        return fail(error,"untrusted payload usr-merge alias");
    output=std::filesystem::path("/")/relative;
    for(++it;it!=input.end();++it)output/=*it;
    return true;
}
}
bool PackagePayloadManifest::load(const std::filesystem::path& path,const std::string& package,
    const std::string& version,PackagePayloadManifest& out,std::string& error) {
    out.entries_.clear();
    if(!knownPackage(package)||!field(version,128)||!pathValid(path))return fail(error,"invalid payload manifest identity/path");
    const int parent=fic::core::openRootControlledDirectory(path.parent_path(),error);
    if(parent<0)return false;
    ::close(parent);
    fic::core::SecureStateFileExpectation options;options.owner=0;options.group=0;
    options.forbiddenMode=0022|07000;options.requireSingleLink=true;options.parentOwner=0;
    const auto file=fic::core::readSecureFileBounded(path,options,1024*1024);
    if(file.status!=fic::core::SecureStateReadStatus::Proven)return fail(error,"payload manifest absent/untrusted: "+file.detail);
    try {
        using json=nlohmann::json;bool duplicate=false;std::vector<std::set<std::string>> objects;
        const auto value=json::parse(file.content,[&](int,json::parse_event_t event,json& token){
            if(event==json::parse_event_t::object_start)objects.emplace_back();
            else if(event==json::parse_event_t::object_end)objects.pop_back();
            else if(event==json::parse_event_t::key&&!objects.back().insert(token.get<std::string>()).second)duplicate=true;
            return true;
        });
        if(duplicate||!value.is_object()||value.size()!=4||!value.at("schema").is_number_unsigned()||value.at("schema")!=1||
           value.at("package")!=package||value.at("version")!=version||!value.at("files").is_array()||
           value.at("files").empty()||value.at("files").size()>8192)throw std::runtime_error("schema");
        std::set<std::string> paths;std::vector<PackagePayloadEntry> entries;
        for(const auto& row:value.at("files")) {
            if(!row.is_object()||row.size()!=5||!row.at("mode").is_number_unsigned())throw std::runtime_error("entry");
            const auto location=row.at("path").get<std::string>(),kind=row.at("kind").get<std::string>(),group=row.at("group").get<std::string>();
            const auto identity=row.at("identity").get<std::string>();const auto mode=row.at("mode").get<unsigned long long>();
            if(!pathValid(location)||!paths.insert(location).second||(group!="root"&&group!="fic")||mode>0777||(mode&0022))throw std::runtime_error("path/metadata");
            PackagePayloadKind type;
            if(kind=="file"&&(mode&0400)&&fic::core::ContentDigest::isCanonicalSha256Hex(identity))type=PackagePayloadKind::Regular;
            else if(kind=="symlink"&&field(identity,4096)&&group=="root"&&mode==0)type=PackagePayloadKind::Symlink;
            else if(kind=="managed-pam-slot"&&package=="fic"&&managedSlot(location)&&identity.empty()&&mode==0644&&group=="root")type=PackagePayloadKind::ManagedPamSlot;
            else if(kind=="managed-pam-provider"&&package=="fic"&&location=="/etc/security/fic-pwhistory.conf"&&identity.empty()&&mode==0644&&group=="root")type=PackagePayloadKind::ManagedPamProvider;
            else throw std::runtime_error("kind/identity");
            entries.push_back({location,type,static_cast<mode_t>(mode),group=="fic",identity});
        }
        out.entries_=std::move(entries);error.clear();return true;
    } catch(...) {return fail(error,"unknown/corrupt payload manifest");}
}
bool PackagePayloadManifest::proveInstalled(gid_t ficGroup,std::chrono::steady_clock::time_point deadline,std::string& error) const {
    if(entries_.empty())return fail(error,"unloaded payload manifest");
    std::uintmax_t budget=256*1024*1024;
    for(const auto& entry:entries_) {
        if(std::chrono::steady_clock::now()>=deadline)return fail(error,"payload proof deadline exceeded");
        std::filesystem::path physical;if(!physicalPath(entry.path,physical,error))return false;
        const int parent=fic::core::openRootControlledDirectory(physical.parent_path(),error);
        if(parent<0)return false;
        struct stat info{};const bool exists=::fstatat(parent,physical.filename().c_str(),&info,AT_SYMLINK_NOFOLLOW)==0;
        if(!exists||info.st_uid||info.st_nlink!=1||info.st_gid!=(entry.ficGroup?ficGroup:0)) {::close(parent);return fail(error,"payload metadata/identity unproven: "+entry.path.string());}
        if(entry.kind==PackagePayloadKind::Symlink) {
            std::array<char,4097> bytes{};const auto size=::readlinkat(parent,physical.filename().c_str(),bytes.data(),bytes.size());
            struct stat after{};const bool proven=S_ISLNK(info.st_mode)&&size>0&&size<static_cast<ssize_t>(bytes.size())&&
                std::string(bytes.data(),size)==entry.identity&&::fstatat(parent,physical.filename().c_str(),&after,AT_SYMLINK_NOFOLLOW)==0&&
                after.st_dev==info.st_dev&&after.st_ino==info.st_ino&&after.st_uid==info.st_uid&&after.st_gid==info.st_gid&&after.st_mode==info.st_mode;
            ::close(parent);if(!proven)return fail(error,"payload symlink differs/changed");continue;
        }
        ::close(parent);
        fic::core::SecureStateFileExpectation options;options.owner=0;options.group=entry.ficGroup?ficGroup:0;
        options.exactMode=entry.mode;options.requireSingleLink=true;options.parentOwner=0;
        const auto file=fic::core::readSecureFileBounded(physical,options,std::min<std::uintmax_t>(budget,64*1024*1024));
        if(file.status!=fic::core::SecureStateReadStatus::Proven||file.content.size()>budget)return fail(error,"payload file absent/untrusted: "+entry.path.string());
        budget-=file.content.size();
        if(entry.kind==PackagePayloadKind::Regular&&fic::core::ContentDigest::sha256Hex(file.content)!=entry.identity)
            return fail(error,"payload digest differs: "+entry.path.string());
        // Managed slots: only file presence/metadata here. Their content and
        // ownership MUST independently pass existing PAM/journal validators.
    }
    if(std::chrono::steady_clock::now()>=deadline)return fail(error,"payload proof deadline exceeded");
    error.clear();return true;
}
bool PackagePayloadManifest::proveRemoved(std::chrono::steady_clock::time_point deadline,std::string& error) const {
    if(entries_.empty())return fail(error,"unloaded payload manifest");
    for(const auto& entry:entries_) {
        if(std::chrono::steady_clock::now()>=deadline)return fail(error,"payload absence proof deadline exceeded");
        if(entry.kind==PackagePayloadKind::ManagedPamSlot||entry.kind==PackagePayloadKind::ManagedPamProvider)continue; // retained conffiles have separate PAM/journal proof
        std::filesystem::path physical;if(!physicalPath(entry.path,physical,error))return false;
        struct stat info{};if(::lstat(physical.c_str(),&info)==0||errno!=ENOENT)return fail(error,"removed package payload remains/unprovable: "+entry.path.string());
        // lstat(leaf)==ENOENT is insufficient when an ancestor was redirected.
        // A missing parent is accepted only after walking all existing parents.
        auto parent=physical.parent_path();
        while(true) {
            if(::lstat(parent.c_str(),&info)==0)break;
            if(errno!=ENOENT||parent==parent.root_path())return fail(error,"payload absence parent is unprovable");
            parent=parent.parent_path();
        }
        const int fd=fic::core::openRootControlledDirectory(parent,error);
        if(fd<0)return false;
        ::close(fd);
    }
    error.clear();return true;
}
}
