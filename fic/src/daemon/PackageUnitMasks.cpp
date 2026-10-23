#include "daemon/PackageUnitMasks.h"
#include "daemon/PackageWriterUnits.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/fs/RootControlledDirectory.h>
#include <fic/core/fs/SecureStateFile.h>
#include <nlohmann/json.hpp>
#include <array>
#include <cerrno>
#include <set>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
namespace fic::daemon {
namespace {
using json=nlohmann::json;
constexpr auto names=PackageWriterUnits;
struct Fd {
    int fd=-1;
    explicit Fd(int value):fd(value){}
    ~Fd(){if(fd>=0)::close(fd);}
    Fd(const Fd&)=delete;
};
struct Snapshot {unsigned kind=0;std::uint64_t device=0,inode=0;mode_t mode=0;};
struct Plan {std::array<Snapshot,PackageWriterUnits.size()> before;std::uint64_t device=0,inode=0;};
bool fail(std::string& error,const char* text){error=text;return false;}
bool validId(const std::string& id) {
    return id.size()==32 && id.find_first_not_of("0123456789abcdef")==std::string::npos;
}
bool privateRoot(const std::filesystem::path& path,std::string& error) {
    Fd fd(fic::core::openRootControlledDirectory(path,error));struct stat st{};
    return fd.fd>=0 && ::fstat(fd.fd,&st)==0 && (st.st_mode&07777)==0700;
}
std::string readLink(int dir,const char* name) {
    char bytes[4096];auto n=::readlinkat(dir,name,bytes,sizeof(bytes));
    return n>=0 && n<static_cast<ssize_t>(sizeof(bytes)) ? std::string(bytes,n) : std::string();
}
bool snapshot(int dir,const char* name,Snapshot& out,std::string& error) {
    struct stat st{};
    if(::fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)) {
        if(errno==ENOENT){out={};return true;}
        return fail(error,"cannot inspect system unit override");
    }
    if(st.st_uid!=0 || st.st_nlink!=1) return fail(error,"untrusted unit override ownership/links");
    if(S_ISLNK(st.st_mode) && readLink(dir,name)=="/dev/null") out.kind=1;
    else if(S_ISREG(st.st_mode) && st.st_size==0 && !(st.st_mode&0022)) out.kind=2;
    else return fail(error,"custom/unknown unit override cannot be replaced by lifecycle mask");
    out.device=st.st_dev;out.inode=st.st_ino;out.mode=st.st_mode;return true;
}
bool same(const Snapshot& a,const Snapshot& b) {
    return a.kind==b.kind && a.device==b.device && a.inode==b.inode && a.mode==b.mode;
}
bool ourMask(int dir,const char* name,const std::filesystem::path& artifact) {
    struct stat st{};
    return ::fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)==0 && S_ISLNK(st.st_mode) &&
        st.st_uid==0 && st.st_nlink==1 && readLink(dir,name)==artifact.string();
}
bool absent(int dir,const char* name) {
    struct stat st{};return ::fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;
}
bool load(const std::filesystem::path& root,const std::string& id,Plan& plan,std::string& error) {
    if(!validId(id)||!privateRoot(root,error))return fail(error,"invalid lifecycle mask area/identity");
    const auto directory=root/id;
    if(!privateRoot(directory,error))return fail(error,"untrusted lifecycle mask operation directory");
    fic::core::SecureStateFileExpectation options;
    options.owner=0;options.group=0;options.exactMode=0600;options.requireSingleLink=true;
    options.parentOwner=0;options.exactParentMode=0700;
    const auto ledger=fic::core::readSecureStateFile(directory/"masks.json",options);
    if(ledger.status!=fic::core::SecureStateReadStatus::Proven)return fail(error,"mask provenance missing/unproven");
    try {
        std::set<std::string> keys;bool duplicate=false;
        auto j=json::parse(ledger.content,[&](int,json::parse_event_t event,json& value){
            if(event==json::parse_event_t::key && !keys.insert(value.get<std::string>()).second)duplicate=true;
            return true;
        });
        if(duplicate || !j.is_object() || j.size()!=4+4*names.size() || !j.at("version").is_number_unsigned() ||
            j.at("version")!=1 || j.at("id")!=id)throw std::runtime_error("schema");
        const auto number=[&](const std::string& key){
            if(!j.at(key).is_number_unsigned())throw std::runtime_error("numeric field");
            return j.at(key).get<std::uint64_t>();
        };
        plan.device=number("artifact_device");plan.inode=number("artifact_inode");
        for(std::size_t i=0;i<names.size();++i) {
            const auto prefix=std::string(names[i]);const auto kind=number(prefix+"_kind"),mode=number(prefix+"_mode");
            if(kind>2 || mode>0177777)throw std::runtime_error("snapshot enum/mode");
            auto& b=plan.before[i];b={static_cast<unsigned>(kind),number(prefix+"_device"),number(prefix+"_inode"),static_cast<mode_t>(mode)};
            if((!kind && (b.device||b.inode||b.mode)) ||
                (kind==1 && !S_ISLNK(b.mode)) || (kind==2 && (!S_ISREG(b.mode)||(b.mode&0022))))
                throw std::runtime_error("snapshot");
        }
    }catch(...){return fail(error,"unknown/corrupt mask provenance");}
    const auto artifact=fic::core::readSecureStateFile(directory/"masked-unit",options);
    if(artifact.status!=fic::core::SecureStateReadStatus::Proven || !artifact.content.empty() ||
        artifact.targetState.identity.device!=plan.device || artifact.targetState.identity.inode!=plan.inode)
        return fail(error,"operation mask artifact identity changed");
    return true;
}
}
bool PackageUnitMasks::validateProvenance(const std::string& id,std::string& error) const {
    Plan plan;return load(state_,id,plan,error);
}
bool PackageUnitMasks::prepare(const DaemonInstanceLock& guard,const std::string& id,std::string& error) {
    if(!guard.heldByCurrentProcess() || !validId(id) || !privateRoot(state_,error))
        return fail(error,"mask plan requires instance admission and private state area");
    Fd unitDir(fic::core::openRootControlledDirectory(units_,error));
    if(unitDir.fd<0)return false;
    Plan plan;
    // Inspect all inputs before publishing ANY mask; foreign/custom data untouched.
    for(std::size_t i=0;i<names.size();++i)if(!snapshot(unitDir.fd,names[i],plan.before[i],error))return false;
    Fd root(fic::core::openRootControlledDirectory(state_,error));
    if(root.fd<0 || ::mkdirat(root.fd,id.c_str(),0700))return fail(error,"mask operation directory must be newly created");
    Fd operation(::openat(root.fd,id.c_str(),O_DIRECTORY|O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
    if(operation.fd<0)return fail(error,"cannot pin mask operation directory");
    Fd artifact(::openat(operation.fd,"masked-unit",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
    struct stat st{};
    if(artifact.fd<0 || ::fchown(artifact.fd,0,0) || ::fsync(artifact.fd) || ::fstat(artifact.fd,&st) ||
        ::fsync(operation.fd) || ::fsync(root.fd))return fail(error,"mask artifact creation durability unconfirmed");
    plan.device=st.st_dev;plan.inode=st.st_ino;
    json j{{"version",1},{"id",id},{"artifact_device",plan.device},{"artifact_inode",plan.inode}};
    for(std::size_t i=0;i<names.size();++i) {
        const auto prefix=std::string(names[i]);const auto& b=plan.before[i];
        j[prefix+"_kind"]=b.kind;j[prefix+"_device"]=b.device;j[prefix+"_inode"]=b.inode;j[prefix+"_mode"]=b.mode;
    }
    AtomicWriteOptions options;options.createIfMissing=true;options.exclusiveCreate=true;options.rejectSymlink=true;
    options.metadataPolicy=FileMetadataPolicy::EnforceProvided;options.fileOwner=0;options.fileGroup=0;options.fileMode=0600;
    AtomicWriteResult result;
    return AtomicFileWriter::writeWithResult((state_/id/"masks.json").string(),j.dump()+"\n",options,&error,&result) && result.durabilityConfirmed;
}
bool PackageUnitMasks::publish(const DaemonInstanceLock& guard,const std::string& id,std::string& error) {
    if(!guard.heldByCurrentProcess())return fail(error,"mask publication lacks admission");
    Plan plan;if(!load(state_,id,plan,error))return false;
    Fd dir(fic::core::openRootControlledDirectory(units_,error));if(dir.fd<0)return false;
    const auto artifact=state_/id/"masked-unit";
    for(std::size_t i=0;i<names.size();++i) {
        if(plan.before[i].kind) {
            Snapshot current;if(!snapshot(dir.fd,names[i],current,error)||!same(current,plan.before[i]))
                return fail(error,"foreign mask changed since plan; left untouched");
        } else if(!ourMask(dir.fd,names[i],artifact)) {
            if(!absent(dir.fd,names[i]) || ::symlinkat(artifact.c_str(),dir.fd,names[i]))
                return fail(error,"unit override changed before exclusive mask publication");
        }
        if(::fsync(dir.fd))return fail(error,"mask publication durability unconfirmed");
    }
    return provePublished(id,error);
}
bool PackageUnitMasks::provePublished(const std::string& id,std::string& error) const {
    Plan plan;if(!load(state_,id,plan,error))return false;
    Fd dir(fic::core::openRootControlledDirectory(units_,error));if(dir.fd<0)return false;
    const auto artifact=state_/id/"masked-unit";
    for(std::size_t i=0;i<names.size();++i) {
        if(!plan.before[i].kind) {if(!ourMask(dir.fd,names[i],artifact))return fail(error,"own persistent mask not proven");}
        else {Snapshot current;if(!snapshot(dir.fd,names[i],current,error)||!same(current,plan.before[i]))return fail(error,"preserved foreign mask not proven");}
    }
    error.clear();return true;
}
bool PackageUnitMasks::restore(const DaemonInstanceLock& guard,const std::string& id,std::string& error) {
    if(!guard.heldByCurrentProcess())return fail(error,"mask restoration lacks admission");
    Plan plan;if(!load(state_,id,plan,error))return false;
    Fd dir(fic::core::openRootControlledDirectory(units_,error));if(dir.fd<0)return false;
    const auto artifact=state_/id/"masked-unit";
    for(std::size_t i=0;i<names.size();++i) {
        if(plan.before[i].kind) {
            Snapshot current;if(!snapshot(dir.fd,names[i],current,error)||!same(current,plan.before[i]))return fail(error,"foreign mask changed; restoration refused");
        } else if(!absent(dir.fd,names[i])) {
            if(!ourMask(dir.fd,names[i],artifact))return fail(error,"foreign override replaces own mask; not removed");
            // FIC-serialized conditional unlink. A non-cooperating privileged
            // writer can still race the final check and unlink (documented).
            if(::unlinkat(dir.fd,names[i],0))return fail(error,"cannot remove own mask");
        }
        if(::fsync(dir.fd))return fail(error,"mask restoration durability unconfirmed");
    }
    error.clear();return true;
}
}
