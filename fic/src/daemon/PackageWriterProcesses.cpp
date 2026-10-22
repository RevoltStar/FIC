#include "daemon/PackageWriterProcesses.h"
#include <fic/core/fs/RootControlledDirectory.h>
#include <fic/core/integrity/ContentDigest.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <map>
#include <set>
#include <sstream>
#include <tuple>
#include <dirent.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
namespace fic::daemon {
namespace {
constexpr std::uint64_t MaxImage=64*1024*1024,MaxImageTotal=256*1024*1024,MaxMetadata=16*1024*1024;
constexpr std::size_t MaxProcesses=4096;
struct Fd {int fd;explicit Fd(int n):fd(n){}~Fd(){if(fd>=0)::close(fd);}Fd(const Fd&)=delete;};
bool fail(std::string& error,const char* text){error=text;return false;}
bool same(const struct stat& a,const struct stat& b) {
    return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_size==b.st_size&&
        a.st_mtim.tv_sec==b.st_mtim.tv_sec&&a.st_mtim.tv_nsec==b.st_mtim.tv_nsec&&
        a.st_ctim.tv_sec==b.st_ctim.tv_sec&&a.st_ctim.tv_nsec==b.st_ctim.tv_nsec;
}
bool readFd(int fd,std::size_t limit,std::string& text,std::uint64_t& budget,
            std::chrono::steady_clock::time_point deadline) {
    text.clear();std::array<char,8192> buffer{};
    for(std::size_t offset=0;;) {
        if(std::chrono::steady_clock::now()>=deadline)return false;
        const auto n=::pread(fd,buffer.data(),std::min(buffer.size(),limit-offset+1),offset);
        if(n<0)return false;
        if(n==0)return true;
        if(static_cast<std::size_t>(n)>limit-offset || static_cast<std::uint64_t>(n)>budget)return false;
        text.append(buffer.data(),n);offset+=n;budget-=n;
    }
}
bool imageDigest(int fd,std::string& digest,std::uint64_t& budget,
                 std::chrono::steady_clock::time_point deadline) {
    struct stat before{},after{};
    if(::fstat(fd,&before) || !S_ISREG(before.st_mode) || before.st_size<=0 ||
        static_cast<std::uint64_t>(before.st_size)>MaxImage)return false;
    std::string bytes;
    if(!readFd(fd,MaxImage,bytes,budget,deadline) || ::fstat(fd,&after) || !same(before,after))return false;
    digest=fic::core::ContentDigest::sha256Hex(bytes);
    return !digest.empty()&&std::chrono::steady_clock::now()<deadline;
}
bool procText(int dir,const char* name,std::string& text,std::uint64_t& budget,
              std::chrono::steady_clock::time_point deadline) {
    Fd fd(::openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
    return fd.fd>=0&&readFd(fd.fd,65536,text,budget,deadline);
}
bool gone(int dir) {
    struct stat info{};return ::fstatat(dir,"stat",&info,AT_SYMLINK_NOFOLLOW)<0&&(errno==ENOENT||errno==ESRCH);
}
bool digits(const std::string& text) {
    return !text.empty()&&text.size()<=10&&std::all_of(text.begin(),text.end(),[](char c){return c>='0'&&c<='9';});
}
bool status(const std::string& text,bool& privileged,bool& kernel,bool& terminal) {
    std::map<std::string,std::string> values;std::istringstream lines(text);std::string line;
    while(std::getline(lines,line)) {
        const auto p=line.find(':');if(p==std::string::npos||!values.emplace(line.substr(0,p),line.substr(p+1)).second)return false;
    }
    if(!values.count("Uid")||!values.count("CapPrm")||!values.count("CapEff"))return false;
    std::istringstream ids(values["Uid"]);std::uint64_t uid;privileged=false;
    for(unsigned i=0;i<4;++i){if(!(ids>>uid))return false;privileged|=uid==0;}
    std::string extra;if(ids>>extra)return false;
    for(const auto* field:{"CapPrm","CapEff"}) {
        std::istringstream caps(values[field]);std::string hex;
        if(!(caps>>hex)||hex.empty()||hex.size()>16||hex.find_first_not_of("0123456789abcdefABCDEF")!=std::string::npos||caps>>extra)return false;
        privileged|=hex.find_first_not_of('0')!=std::string::npos;
    }
    kernel=false;
    if(!values.count("State"))return false;
    std::istringstream processState(values["State"]);char state=0;
    if(!(processState>>state))return false;
    // Zombies/dead tasks cannot resume execution; missing exe is normal there.
    terminal=state=='Z'||state=='X'||state=='x';
    if(values.count("Kthread")) {
        std::istringstream field(values["Kthread"]);unsigned flag;
        if(!(field>>flag)||flag>1||field>>extra)return false;
        kernel=kernel||flag==1;
    }
    return true;
}
bool startTime(int process,const std::string& pid,std::string& token,std::uint64_t& metadata,
               std::chrono::steady_clock::time_point deadline) {
    std::string text;if(!procText(process,"stat",text,metadata,deadline))return false;
    const auto split=text.find(' '),end=text.rfind(')');
    if(split==std::string::npos||end==std::string::npos||text.substr(0,split)!=pid||end<=split)return false;
    std::istringstream fields(text.substr(end+1));
    for(unsigned field=3;field<=22;++field)if(!(fields>>token))return false;
    return !token.empty()&&token.size()<=20&&token.find_first_not_of("0123456789")==std::string::npos;
}
bool terminalGroup(int process,std::uint64_t& metadata,std::size_t& count,
                   std::chrono::steady_clock::time_point deadline) {
    Fd tasks(::openat(process,"task",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    if(tasks.fd<0)return gone(process);
    DIR* entries=::fdopendir(::dup(tasks.fd));if(!entries)return false;
    struct Close {DIR* dir;~Close(){::closedir(dir);}} close{entries};
    for(;;) {
        errno=0;auto* entry=::readdir(entries);if(!entry)return errno==0;
        if(!digits(entry->d_name))continue;
        if(++count>MaxProcesses || std::chrono::steady_clock::now()>=deadline)return false;
        Fd task(::openat(tasks.fd,entry->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        if(task.fd<0){if(errno==ENOENT||errno==ESRCH)continue;return false;}
        std::string text;bool privileged=false,kernel=false,terminal=false;
        if(!procText(task.fd,"status",text,metadata,deadline)||!status(text,privileged,kernel,terminal)) {
            if(gone(task.fd))continue;
            return false;
        }
        if(!terminal)return false;
    }
}

}
bool captureLegacyWriterImage(const std::filesystem::path& path,LegacyWriterImage& result,std::string& error) {
    result={};
    if(!path.is_absolute()||path.lexically_normal()!=path)return fail(error,"invalid legacy image path");
    Fd parent(fic::core::openRootControlledDirectory(path.parent_path(),error));
    if(parent.fd<0)return false;
    Fd file(::openat(parent.fd,path.filename().c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
    struct stat info{};
    if(file.fd<0 || ::fstat(file.fd,&info) || !S_ISREG(info.st_mode) || info.st_uid ||
        (info.st_mode&0022) || info.st_nlink!=1 || !(info.st_mode&0111))return fail(error,"untrusted legacy executable reference");
    std::uint64_t budget=MaxImage;std::string digest;
    if(!imageDigest(file.fd,digest,budget,std::chrono::steady_clock::now()+std::chrono::seconds(5)))
        return fail(error,"legacy executable reference cannot be fingerprinted within budget");
    struct stat confirmed{};if(::fstat(file.fd,&confirmed)||!same(info,confirmed))return fail(error,"legacy executable reference changed");
    result={static_cast<std::uint64_t>(info.st_dev),static_cast<std::uint64_t>(info.st_ino),static_cast<std::uint64_t>(info.st_size),digest};
    error.clear();return true;
}
bool proveNoPackageWriterProcesses(const std::vector<LegacyWriterImage>& references,
    std::chrono::steady_clock::time_point deadline,std::string& error) {
    if(::geteuid()!=0 || references.size()>8)return fail(error,"writer census requires root and bounded reference set");
    for(const auto& image:references)if(!image.size || image.size>MaxImage || !fic::core::ContentDigest::isCanonicalSha256Hex(image.digest))
        return fail(error,"unproven legacy image reference");
    Fd root(::open("/proc",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));struct statfs fs{};
    if(root.fd<0||::fstatfs(root.fd,&fs)||fs.f_type!=PROC_SUPER_MAGIC)return fail(error,"process census requires genuine procfs");
    char self[64];const auto selfLength=::readlinkat(root.fd,"self",self,sizeof(self));
    if(selfLength<0 || selfLength>=static_cast<ssize_t>(sizeof(self)) ||
        std::string(self,selfLength)!=std::to_string(::getpid()))return fail(error,"procfs PID namespace differs from caller");
    DIR* directory=::fdopendir(::dup(root.fd));if(!directory)return fail(error,"cannot enumerate processes");
    struct Close {DIR* dir;~Close(){::closedir(dir);}} close{directory};
    std::uint64_t metadata=MaxMetadata,images=MaxImageTotal;std::size_t count=0;
    using Key=std::tuple<dev_t,ino_t,off_t,long,long,long,long>;
    std::map<Key,std::string> cache;
    for(;;) {
        errno=0;auto* entry=::readdir(directory);
        if(!entry){if(errno)return fail(error,"process enumeration failed");break;}
        const std::string pid=entry->d_name;
        if(!digits(pid)||pid==std::to_string(::getpid()))continue;
        if(++count>MaxProcesses || std::chrono::steady_clock::now()>=deadline)return fail(error,"writer census budget exceeded");
        Fd process(::openat(root.fd,pid.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        if(process.fd<0){if(errno==ENOENT||errno==ESRCH)continue;return fail(error,"cannot pin process identity");}
        std::string initialStart;
        if(!startTime(process.fd,pid,initialStart,metadata,deadline)) {
            if(gone(process.fd))continue;
            return fail(error,"process start identity unprovable");
        }
        std::string fields;bool privileged=false,kernel=false,terminal=false;
        if(!procText(process.fd,"status",fields,metadata,deadline)||!status(fields,privileged,kernel,terminal)) {
            if(gone(process.fd))continue;
            return fail(error,"process privilege identity unprovable");
        }
        if(!privileged||kernel)continue;
        // exe is deliberately the kernel procfs magic link, not a pathname from argv.
        Fd executable(::openat(process.fd,"exe",O_RDONLY|O_CLOEXEC|O_NONBLOCK));struct stat before{},after{};
        if(executable.fd<0||::fstat(executable.fd,&before)) {
            if(gone(process.fd) || (terminal && terminalGroup(process.fd,metadata,count,deadline)))continue;
            return fail(error,"privileged process executable unidentifiable or live threads remain");
        }
        char link[4096];const auto length=::readlinkat(process.fd,"exe",link,sizeof(link));
        if(length<0||length>=static_cast<ssize_t>(sizeof(link))) {
            if(gone(process.fd))continue;
            return fail(error,"process executable name unprovable");
        }
        std::string path(link,length);const std::string deleted=" (deleted)";
        if(path.size()>=deleted.size()&&path.compare(path.size()-deleted.size(),deleted.size(),deleted)==0)path.resize(path.size()-deleted.size());
        const auto name=std::filesystem::path(path).filename().string();
        bool writer=name=="fic"||name=="fic-runtime"||name=="fic-dick"||name=="fic-notify-dispatcher";
        for(const auto& image:references) {
            if(static_cast<std::uint64_t>(before.st_size)!=image.size)continue;
            const Key key{before.st_dev,before.st_ino,before.st_size,before.st_mtim.tv_sec,before.st_mtim.tv_nsec,before.st_ctim.tv_sec,before.st_ctim.tv_nsec};
            auto it=cache.find(key);
            if(it==cache.end()) {
                std::string digest;if(!imageDigest(executable.fd,digest,images,deadline))return fail(error,"executable fingerprint budget/identity unproven");
                it=cache.emplace(key,std::move(digest)).first;
            }
            writer|=it->second==image.digest;
        }
        // Do not decide from an executable that changed during the inventory.
        if(::fstatat(process.fd,"exe",&after,0)||!same(before,after)) {
            if(gone(process.fd))continue;
            return fail(error,"process executable changed during census");
        }
        std::string finalStart;
        if(!startTime(process.fd,pid,finalStart,metadata,deadline)||finalStart!=initialStart) {
            if(gone(process.fd))continue;
            return fail(error,"process identity changed during census");
        }
        if(writer){error="legacy/manual FIC writer remains: pid="+pid+" start="+initialStart+" executable="+path;return false;}
    }
    error.clear();return true;
}
}
