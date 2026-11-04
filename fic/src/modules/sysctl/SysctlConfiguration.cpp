#include "modules/sysctl/SysctlConfiguration.h"
#include "modules/sysctl/SysctlKey.h"
#include <fic/core/fs/SecureStateFile.h>
#include <algorithm>
#include <sstream>
#include <set>
#include <cerrno>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
namespace {
constexpr auto header="# Managed by FIC. Manual changes may be overwritten.";
std::string trim(std::string s){return fic::sysctl::trimKey(std::move(s));}
bool parse(const std::string& text,std::map<std::string,std::string>& values,std::string& error) {
    std::istringstream input(text);std::string line;
    while(std::getline(input,line)) {
        line=trim(line);if(line.empty()||line==header)continue;
        const auto equal=line.find('=');
        if(equal==std::string::npos||line.front()=='#'||line.front()==';'||line.front()=='-') {error="foreign/invalid data in FIC sysctl artifact";return false;}
        const auto key=fic::sysctl::systemdConfigKeyToCanonicalPath(trim(line.substr(0,equal)));
        const auto value=trim(line.substr(equal+1));
        bool valid=!key.empty()&&!value.empty()&&key.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-")==std::string::npos&&value.find('\0')==std::string::npos;
        for(const auto& part:fic::sysctl::splitKey(key,'/'))valid&=!part.empty()&&part!="."&&part!="..";
        if(!valid||!values.emplace(key,value).second){error="duplicate/invalid FIC sysctl assignment";return false;}
    }
    return true;
}
std::string render(const std::map<std::string,std::string>& values) {
    std::string text=std::string(header)+"\n";
    for(const auto& [k,v]:values)text+=fic::sysctl::configKeyFromCanonicalPath(k)+" = "+v+"\n";
    return text;
}
std::string identity(const struct stat& s) {
    return std::to_string(s.st_dev)+":"+std::to_string(s.st_ino)+":"+std::to_string(s.st_mode)+":"+std::to_string(s.st_uid)+":"+std::to_string(s.st_gid)+":"+std::to_string(s.st_size)+":"+std::to_string(s.st_mtim.tv_sec)+":"+std::to_string(s.st_mtim.tv_nsec)+":"+std::to_string(s.st_ctim.tv_sec)+":"+std::to_string(s.st_ctim.tv_nsec);
}
bool suffix(const std::string& s){return s.size()>5&&s.compare(s.size()-5,5,".conf")==0;}
}
SysctlConfiguration::SysctlConfiguration(SysctlConfigurationOptions options):options_(std::move(options)){}
std::mutex& SysctlConfiguration::mutationMutex(){static std::mutex mutex;return mutex;}
bool SysctlConfiguration::directorySafe(const std::filesystem::path& path,std::string& error) const {
    if(!path.is_absolute()||path.lexically_normal()!=path){error="noncanonical sysctl directory";return false;}
    // Resolve ordinary /lib -> /usr/lib layout, then prove every ancestor.
    std::error_code ec;auto canonical=std::filesystem::canonical(path,ec);
    if(ec){error="sysctl directory unavailable: "+path.string();return false;}
    for(auto p=canonical;;p=p.parent_path()) {
        struct stat s{};
        if(::lstat(p.c_str(),&s)||!S_ISDIR(s.st_mode)||(options_.enforceOwnership&&(s.st_uid!=0||(s.st_mode&0022)))) {
            error="untrusted sysctl directory: "+p.string();return false;
        }
        if(p==p.root_path())break;
    }
    return true;
}
bool SysctlConfiguration::topology(std::map<std::string,std::string>& out,std::string& error) const {
    if(options_.platform.loader!=fic::platform::SysctlLoaderKind::SystemdSysctl){error="unsupported SYSCTL loader";return false;}
    const auto managed=options_.platform.managedConfigPath;
    if(managed.empty()||!suffix(managed.filename().string())||!directorySafe(managed.parent_path(),error))return false;
    std::set<std::filesystem::path> visited;std::set<std::string> names;bool managedDirectory=false;unsigned count=0;
    for(const auto& directory:options_.directories) {
        std::error_code ec;const auto status=std::filesystem::symlink_status(directory,ec);
        if(ec==std::errc::no_such_file_or_directory||status.type()==std::filesystem::file_type::not_found){out[directory.string()]="absent";continue;}
        if(ec||!directorySafe(directory,error))return false;
        const auto canonical=std::filesystem::canonical(directory,ec);if(ec)return false;
        if(!visited.insert(canonical).second)continue;
        struct stat ds{};if(::stat(directory.c_str(),&ds))return false;
        // Own rename changes directory times/size, not identity/authority.
        out[directory.string()]=std::to_string(ds.st_dev)+":"+std::to_string(ds.st_ino)+":"+std::to_string(ds.st_mode)+":"+std::to_string(ds.st_uid)+":"+std::to_string(ds.st_gid);
        const bool own=std::filesystem::equivalent(directory,managed.parent_path(),ec);if(ec)return false;
        managedDirectory|=own;
        std::filesystem::directory_iterator it(directory,ec),end;if(ec){error="sysctl inventory failed";return false;}
        for(;it!=end;it.increment(ec)) {
            if(ec||++count>8192){error="sysctl inventory bound/error";return false;}
            const auto path=it->path();const auto name=path.filename().string();if(!suffix(name))continue;
            if(name==managed.filename()) {
                if(!managedDirectory){error="FIC sysctl file shadowed by higher priority directory";return false;}
                continue; // planned /etc FIC file shadows lower same-name files
            }
            if(!names.insert(name).second)continue; // first directory wins, even a /dev/null mask
            struct stat ls{},target{};if(::lstat(path.c_str(),&ls)){error="sysctl topology changed";return false;}
            out[path.string()]=identity(ls);
            if(S_ISLNK(ls.st_mode)) {
                const auto destination=std::filesystem::canonical(path,ec);
                if(ec||::stat(path.c_str(),&target)){error="unproven sysctl symlink: "+path.string();return false;}
                out[path.string()]+="->"+destination.string()+":"+identity(target);
                if(destination=="/dev/null"&&S_ISCHR(target.st_mode))continue;
                if(!directorySafe(destination.parent_path(),error))return false;
            } else target=ls;
            if(!S_ISREG(target.st_mode)||(options_.enforceOwnership&&(target.st_uid!=0||(target.st_mode&0022)))) {error="untrusted sysctl source topology";return false;}
            if(name>managed.filename().string()){error="sysctl file sorts after FIC: "+path.string();return false;}
        }
        if(ec){error="incomplete sysctl inventory";return false;}
    }
    if(!managedDirectory){error="FIC file is outside loader directories";return false;}
    return true;
}
bool SysctlConfiguration::loadManaged(std::string& error) {
    snapshot_.reset();values_.clear();const auto path=options_.platform.managedConfigPath;
    if(path.empty()||!directorySafe(path.parent_path(),error))return false;
    fic::core::SecureStateFileExpectation expect;expect.requireSingleLink=true;
    if(options_.enforceOwnership){expect.owner=0;expect.parentOwner=0;expect.forbiddenMode=0022;}
    const auto read=fic::core::readSecureFileBounded(path,expect,1024*1024);
    if(read.status==fic::core::SecureStateReadStatus::Unprovable){error=read.detail;return false;}
    if(read.status==fic::core::SecureStateReadStatus::Proven){snapshot_=read.targetState;return parse(snapshot_->content,values_,error);}
    return true;
}
bool SysctlConfiguration::load(std::string& error) {topology_.clear();return topology(topology_,error)&&loadManaged(error);}
bool SysctlConfiguration::verifyPriority(std::string& error) const {
    std::map<std::string,std::string> current;
    if(!topology(current,error))return false;
    if(current!=topology_){error="sysctl topology changed during operation";return false;}
    return true;
}
bool SysctlConfiguration::verifyCurrent(std::string& error) const {
    if(snapshot_)return AtomicFileWriter::targetStateMatches(options_.platform.managedConfigPath.string(),*snapshot_,&error);
    struct stat s{};if(::lstat(options_.platform.managedConfigPath.c_str(),&s)==-1&&errno==ENOENT)return true;
    error="FIC sysctl artifact appeared";return false;
}
bool SysctlConfiguration::inspectManagedSettings(const std::string& text,bool& present,std::string& error){std::map<std::string,std::string> values;present=false;if(!parse(text,values,error))return false;present=!values.empty();return true;}
SysctlValueObservation SysctlConfiguration::inspectManagedValue(const std::string& key) const {
    const auto found=values_.find(fic::sysctl::internalKeyToCanonicalPath(key));
    if(found==values_.end())return {};
    return {true,found->second,{options_.platform.managedConfigPath,options_.platform.managedConfigPath.string(),0}};
}
std::string SysctlConfiguration::renderUpdate(const std::map<std::string,std::string>& values) const {
    std::string text;
        if(!snapshot_)text=render(values);
        else {
            std::set<std::string> written;std::size_t begin=0;
            while(begin<snapshot_->content.size()) {
                auto end=snapshot_->content.find('\n',begin);const bool lf=end!=std::string::npos;
                if(!lf)end=snapshot_->content.size();
                const auto physical=snapshot_->content.substr(begin,end-begin);const auto equal=physical.find('=');
                const auto key=equal==std::string::npos?std::string():fic::sysctl::systemdConfigKeyToCanonicalPath(trim(physical.substr(0,equal)));
                if(!key.empty()&&values_.count(key)) {
                    auto value=values.find(key);
                    if(value!=values.end()) {
                        if(value->second==values_.at(key))text+=physical+(lf?"\n":"");
                        else text+=fic::sysctl::configKeyFromCanonicalPath(key)+" = "+value->second+(lf?"\n":"");
                        written.insert(key);
                    }
                } else text+=physical+(lf?"\n":"");
                begin=lf?end+1:end;
            }
            for(const auto& [key,value]:values)if(!written.count(key)) {
                if(!text.empty()&&text.back()!='\n')text+='\n';
                text+=fic::sysctl::configKeyFromCanonicalPath(key)+" = "+value+"\n";
            }
        }
    return text;
}
SysctlOperationResult SysctlConfiguration::publish(const std::map<std::string,std::string>& values,bool deleteEmpty,
    const std::function<bool(const AtomicTargetState&,std::string&)>& beforePublish) {
    SysctlOperationResult result;std::string error;
    if(!verifyCurrent(error)){result.message=error;return result;}
    const auto path=options_.platform.managedConfigPath.string();
    std::optional<AtomicTargetState> published;
    if(values.empty()&&deleteEmpty&&snapshot_) {
        AtomicRemoveResult removed;
        result.ok=AtomicFileWriter::removeIfCurrentState(path,*snapshot_,&error,&removed)&&removed.removed&&removed.durabilityConfirmed&&!removed.preconditionFailed;
        result.changed=removed.removed;result.noEffect=!removed.removed;
    } else {
        const auto text=renderUpdate(values);
        if(snapshot_&&text==snapshot_->content){result.ok=true;result.message="FIC sysctl artifact unchanged";return result;}
        AtomicWriteOptions options;options.createIfMissing=!snapshot_;options.exclusiveCreate=!snapshot_;options.rejectSymlink=true;
        options.expectedTargetState=snapshot_;options.fileMode=0644;options.beforePublish=beforePublish;
        if(options_.enforceOwnership){options.fileOwner=0;options.fileGroup=0;}
        AtomicWriteResult written;result.noEffect=false;
        result.ok=AtomicFileWriter::writeWithResult(path,text,options,&error,&written)&&written.installed&&written.durabilityConfirmed&&written.installedTargetState.has_value();
        published=written.installedTargetState;
        result.changed=written.installed;result.noEffect=!written.installed&&!written.installedTargetState;
    }
    result.message=result.ok?"FIC sysctl persistent ownership updated":error;
    if(result.ok){std::string check;
        const bool unchanged=published?AtomicFileWriter::targetStateMatches(path,*published,&check):!std::filesystem::exists(path);
        if(!unchanged||!loadManaged(check)||values_!=values){result.ok=false;result.noEffect=false;result.message="SYSCTL publication verification failed: "+check;}}
    return result;
}
SysctlOperationResult SysctlConfiguration::ensureManagedValue(const std::string& key,const std::string& value) {
    SysctlOperationResult result;std::string error;
    if(!verifyPriority(error)){result.message=error;return result;}
    const auto current=inspectManagedValue(key);
    if(current.found&&current.value==value) {
        result.ok=verifyCurrent(error);result.message=result.ok?"FIC sysctl value unchanged":error;return result;
    }
    auto values=values_;values[fic::sysctl::internalKeyToCanonicalPath(key)]=value;
    std::map<std::string,std::string> checked;if(!parse(render(values),checked,error)||values!=checked){result.message="invalid SYSCTL target";return result;}
    return publish(values,false);
}
SysctlOperationResult SysctlConfiguration::removeManagedKey(const std::string& key,const std::string& expected,bool deleteEmpty,
    const std::function<bool(const AtomicTargetState&,std::string&)>& beforePublish) {
    SysctlOperationResult result;const auto canonical=fic::sysctl::internalKeyToCanonicalPath(key);auto values=values_;const auto found=values.find(canonical);
    if(found==values.end()) {
        if(values.empty()&&deleteEmpty&&snapshot_)return publish(values,true,beforePublish);
        std::string error;result.ok=confirmDurable(error);
        result.targetMissing=result.ok;result.message=result.ok?"FIC sysctl key durably absent":error;return result;
    }
    if(found->second!=expected){result.conflict=true;result.message="owned SYSCTL assignment drift";return result;}
    values.erase(found);return publish(values,deleteEmpty,beforePublish);
}

bool SysctlConfiguration::confirmDurable(std::string& error) {
        if(snapshot_) {
            const int fd=::open(options_.platform.managedConfigPath.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
            struct stat st{};const bool durable=fd>=0&&::fstat(fd,&st)==0&&st.st_dev==snapshot_->identity.device&&st.st_ino==snapshot_->identity.inode&&::fsync(fd)==0;
            if(fd>=0)::close(fd);
            return durable&&AtomicFileWriter::ensureTargetDurableIfCurrentState(options_.platform.managedConfigPath.string(),*snapshot_,&error);
        } else return AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(options_.platform.managedConfigPath.string(),&error);
}
bool SysctlConfiguration::planRemoval(const std::optional<AtomicTargetState>& before,
    const std::string& key,const std::string& expected,bool deleteEmpty,
    std::optional<AtomicTargetState>& target,std::string& error) {
    target.reset();if(!before)return true;
    SysctlConfiguration config;config.snapshot_=before;
    if(!parse(before->content,config.values_,error))return false;
    const auto canonical=fic::sysctl::internalKeyToCanonicalPath(key);
    const auto found=config.values_.find(canonical);
    if(found!=config.values_.end()&&found->second!=expected){error="owned SYSCTL assignment drift";return false;}
    auto values=config.values_;values.erase(canonical);
    if(values.empty()&&deleteEmpty)return true;
    target=*before;target->identity={};target->content=config.renderUpdate(values);return true;
}
