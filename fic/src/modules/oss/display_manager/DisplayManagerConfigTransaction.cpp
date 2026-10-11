#include "modules/oss/display_manager/DisplayManagerConfigTransaction.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/process/ExclusivePidLock.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <glib.h>
#include <QString>
#include <QTemporaryFile>
#include <QDir>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

using namespace fic::rollback;
using fic::platform::ExecutableId;
namespace {
const PolicyRef owner{"OSS","DisplayManager","disable_autologin"};
std::string trim(const std::string& s) { return QString::fromUtf8(s.data(),static_cast<int>(s.size())).trimmed().toStdString(); }
// GDM on ALT is compiled with /var/run. Only its read-only runtime input
// permits the standard root-owned /var/run -> /run alias, re-proved each time.
// Mutation targets and all other symlink ancestors remain forbidden.
bool nativeRuntimeAlias(const std::filesystem::path& path,std::string& error) {
    if(path.string().compare(0,9,"/var/run/")!=0)return true;
    struct stat parent{},alias{},target{};
    if(::lstat("/var",&parent)!=0 || !S_ISDIR(parent.st_mode) || parent.st_uid!=0 || (parent.st_mode&0022)) {
        error="unsafe GDM runtime parent";return false;
    }
    if(::lstat("/var/run",&alias)!=0) {
        if(errno==ENOENT)return true;error="cannot inspect GDM runtime alias";return false;
    }
    if(S_ISDIR(alias.st_mode)&&alias.st_uid==0&&!(alias.st_mode&0022))return true;
    std::error_code ec;auto link=std::filesystem::read_symlink("/var/run",ec);
    if(!ec&&!link.is_absolute())link=std::filesystem::path("/var")/link;
    if(ec||!S_ISLNK(alias.st_mode)||alias.st_uid!=0||link.lexically_normal()!="/run" ||
        ::lstat("/run",&target)!=0||!S_ISDIR(target.st_mode)||target.st_uid!=0||(target.st_mode&0022)) {
        error="unproven GDM /var/run alias";return false;
    }
    return true;
}
bool secureAncestors(const std::filesystem::path& path, std::string& error,bool runtimeAlias=false) {
    auto current = path.parent_path();
    while (!current.empty()) {
        struct stat st{};
        if(runtimeAlias && current=="/var/run" && ::lstat(current.c_str(),&st)==0 && S_ISLNK(st.st_mode)) {
            if(!nativeRuntimeAlias(path,error))return false;
            current=current.parent_path();continue;
        }
        if (::lstat(current.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
            (st.st_mode & 0022) && !(st.st_mode & S_ISVTX)) { error="unsafe/missing DM parent: " + current.string(); return false; }
        if (current == current.root_path()) break; current=current.parent_path();
    }
    return true;
}
struct File {
    std::filesystem::path path;
    bool exists=false;
    AtomicTargetState state;
};
bool capture(const std::filesystem::path& path, File& file, std::string& error,bool runtimeAlias=false) {
    file.path=path;
    struct stat st{};
    if (::lstat(path.c_str(), &st) != 0) {
        if (errno==ENOENT) { file.exists=false; return true; }
        error="cannot inspect DM file: " + path.string(); return false;
    }
    if (!secureAncestors(path,error,runtimeAlias) || !AtomicFileWriter::captureTargetState(path.string(),file.state,&error) ||
        file.state.owner != 0 || (file.state.mode & 0022) || file.state.content.size() > 1024*1024 ||
        file.state.content.find('\0') != std::string::npos) { error="unsafe DM file: " + path.string() + ": " + error; return false; }
    file.exists=true; return true;
}
bool proof(const File& f, std::string& error) {
    if (f.exists) return AtomicFileWriter::targetStateMatches(f.path.string(),f.state,&error);
    struct stat st{};
    if (::lstat(f.path.c_str(), &st)==0 || errno!=ENOENT) { error="DM input appeared: " + f.path.string(); return false; }
    return true;
}
std::vector<std::string> sections(const std::string& text) {
    std::set<std::string> names{"Seat:*"}; std::istringstream in(text); std::string line;
    while (std::getline(in,line)) {
        line=trim(line);
        if (line.size()>2 && line.front()=='[' && line.back()==']') {
            auto name=line.substr(1,line.size()-2);
            if (name=="SeatDefaults" || name.compare(0,5,"Seat:")==0) names.insert(name);
        }
    }
    return {names.begin(),names.end()};
}
// SDDM ConfigReader::loadInternal (0.19-0.21) uses QString trimming,
// strips # comments and merges repeated sections/keys in traversal order.
// QSettings is deliberately NOT used: SDDM's reader has different semantics.
std::string sddmUser(const std::string& text) {
    std::string group, user; std::istringstream in(text); std::string raw;
    while (std::getline(in,raw)) {
        auto q=QString::fromUtf8(raw.data(),static_cast<int>(raw.size()));
        auto hash=q.indexOf('#'); if(hash>=0) q=q.left(hash); q=q.trimmed();
        const auto equal=q.indexOf('=');
        if(equal>=0) { if(group=="Autologin" && q.left(equal).trimmed()=="User") user=q.mid(equal+1).trimmed().toStdString(); }
        else if(q.startsWith('[') && q.endsWith(']')) group=q.mid(1,q.size()-2).toStdString();
    }
    return user;
}
bool gdmFlags(const std::string& text, std::map<std::string,bool>& flags, std::string& error) {
    if(text.empty()) return true;
    GKeyFile* key=g_key_file_new(); GError* failure=nullptr;
    if(!g_key_file_load_from_data(key,text.data(),text.size(),G_KEY_FILE_NONE,&failure)) {
        error="GDM native GKeyFile parse failed: " + std::string(failure?failure->message:"");
        if(failure) g_error_free(failure); g_key_file_free(key); return false;
    }
    for(const auto* name:{"AutomaticLoginEnable","TimedLoginEnable"}) {
        if(!g_key_file_has_key(key,"daemon",name,nullptr)) continue;
        const bool enabled=g_key_file_get_boolean(key,"daemon",name,&failure);
        if(failure) {error="GDM invalid enabling flag";g_error_free(failure);g_key_file_free(key);return false;}
        flags[name]=enabled;
    }
    g_key_file_free(key); return true;
}
}
struct DisplayManagerConfigTransaction::Plan {
    std::string manager;
    bool enforce=false, noop=false, deleteFile=false, detach=false;
    File main, runtime;
    std::vector<File> inputs;
    std::map<std::filesystem::path, std::vector<std::filesystem::path>> directories;
    std::optional<MutationRecord> record;
    UndoRemoveDisplayManagerBlock payload;
    std::string target;
};
DisplayManagerConfigTransaction::DisplayManagerConfigTransaction(
    const fic::platform::PlatformExecutableResolver& executables, fic::platform::DisplayManagerPlatformConfig config)
    : DisplayManagerConfigTransaction([&executables](ExecutableId id,const std::vector<std::string>& args){
        std::filesystem::path path;std::string error;
        if(!executables.resolve(id,path,error)) {ProcessResult r;r.error=error;return r;}
        ProcessOptions options;options.clearEnvironment=true;
        options.environment={{"LC_ALL","C"},{"PATH","/usr/sbin:/usr/bin:/sbin:/bin"}};
        return ProcessExecutor::execute(path.string(),args,options);
    },std::move(config),fic::core::FicRuntimePaths::isInitialized() ? (fic::core::FicRuntimePaths::get().runtimeDir / "display-manager-config.lock").string() : std::string()) {}
DisplayManagerConfigTransaction::DisplayManagerConfigTransaction(Run run,
    fic::platform::DisplayManagerPlatformConfig config,std::string lockPath)
    :run_(std::move(run)),config_(std::move(config)),lockPath_(std::move(lockPath)) {}
std::string DisplayManagerConfigTransaction::block(const MutationRecord& record) {
    const auto& p=std::get<UndoRemoveDisplayManagerBlock>(record.undo.payload);
    std::string body;
    if(p.manager=="SDDM") body="[Autologin]\nUser=\n";
    if(p.manager=="GDM") body="[daemon]\nAutomaticLoginEnable=false\nTimedLoginEnable=false\n";
    if(p.manager=="LIGHTDM") for(const auto& seat:p.seats) body+="["+seat+"]\nautologin-user=\nautologin-guest=false\n";
    return p.separator+"# FIC-DM BEGIN "+std::to_string(record.id)+" "+p.manager+"\n"+body+
        "# FIC-DM END "+std::to_string(record.id)+" "+p.manager+"\n";
}
bool DisplayManagerConfigTransaction::verify(const Plan& p,const std::string& content,bool disabled,std::string& error,bool currentState) const {
    if(p.manager=="SDDM") {
        const auto args = config_.packageManagerKind == fic::platform::PackageManagerKind::Dpkg
            ? std::vector<std::string>{"--show", "--showformat=${db:Status-Status} ${Version}\n", "sddm"}
            : std::vector<std::string>{"-q", "--qf", "%{VERSION}\n", "sddm"};
        const auto version=run_(ExecutableId::PackageQuery,args);
        auto nativeVersion=trim(version.standardOutput);
        if(config_.packageManagerKind == fic::platform::PackageManagerKind::Dpkg) {
            if(nativeVersion.compare(0,10,"installed ")!=0) {error="SDDM package is not installed";return false;}
            nativeVersion=nativeVersion.substr(10);
        }
        auto epoch=nativeVersion.find(':');if(epoch!=std::string::npos)nativeVersion=nativeVersion.substr(epoch+1);
        if(!version.success() || (nativeVersion.compare(0,5,"0.19.")!=0 && nativeVersion.compare(0,5,"0.20.")!=0 &&
            nativeVersion.compare(0,5,"0.21.")!=0)) {error="unverified SDDM native parser version";return false;}
        // Main file is last in the supported native source contract; no
        // drop-in ordering assumption is needed for its explicit empty User.
        if(disabled && sddmUser(content)!="") {error="SDDM effective Autologin/User is not empty";return false;}
        return true;
    }
    if(p.manager=="GDM") {
        const auto version=run_(ExecutableId::Gdm,{"--version"});
        if(!version.success()) {error="GDM native version query failed";return false;}
        std::map<std::string,bool> flags;
        if(!gdmFlags(content,flags,error) || (p.runtime.exists && !gdmFlags(p.runtime.state.content,flags,error))) return false;
        if(disabled && (flags["AutomaticLoginEnable"] || flags["TimedLoginEnable"])) {error="GDM runtime/primary enabling flag defeats autologin prohibition";return false;}
        return true;
    }
    QTemporaryFile temporary(QDir::tempPath()+"/fic-dm-inspect-XXXXXX");
    std::string staged;
    // --config selects a custom primary and can omit native site drop-ins.
    // Preview therefore supplies their complete captured contents explicitly;
    // physical verification uses the native default search, without --config.
    for(const auto& input:p.inputs) {staged+=input.state.content;if(!staged.empty()&&staged.back()!='\n')staged+='\n';}
    staged+=content;
    if(!temporary.open() || temporary.write(staged.data(),static_cast<qint64>(staged.size())) != static_cast<qint64>(staged.size()) || !temporary.flush()) {
        error="cannot stage LightDM native inspection";return false;
    }
    const auto args=currentState?std::vector<std::string>{"--show-config"}:std::vector<std::string>{"--show-config","--config="+temporary.fileName().toStdString()};
    const auto native=run_(ExecutableId::LightDm,args);
    if(!native.success()) {error="LightDM native --show-config failed: "+native.error+native.standardError;return false;}
    // show-config prefixes each assignment with its source letter(s).
    std::istringstream in(native.standardOutput+"\n"+native.standardError);std::string line,group;
    std::map<std::string,std::map<std::string,std::string>> seats;
    while(std::getline(in,line)) {
        line=trim(line);auto bracket=line.find('[');
        if(bracket!=std::string::npos && line.back()==']') {group=line.substr(bracket+1,line.size()-bracket-2);continue;}
        auto equal=line.find('=');if(equal==std::string::npos) continue;
        auto key=trim(line.substr(0,equal)); auto space=key.find_last_of(" \t");if(space!=std::string::npos) key=key.substr(space+1);
        if(group=="SeatDefaults" || group.compare(0,5,"Seat:")==0) seats[group][key]=trim(line.substr(equal+1));
    }
    if(seats.empty()) {error="LightDM native seat inventory is empty/unclassifiable";return false;}
    if(disabled) for(const auto& [seat,values]:seats) {
        auto user=values.find("autologin-user"),guest=values.find("autologin-guest");
        if((user!=values.end() && !user->second.empty()) || (guest!=values.end() && guest->second!="false")) {
            error="LightDM native autologin remains enabled for "+seat;return false;
        }
    }
    return true;
}
bool DisplayManagerConfigTransaction::plan(const std::string& manager,bool enforce,MutationJournal& journal,Plan& p,std::string& error) const {
    p={};p.manager=manager;p.enforce=enforce;p.payload.manager=manager;
    if(!journal.usable()) {error="DM journal unavailable";return false;}
    if(manager!="SDDM" && manager!="GDM" && manager!="LIGHTDM") {error="unknown DM route";return false;}
    for(const auto& r:journal.records()) if(r.isActive() && r.undo.backend==MutationBackend::DisplayManager && r.resource=="DM/"+manager+"/autologin") {
        if(p.record) {error="duplicate DM ownership";return false;} p.record=r;p.payload=std::get<UndoRemoveDisplayManagerBlock>(r.undo.payload);
    }
    std::filesystem::path path;
    if(manager=="SDDM") path=config_.sddmConfigPath;
    if(manager=="LIGHTDM") path=config_.lightDmConfigPath;
    if(manager=="GDM") {
        if(config_.gdmConfigCandidates.empty() || p.payload.route>=config_.gdmConfigCandidates.size()) {error="GDM trusted route unavailable";return false;}
        // Profile primary is the native package's compiled path. Alternate
        // files are inventoried but never guessed as replacement primaries.
        path=config_.gdmConfigCandidates[p.payload.route];
        for(unsigned i=0;i<config_.gdmConfigCandidates.size();++i) if(i!=p.payload.route) {
            File f;if(!capture(config_.gdmConfigCandidates[i],f,error))return false;p.inputs.push_back(f);
        }
        if(!nativeRuntimeAlias(config_.gdmRuntimeConfigPath,error) || !capture(config_.gdmRuntimeConfigPath,p.runtime,error,true))return false;
    }
    if(!capture(path,p.main,error))return false;
    const auto& dirs=manager=="SDDM"?config_.sddmConfigDirectories:config_.lightDmConfigDirectories;
    if(manager!="GDM") for(const auto& dir:dirs) {
        struct stat st{};
        if(::lstat(dir.c_str(),&st)!=0) {if(errno==ENOENT) {p.directories[dir]={};continue;}error="DM directory read failed";return false;}
        if(!S_ISDIR(st.st_mode) || st.st_uid!=0 || (st.st_mode&0022) || !secureAncestors(dir/"placeholder",error)) {error="unsafe DM config directory";return false;}
        std::vector<std::filesystem::path> names;std::error_code ec;
        for(std::filesystem::directory_iterator it(dir,ec),end;!ec && it!=end;it.increment(ec)) {
            if(manager=="LIGHTDM" && it->path().extension()!=".conf") continue;
            names.push_back(it->path());
        }
        if(ec){error=ec.message();return false;}std::sort(names.begin(),names.end());p.directories[dir]=names;
        for(const auto& name:names){File f;if(!capture(name,f,error))return false;if(!f.exists){error="DM input disappeared";return false;}p.inputs.push_back(f);}
    }
    std::set<std::string> nativeSeats;
    if(manager=="LIGHTDM" && enforce) {
        const auto inspection=run_(ExecutableId::LightDm,{"--show-config"});
        if(!inspection.success()){error="LightDM native source inventory failed";return false;}
        const auto text=inspection.standardOutput+"\n"+inspection.standardError;
        for(const auto& seat:sections(text))nativeSeats.insert(seat);
        bool sourceList=false;std::istringstream rows(text);std::string line;
        while(std::getline(rows,line)) {
            line=trim(line);if(line=="Sources:"){sourceList=true;continue;}
            if(!sourceList||line.empty())continue;
            const auto slash=line.find('/');if(slash==std::string::npos){error="LightDM source inventory is unclassifiable";return false;}
            const std::filesystem::path source=trim(line.substr(slash));
            bool trusted=source==p.main.path;
            for(const auto& dir:config_.lightDmConfigDirectories)trusted=trusted||source.parent_path()==dir;
            if(!trusted||source.lexically_normal()!=source){error="unproven LightDM native source route: "+source.string();return false;}
        }
    }
    for(const auto& input:p.inputs) if(input.state.content.find("# FIC-DM")!=std::string::npos) {error="orphan DM block in an unowned input route";return false;}
    if(enforce && p.record && p.payload.phase=="release") {error="pending DM release must finish before re-enrollment";return false;}
    std::string content=p.main.exists?p.main.state.content:"";
    if(p.record) {
        auto owned=block(*p.record);auto at=content.find(owned);
        if(at==std::string::npos) {
            if(content.find("# FIC-DM")!=std::string::npos || (p.payload.hadApplied && p.payload.phase!="release")) {error="DM owned block missing/changed/ID mismatch";return false;}
            if(p.payload.phase=="release") {p.noop=true;p.target=content;return true;}
            if(!enforce) { p.payload.phase="release"; p.noop=true; p.target=content; return true; }
            // fresh Prepared before publication: still require no orphan.
        } else {
            auto remainder=content;
            // An inserted separator becomes necessary for foreign appended
            // sections. Transfer that newline rather than concatenate them
            // with a formerly unterminated administrator line.
            if(!p.payload.separator.empty() && at+owned.size()<content.size())
                remainder.erase(at+p.payload.separator.size(),owned.size()-p.payload.separator.size());
            else remainder.erase(at,owned.size());
            if(remainder.find("# FIC-DM")!=std::string::npos) {error="orphan/duplicate DM block";return false;}
            if(p.payload.phase=="release" && enforce) {error="pending DM release must finish before re-enrollment";return false;}
            if(!enforce) {p.target=remainder;p.deleteFile=p.payload.createdFile && remainder.empty() &&
                (!p.payload.hadApplied || (p.payload.creationDevice==p.main.state.identity.device && p.payload.creationInode==p.main.state.identity.inode));
                p.detach=p.payload.createdFile && !p.deleteFile;return true;}
            p.target=content;
        }
    } else {
        if(content.find("# FIC-DM")!=std::string::npos) {error="orphan DM block without journal";return false;}
        if(!enforce) {p.noop=true;p.target=content;return true;}
        p.payload.createdFile=!p.main.exists;
        p.payload.separator=!content.empty() && content.back()!='\n'?"\n":"";
        if(manager=="LIGHTDM") {
            std::set<std::string> names=nativeSeats;for(const auto& name:sections(content))names.insert(name);
            for(const auto& f:p.inputs)for(const auto& name:sections(f.state.content))names.insert(name);
            p.payload.seats={names.begin(),names.end()};
        }
    }
    if(enforce) {
        if(!secureAncestors(path,error)) return false;
        if(!p.record || content.find(block(*p.record))==std::string::npos) {
            MutationRecord preview;preview.id=p.record?p.record->id:1;preview.undo={MutationBackend::DisplayManager,p.payload};
            p.target=content+block(preview);
        }
        if(manager=="LIGHTDM" && p.record) {
            std::set<std::string> names=nativeSeats;for(const auto& f:p.inputs)for(const auto& name:sections(f.state.content))names.insert(name);
            for(const auto& name:sections(content))names.insert(name);
            for(const auto& name:names) if(std::find(p.payload.seats.begin(),p.payload.seats.end(),name)==p.payload.seats.end()) {error="new LightDM seat requires ownership-safe release/re-enrollment";return false;}
        }
        MutationRecord proposal;proposal.policy=owner;proposal.resource="DM/"+manager+"/autologin";proposal.undo={MutationBackend::DisplayManager,p.payload};
        if(!validateDisplayManagerMutationRecord(proposal,error))return false;
        return verify(p,p.target,true,error);
    }
    p.target=content;return true;
}
bool DisplayManagerConfigTransaction::preflight(const std::string& manager,bool enforce,MutationJournal& journal,std::string& error) const {
    ExclusivePidLock lock(lockPath_,"",false);if(!lock.tryAcquire()){error="DM config lock unavailable";return false;}
    Plan p;
    bool pendingRelease=false;
    for(const auto& record:journal.records()) if(record.isActive() && record.undo.backend==MutationBackend::DisplayManager &&
        record.resource=="DM/"+manager+"/autologin" && std::get<UndoRemoveDisplayManagerBlock>(record.undo.payload).phase=="release") pendingRelease=true;
    if(enforce && pendingRelease) {
        if(!plan(manager,false,journal,p,error))return false;
        UndoRemoveDisplayManagerBlock fresh;
        fresh.manager=manager;fresh.route=p.payload.route;
        fresh.separator=!p.target.empty() && p.target.back()!='\n'?"\n":"";
        if(manager=="LIGHTDM") {
            std::set<std::string> names;for(const auto& seat:sections(p.target))names.insert(seat);
            for(const auto& input:p.inputs)for(const auto& seat:sections(input.state.content))names.insert(seat);
            fresh.seats={names.begin(),names.end()};
        }
        MutationRecord preview;preview.id=1;preview.undo={MutationBackend::DisplayManager,fresh};
        return verify(p,p.target+block(preview),true,error);
    }
    return plan(manager,enforce,journal,p,error);
}
bool DisplayManagerConfigTransaction::proveInputs(const Plan& p,std::string& error) const {
        for(const auto& f:p.inputs)if(!proof(f,error))return false;
        if(p.manager=="GDM" && (!nativeRuntimeAlias(p.runtime.path,error)||!proof(p.runtime,error)))return false;
        for(const auto& [dir,names]:p.directories) {
            struct stat st{};if(::lstat(dir.c_str(),&st)!=0){if(errno==ENOENT && names.empty())continue;error="DM source directory disappeared";return false;}
            if(!S_ISDIR(st.st_mode)||st.st_uid!=0||(st.st_mode&0022)){error="unsafe changed DM source directory";return false;}
            std::vector<std::filesystem::path> current;std::error_code ec;
            for(std::filesystem::directory_iterator it(dir,ec),end;!ec&&it!=end;it.increment(ec)) {
                if(p.manager=="LIGHTDM"&&it->path().extension()!=".conf")continue;current.push_back(it->path());
            }
            std::sort(current.begin(),current.end());if(ec||current!=names){error="DM source membership changed";return false;}
        }return true;
}
bool DisplayManagerConfigTransaction::runPlan(Plan& p,MutationJournal& journal,std::string& error) const {
    const auto proveInputs=[&](){return this->proveInputs(p,error);};
    if(!proveInputs())return false;
    if(p.noop) {
        if(p.record && p.payload.phase=="release") {
            if(!AtomicFileWriter::fsyncParentDirectoryForPath(p.main.path.string(),&error))return false;
            return journal.setStatus(p.record->id, p.payload.createdFile && p.main.exists?MutationStatus::Detached:MutationStatus::RolledBack,error);
        }return true;
    }
    MutationRecord r;
    if(p.record)r=*p.record;
    r.status=MutationStatus::Prepared;
    r.policy=owner;r.resource="DM/"+p.manager+"/autologin";
    p.payload.phase=p.enforce?"ensure":"release";r.undo={MutationBackend::DisplayManager,p.payload};
    MutationId id=0;if(!journal.prepareMutation(r,id,error))return false;r.id=id;
    if(p.enforce && !p.record) p.target=(p.main.exists?p.main.state.content:"")+block(r);
    if(!proof(p.main,error)||!proveInputs())return false;
    if(p.deleteFile) {
        AtomicRemoveResult removed;
        if(!AtomicFileWriter::removeIfCurrentState(p.main.path.string(),p.main.state,&error,&removed) ||
            !removed.removed || !removed.durabilityConfirmed)return false;
    } else if(!p.main.exists || p.target!=p.main.state.content) {
        AtomicWriteOptions opts;opts.rejectSymlink=true;opts.createIfMissing=!p.main.exists;opts.exclusiveCreate=!p.main.exists;
        opts.fileMode=0644;opts.fileOwner=0;opts.fileGroup=0;
        if(p.main.exists)opts.expectedTargetState=p.main.state;
        AtomicWriteResult result;
        if(!AtomicFileWriter::writeWithResult(p.main.path.string(),p.target,opts,&error,&result)||!result.durabilityConfirmed)return false;
    }
    File after;if(!capture(p.main.path,after,error))return false;
    if((p.deleteFile && after.exists)||(!p.deleteFile&&(!after.exists||after.state.content!=p.target))) {error="DM publication drift";return false;}
    if(!proveInputs())return false;
    if(p.enforce && !verify(p,p.target,true,error,true))return false;
    if(after.exists) {if(!AtomicFileWriter::ensureTargetDurableIfCurrentState(after.path.string(),after.state,&error))return false;}
    else if(!AtomicFileWriter::fsyncParentDirectoryForPath(after.path.string(),&error))return false;
    if(!proveInputs()||!proof(after,error))return false;
    if(p.enforce) {
        if(p.payload.createdFile && !p.payload.hadApplied) {p.payload.creationDevice=after.state.identity.device;p.payload.creationInode=after.state.identity.inode;}
        p.payload.hadApplied=true;r.undo={MutationBackend::DisplayManager,p.payload};
        if(!journal.prepareMutation(r,id,error))return false;
        return journal.setStatus(id,MutationStatus::Applied,error);
    }
    return journal.setStatus(id,p.detach?MutationStatus::Detached:MutationStatus::RolledBack,error);
}
bool DisplayManagerConfigTransaction::reconcile(const std::string& manager,bool enforce,MutationJournal& journal,std::string& error) const {
    ExclusivePidLock lock(lockPath_,"",false);if(!lock.tryAcquire()){error="DM config lock unavailable";return false;}
    if(enforce) for(const auto& record:journal.records()) if(record.isActive() && record.undo.backend==MutationBackend::DisplayManager &&
        record.resource=="DM/"+manager+"/autologin" && std::get<UndoRemoveDisplayManagerBlock>(record.undo.payload).phase=="release") {
        Plan release;if(!plan(manager,false,journal,release,error)||!runPlan(release,journal,error))return false;break;
    }
    Plan p;if(!plan(manager,enforce,journal,p,error))return false;
    return runPlan(p,journal,error);
}
bool DisplayManagerConfigTransaction::verifyApplied(const std::string& manager,MutationJournal& journal,std::string& error) const {
    ExclusivePidLock lock(lockPath_,"",false);if(!lock.tryAcquire()){error="DM config lock unavailable";return false;}
    Plan p;if(!plan(manager,true,journal,p,error))return false;
    if(!p.record || p.record->status!=MutationStatus::Applied || !p.main.exists ||
        p.main.state.content.find(block(*p.record))==std::string::npos) {error="DM current state is not durably enrolled and Applied";return false;}
    return verify(p,p.main.state.content,true,error,true) && proof(p.main,error) && proveInputs(p,error);
}
bool DisplayManagerConfigTransaction::verifyReleased(const std::string& manager,MutationJournal& journal,std::string& error) const {
    ExclusivePidLock lock(lockPath_,"",false);if(!lock.tryAcquire()){error="DM config lock unavailable";return false;}
    Plan p;if(!plan(manager,false,journal,p,error))return false;
    if(p.record){error="DM ownership release is not durably resolved";return false;}
    return proof(p.main,error) && proveInputs(p,error);
}
bool DisplayManagerConfigTransaction::releaseAll(MutationJournal& journal,std::string& error,bool preview) const {
    // Fixed routes are inspected even without active records: an orphan must
    // block erase rather than silently leave a false successful release.
    ExclusivePidLock lock(lockPath_,"",false);if(!lock.tryAcquire()){error="DM config lock unavailable";return false;}
    std::vector<Plan> plans;
    for(const auto* dm:{"SDDM","GDM","LIGHTDM"}) {Plan p;if(!plan(dm,false,journal,p,error))return false;plans.push_back(std::move(p));}
    if(preview)return true;
    for(auto& p:plans)if(!runPlan(p,journal,error))return false;
    for(const auto* dm:{"SDDM","GDM","LIGHTDM"}) {Plan p;if(!plan(dm,false,journal,p,error))return false;if(p.record){error="DM release retains active ownership";return false;}}
    return true;
}
