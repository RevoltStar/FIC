#include "daemon/PackageDatabaseSnapshot.h"
#include <fic/core/process/ProcessExecutor.h>
#include <algorithm>
#include <array>
#include <set>
#include <sstream>
namespace fic::daemon {
namespace {
constexpr std::array<const char*,7> names{{"fic","fic-runtime","fic-dick","fic-cli","fic-gui","fic-session-agent","fic-prelogin"}};
bool fail(std::string& error,const char* why){error=why;return false;}
bool validField(const std::string& field,std::size_t maximum) {
    return !field.empty()&&field.size()<=maximum&&std::all_of(field.begin(),field.end(),[](unsigned char c){return c>32&&c<127;});
}
bool parseDpkgStatus(const std::string& text,PackageInstallState& state) {
    std::istringstream fields(text);std::string want,flag,status,extra;
    const std::set<std::string> wants{"unknown","install","hold","deinstall","purge"};
    const std::set<std::string> states{"not-installed","config-files","half-installed","unpacked","half-configured","triggers-awaited","triggers-pending","installed"};
    if(!(fields>>want>>flag>>status)||fields>>extra||!wants.count(want)||
       (flag!="ok"&&flag!="reinstreq")||!states.count(status))return false;
    if(flag!="ok")state=PackageInstallState::Incomplete;
    else if(status=="not-installed")state=PackageInstallState::Absent;
    else if(status=="config-files")state=PackageInstallState::ConfigFiles;
    else if(status=="installed"&&(want=="install"||want=="hold"))state=PackageInstallState::Installed;
    else state=PackageInstallState::Incomplete;
    return true;
}
}
bool parseFicPackageDatabase(fic::platform::PackageManagerKind kind,const std::string& output,
    PackageDatabaseSnapshot& snapshot,std::string& error) {
    snapshot={};
    if((kind!=fic::platform::PackageManagerKind::Dpkg&&kind!=fic::platform::PackageManagerKind::Rpm)||
       output.size()>1024*1024||output.find('\0')!=std::string::npos||(!output.empty()&&output.back()!='\n'))
        return fail(error,"package database output is unknown/oversized/incomplete");
    PackageDatabaseSnapshot parsed;
    std::istringstream lines(output);std::string line;std::size_t rows=0;
    while(std::getline(lines,line)) {
        if(++rows>50000||line.size()>4096)return fail(error,"package database row budget exceeded");
        std::array<std::string,4> fields;std::size_t start=0;
        for(std::size_t i=0;i<fields.size();++i) {
            const auto end=line.find('\t',start);
            if((i<3&&end==std::string::npos)||(i==3&&end!=std::string::npos))return fail(error,"malformed package database row");
            fields[i]=line.substr(start,end==std::string::npos?end:end-start);start=end+1;
        }
        // Debian ${Package} is unqualified. Duplicate multiarch or stale RPM
        // versions of a required FIC package are deliberately not collapsed.
        if(std::find(names.begin(),names.end(),fields[0])==names.end())continue;
        PackageDatabaseEntry entry;
        entry.architecture=fields[3];
        if(kind==fic::platform::PackageManagerKind::Dpkg) {
            if(!parseDpkgStatus(fields[1],entry.state))return fail(error,"unknown dpkg FIC package state");
            if(!validField(fields[3],64)&&!(fields[3].empty()&&entry.state==PackageInstallState::Absent))
                return fail(error,"unproven FIC package architecture");
            if(!validField(fields[2],128)&&!(fields[2].empty()&&entry.state==PackageInstallState::Absent))
                return fail(error,"unproven dpkg FIC package version");
            entry.version=fields[2];
        } else {
            if(!validField(fields[3],64))return fail(error,"unproven FIC package architecture");
            const auto epoch=fields[1]=="(none)"?"0":fields[1];
            if(epoch.empty()||epoch.size()>20||epoch.find_first_not_of("0123456789")!=std::string::npos||
                (epoch.size()>1&&epoch.front()=='0')||!validField(fields[2],107))return fail(error,"unproven RPM FIC package EVR");
            entry.state=PackageInstallState::Installed;entry.version=epoch+":"+fields[2];
        }
        if(!parsed.packages.emplace(fields[0],std::move(entry)).second)return fail(error,"duplicate FIC package identities/versions");
    }
    snapshot=std::move(parsed);error.clear();return true;
}
bool proveRuntimePackagePrerequisite(const PackageDatabaseSnapshot& snapshot,
    const std::string& expectedVersion,std::string& error) {
    const auto runtime=snapshot.packages.find("fic-runtime");
    if(!validField(expectedVersion,128)||runtime==snapshot.packages.end()||
        runtime->second.state!=PackageInstallState::Installed||runtime->second.version!=expectedVersion) {
        error="configured exact-version fic-runtime prerequisite is unproven";return false;
    }
    error.clear();return true;
}
bool PackageDatabaseReader::observeRuntimePrerequisite(const std::string& expectedVersion,std::chrono::steady_clock::time_point deadline,
    std::size_t& budget,std::string& error) const {
    if(!validField(expectedVersion,128))
        return fail(error,"runtime prerequisite observation requires exact version");
    PackageDatabaseSnapshot snapshot;
    return query(deadline,budget,snapshot,error)&&proveRuntimePackagePrerequisite(snapshot,expectedVersion,error);
}
bool PackageDatabaseReader::read(const PackageManagerTransactionLock& locks,
    std::chrono::steady_clock::time_point deadline,std::size_t& budget,
    PackageDatabaseSnapshot& snapshot,std::string& error) const {
    snapshot={};
    if(!locks.covers(kind_))return fail(error,"package database manager differs from held transaction locks");
    if(!locks.revalidate(error))return false;
    if(!query(deadline,budget,snapshot,error))return false;
    if(!locks.revalidate(error)){snapshot={};return false;}
    return true;
}
bool PackageDatabaseReader::query(std::chrono::steady_clock::time_point deadline,std::size_t& budget,
    PackageDatabaseSnapshot& snapshot,std::string& error) const {
    snapshot={};
    const auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now());
    if(remaining.count()<=0||budget==0)return fail(error,"package proof deadline/output budget exhausted");
    if(kind_!=fic::platform::PackageManagerKind::Dpkg&&kind_!=fic::platform::PackageManagerKind::Rpm)
        return fail(error,"unknown package manager");
    std::filesystem::path query;
    if(!executables_.resolve(fic::platform::ExecutableId::PackageQuery,query,error))return false;
    ProcessOptions options;options.clearEnvironment=true;options.environment={{"LANG","C"},{"LC_ALL","C"}};
    options.timeout=std::min(remaining,std::chrono::milliseconds(5000));options.maxOutputBytes=std::min<std::size_t>(budget,1024*1024);
    const std::vector<std::string> args=kind_==fic::platform::PackageManagerKind::Dpkg?
        std::vector<std::string>{"--show","--showformat=${Package}\t${Status}\t${Version}\t${Architecture}\n","fic*"}:
        std::vector<std::string>{"-qa","--queryformat","%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"};
    const auto result=ProcessExecutor::execute(query,args,options);
    const auto captured=result.standardOutput.size()+result.standardError.size();
    if(captured>budget){budget=0;return fail(error,"package database query output budget exceeded");}
    budget-=captured;
    if(!result.success()) {error="package database query failed: "+result.error+" "+result.standardError;return false;}
    if(std::chrono::steady_clock::now()>=deadline)return fail(error,"package database proof deadline exceeded");
    return parseFicPackageDatabase(kind_,result.standardOutput,snapshot,error);
}
}
