#include "daemon/UninstallOverride.h"
#include <fic/core/fs/RootControlledDirectory.h>
#include <fic/core/fs/SecureStateFile.h>
#include <set>
#include <sstream>
#include <unistd.h>
namespace fic::daemon {
namespace {
std::string trim(const std::string& text) {
    const auto begin=text.find_first_not_of(" \t\r");
    if(begin==std::string::npos)return {};
    return text.substr(begin,text.find_last_not_of(" \t\r")-begin+1);
}
bool requirement(const std::string& value,UninstallRequirement& result) {
    if(value=="TRUE")result=UninstallRequirement::Required;
    else if(value=="FALSE")result=UninstallRequirement::BestEffort;
    else if(value=="SKIP")result=UninstallRequirement::Skip;
    else return false;
    return true;
}
}
bool readUninstallOverride(UninstallOverride& result,std::string& error,const std::filesystem::path& file) {
    // Do not partially publish a permissive value after a later parse failure.
    result={};UninstallOverride candidate;
    const int parent=fic::core::openRootControlledDirectory(file.parent_path(),error);
    if(parent<0)return false;
    ::close(parent);
    fic::core::SecureStateFileExpectation expected;
    expected.owner=0;expected.parentOwner=0;expected.forbiddenMode=0022;
    expected.requireSingleLink=true;expected.maxSize=4096;
    const auto read=fic::core::readSecureStateFile(file,expected);
    if(read.status==fic::core::SecureStateReadStatus::Missing){error.clear();return true;}
    if(read.status!=fic::core::SecureStateReadStatus::Proven){error="unsafe uninstall override: "+read.detail;return false;}
    candidate.present=true;
    std::set<std::string> keys;std::istringstream lines(read.content);std::string line;
    while(std::getline(lines,line)) {
        line=trim(line);if(line.empty()||line.front()=='#')continue;
        const auto separator=line.find('=');
        if(separator==std::string::npos){error="uninstall override requires KEY=VALUE";return false;}
        const auto key=trim(line.substr(0,separator)),value=trim(line.substr(separator+1));
        if(!keys.insert(key).second){error="duplicate uninstall override key: "+key;return false;}
        bool valid=false;
        if(key=="ROLLBACK_TYPE") {
            valid=true;
            if(value=="STANDARD")candidate.rollback=UninstallRollbackMode::Standard;
            else if(value=="IGNORE_ERROR")candidate.rollback=UninstallRollbackMode::IgnoreError;
            else if(value=="SKIP")candidate.rollback=UninstallRollbackMode::Skip;
            else valid=false;
        } else if(key=="FIC_REQUIRED_UNINSTALL_STATUS")valid=requirement(value,candidate.prepare);
        else if(key=="FIC_REQUIRED_STOP")valid=requirement(value,candidate.stop);
        else {error="unknown uninstall override key: "+key;return false;}
        if(!valid){error="invalid uninstall override value for "+key;return false;}
    }
    if(!lines.eof()){error="cannot parse uninstall override";return false;}
    result=candidate;error.clear();return true;
}
}
