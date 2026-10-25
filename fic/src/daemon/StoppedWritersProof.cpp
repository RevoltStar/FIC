#include "daemon/StoppedWritersProof.h"
#include <algorithm>
#include <charconv>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <sys/types.h>
namespace fic::daemon {
namespace {
bool pid(const std::string& value) {
    if(value.empty()||(value.size()>1&&value[0]=='0')||value.find_first_not_of("0123456789")!=std::string::npos)return false;
    unsigned long long n=0;const auto result=std::from_chars(value.data(),value.data()+value.size(),n);
    return result.ec==std::errc{}&&result.ptr==value.data()+value.size()&&n<=static_cast<unsigned long long>(std::numeric_limits<pid_t>::max());
}
}
bool inspectWriterUnit(const std::string& unit,const std::string& properties,
                       WriterUnitFacts& facts,std::string& error) {
    facts={};std::map<std::string,std::string> values;std::istringstream input(properties);std::string line;
    while(std::getline(input,line)) {
        const auto separator=line.find('=');
        if(separator==std::string::npos||separator==0||!values.emplace(line.substr(0,separator),line.substr(separator+1)).second) {
            error="untrusted or duplicate systemd property for "+unit;return false;
        }
    }
    if(values.size()!=7){error="unexpected systemd property set for "+unit;return false;}
    for(const auto* name:{"Id","LoadState","ActiveState","SubState","MainPID","ControlPID","Job"})
        if(!values.count(name)){error="missing systemd property "+std::string(name);return false;}
    const std::set<std::string> states{"active","inactive","failed","activating","deactivating","reloading"};
    const bool knownLoad=values["LoadState"]=="loaded"||values["LoadState"]=="masked"||values["LoadState"]=="not-found";
    if(values["Id"]!=unit||!knownLoad||!states.count(values["ActiveState"])||values["SubState"].empty()||
        values["SubState"].size()>128||values["SubState"].find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-")!=std::string::npos||
        !pid(values["MainPID"])||!pid(values["ControlPID"])||(!values["Job"].empty()&&!pid(values["Job"]))) {
        error="unproven systemd unit properties: "+unit;return false;
    }
    facts={values["LoadState"],values["ActiveState"],values["SubState"],values["MainPID"],values["ControlPID"],values["Job"]};
    // systemd retains failed state after a failed ExecStop even when the
    // package removed its unit file. This is distinct from a live/job state;
    // callers still prove empty cgroups and perform the process census.
    const bool stoppedState=(facts.activeState=="inactive"&&facts.subState=="dead")||
                            (facts.activeState=="failed"&&facts.subState=="failed");
    if(facts.loadState=="not-found"&&(!stoppedState||facts.mainPid!="0"||facts.controlPid!="0"||!facts.job.empty())) {
        error="missing unit has inconsistent runtime state";facts={};return false;
    }
    error.clear();return true;
}
bool proveStoppedUnit(const std::string& unit,const std::string& properties,std::string& error) {
    WriterUnitFacts facts;if(!inspectWriterUnit(unit,properties,facts,error))return false;
    const bool inactive=facts.activeState=="inactive"&&facts.subState=="dead";
    const bool failed=facts.activeState=="failed"&&facts.subState=="failed";
    if((!inactive&&!failed)||facts.mainPid!="0"||facts.controlPid!="0"||!facts.job.empty()) {
        error="unit is not proven quiescent: "+unit;return false;
    }
    error.clear();return true;
}
}
