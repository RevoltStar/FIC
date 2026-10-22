#ifndef FIC_STOPPED_WRITERS_PROOF_H
#define FIC_STOPPED_WRITERS_PROOF_H
#include <string>
namespace fic::daemon {
struct WriterUnitFacts {
    std::string loadState,activeState,subState,mainPid,controlPid,job;
};
// Only output of a successful manager query. Empty/duplicate/unknown responses
// are never projected to inactive. This does not prove cgroups/manual processes.
bool inspectWriterUnit(const std::string& unit,const std::string& properties,
                       WriterUnitFacts&,std::string& error);
bool proveStoppedUnit(const std::string& unit,const std::string& properties,std::string& error);
}
#endif
