#ifndef FIC_PACKAGE_UNIT_MASKS_H
#define FIC_PACKAGE_UNIT_MASKS_H
#include "daemon/DaemonInstanceLock.h"
#include <filesystem>
#include <string>
namespace fic::daemon {
// Immutable pre-mutation provenance for the fixed FIC writer units.
// A unique root-private artifact identifies our masks after crash; foreign
// /dev/null or empty-file masks are preserved. Custom units are not overwritten.
class PackageUnitMasks {
public:
    PackageUnitMasks(std::filesystem::path stateDirectory,std::filesystem::path systemUnitDirectory)
        : state_(std::move(stateDirectory)),units_(std::move(systemUnitDirectory)) {}
    bool prepare(const DaemonInstanceLock&,const std::string& operationId,std::string& error);
    bool publish(const DaemonInstanceLock&,const std::string& operationId,std::string& error);
    bool provePublished(const std::string& operationId,std::string& error) const;
    bool restore(const DaemonInstanceLock&,const std::string& operationId,std::string& error);
private:
    std::filesystem::path state_,units_;
};
}
#endif
