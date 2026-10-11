#ifndef FIC_DISPLAY_MANAGER_INVENTORY_H
#define FIC_DISPLAY_MANAGER_INVENTORY_H
#include "platform/PlatformExecutableResolver.h"
#include <fic/core/process/ProcessExecutor.h>
#include <functional>
#include <map>
#include <memory>
#include <set>

struct DisplayManagerState {
    bool installed = false;
    bool selected = false;
    bool running = false;
    bool configurationSupported = true;
};
struct DisplayManagerSnapshot {
    bool complete = false;
    std::map<std::string, DisplayManagerState> managers;
    std::vector<std::string> unknownSelectedOrRunning;
    std::string diagnostic;
};
class DisplayManagerInventory {
public:
    virtual ~DisplayManagerInventory() = default;
    virtual bool inspect(DisplayManagerSnapshot&, std::string&) const = 0;
};
class SystemDisplayManagerInventory final : public DisplayManagerInventory {
public:
    using Run = std::function<ProcessResult(fic::platform::ExecutableId, const std::vector<std::string>&)>;
    SystemDisplayManagerInventory(const fic::platform::PlatformExecutableResolver& executables,
        fic::platform::DisplayManagerPlatformConfig config);
    SystemDisplayManagerInventory(Run run, fic::platform::DisplayManagerPlatformConfig config);
    bool inspect(DisplayManagerSnapshot&, std::string&) const override;
    static std::string canonicalName(const std::string& identity);
private:
    Run run_;
    std::function<bool(const std::string&, std::string&)> executableProof_;
    std::function<bool(const std::string&, const std::string&)> unitExecutableProof_;
    fic::platform::DisplayManagerPlatformConfig config_;
};
#endif
