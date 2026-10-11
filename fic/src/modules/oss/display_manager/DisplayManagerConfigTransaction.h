#ifndef FIC_DM_CONFIG_TRANSACTION_H
#define FIC_DM_CONFIG_TRANSACTION_H
#include "platform/PlatformExecutableResolver.h"
#include "rollback/MutationJournal.h"
#include "modules/oss/display_manager/DisplayManagerInventory.h"

// Trusted routes come from the build platform, never from a journal path.
class DisplayManagerConfigTransaction {
public:
    using Run = SystemDisplayManagerInventory::Run;
    DisplayManagerConfigTransaction(const fic::platform::PlatformExecutableResolver&,
        fic::platform::DisplayManagerPlatformConfig);
    DisplayManagerConfigTransaction(Run, fic::platform::DisplayManagerPlatformConfig, std::string lockPath);
    bool preflight(const std::string& manager, bool enforce, fic::rollback::MutationJournal&, std::string& error) const;
    bool reconcile(const std::string& manager, bool enforce, fic::rollback::MutationJournal&, std::string& error) const;
    bool verifyApplied(const std::string&, fic::rollback::MutationJournal&, std::string& error) const;
    bool verifyReleased(const std::string&, fic::rollback::MutationJournal&, std::string& error) const;
    bool releaseAll(fic::rollback::MutationJournal&, std::string& error, bool preview = false) const;
    static std::string block(const fic::rollback::MutationRecord&);
private:
    struct Plan;
    bool plan(const std::string&, bool, fic::rollback::MutationJournal&, Plan&, std::string&) const;
    bool verify(const Plan&, const std::string& mainContent, bool disabled, std::string&, bool currentState = false) const;
    bool runPlan(Plan&, fic::rollback::MutationJournal&, std::string&) const;
    bool proveInputs(const Plan&, std::string&) const;
    Run run_;
    fic::platform::DisplayManagerPlatformConfig config_;
    std::string lockPath_;
};
#endif
