#ifndef FIC_CONTROLLED_DM_H
#define FIC_CONTROLLED_DM_H
#include "modules/oss/display_manager/DisplayManager.h"
#include "modules/oss/display_manager/DisplayManagerConfigTransaction.h"
class PolicyRegistry;
class ControlledDisplayManagerScope {
public:
    virtual ~ControlledDisplayManagerScope() = default;
    virtual bool configured(std::vector<std::string>&,std::string&) = 0;
    virtual bool ready(std::string&) = 0;
};
class OSS_controlled_display_managers final : public DisplayManager, public ControlledDisplayManagerScope {
public:
    OSS_controlled_display_managers(std::shared_ptr<DisplayManagerInventory>,
        std::shared_ptr<DisplayManagerConfigTransaction>,fic::rollback::MutationJournal* journal=nullptr);
    bool apply() override;
    bool configured(std::vector<std::string>&,std::string&) override;
    bool ready(std::string&) override;
    bool reconcile(Policy& autologin,std::string& error);
private:
    std::shared_ptr<DisplayManagerInventory> inventory_;
    std::shared_ptr<DisplayManagerConfigTransaction> backend_;
    fic::rollback::MutationJournal* journal_;
};
bool reconcileDisplayManagerScope(PolicyRegistry&,std::string& error);
#endif
