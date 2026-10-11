#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "rollback/ScopeTransition.h"
#include "modules/oss/desktop_environment/backends/FlySystemBackend.h"
#include <fic/core/config/ModuleConfigFileHandler.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <stdexcept>
#include <unistd.h>

namespace {
void require(bool value, const std::string& error) { if (!value) throw std::runtime_error(error); }
const PolicyRef scopeRef{"OSS", "DesktopEnvironment", "controlled_desktop_environments"};
class Scope final : public Policy, public ControlledDesktopEnvironmentScope {
public:
    void disable() { moduleConf->setPolicyStatus(policyName, "DISABLE"); }
    void refresh() { require(moduleConf->loadConfig(), "scope reload"); }
    DesktopEnvironmentSet target{DesktopEnvironmentKind::Gnome};
    bool valid = true;
    explicit Scope(const std::filesystem::path& root) {
        moduleName = "OSS"; submoduleName = "DesktopEnvironment"; policyName = scopeRef.policyName;
        moduleConf = std::make_unique<ModuleConfigFileHandler>(root, "OSS");
        require(moduleConf->loadConfig(), "scope load");
    }
    bool apply() override { throw std::runtime_error("coordinator must not call scope apply"); }
    bool readyForApply(std::string&) override { throw std::runtime_error("coordinator must not require its own committed target"); }
    bool controlledDesktopEnvironments(DesktopEnvironmentSet& value, std::string& error) override {
        if (!valid) { error = "invalid scope"; return false; }
        value = target; return true;
    }
};
class Contributor final : public Policy, public GlobalDesktopPolicyContributor, public SessionAwarePolicy {
public:
    void disable() { moduleConf->setPolicyStatus(policyName, "DISABLE"); require(moduleConf->saveConfig(), "save status"); }
    void refresh() { require(moduleConf->loadConfig(), "contributor reload"); }
    std::string backend = "gnome", key = "key", value = "true";
    DesktopEnvironmentKind kind = DesktopEnvironmentKind::Gnome;
    EnforcementMode mode = EnforcementMode::MandatoryGlobal;
    bool capability = true, generation = true, sessionOnlyRoute = false;
    PolicyRef ownerOverride;
    explicit Contributor(const std::filesystem::path& root, const std::string& name) {
        moduleName = "OSS"; submoduleName = "DesktopEnvironment"; policyName = name;
        moduleConf = std::make_unique<ModuleConfigFileHandler>(root, "OSS");
        require(moduleConf->loadConfig(), "contributor load"); addRequiredDependency(scopeRef);
    }
    bool apply() override { return true; }
    std::vector<PolicyCapability> capabilities() const override {
        return capability ? std::vector<PolicyCapability>{PolicyCapability::GlobalDesktopConfiguration, PolicyCapability::SessionAware}
                          : std::vector<PolicyCapability>{PolicyCapability::SessionAware};
    }
    SessionApplicability sessionApplicability(DesktopEnvironmentKind desktop, std::string&) override {
        return desktop == kind ? SessionApplicability::Applicable : SessionApplicability::NotApplicable;
    }
    EnforcementMode enforcementMode(DesktopEnvironmentKind) const override { return mode; }
    void setGlobalEnforcementResults(PolicyGlobalEnforcementResults) override {}
    SessionReconcileResult reconcileSession(const SessionReconcileContext&, const PolicyGlobalEnforcementResult&) override { return {}; }
    bool globalDesktopPolicyContributions(std::vector<GlobalDesktopPolicyContribution>& out, std::string& error) override {
        if (!generation) { error = "generation failed"; return false; }
        if (sessionOnlyRoute) return true;
        out.push_back({backend, kind, ownerOverride.policyName.empty() ?
            PolicyRef{moduleName, submoduleName, policyName} : ownerOverride, {key}, value}); return true;
    }
};
class Backend final : public DesktopSystemBackend {
public:
    std::string name = "gnome";
    DesktopEnvironmentKind kind = DesktopEnvironmentKind::Gnome;
    DesktopGlobalConfigRequirements owned;
    std::vector<std::string>* order = nullptr;
    std::function<void()> afterWrite;
    bool preflightOK = true, writeOK = true, verifyOK = true;
    bool effectiveAvailable = true;
    int writes = 0;
    DesktopEnvironmentKind desktop() const override { return kind; }
    std::string backendName() const override { return name; }
    bool verifiedEnforcementAvailable(std::string& error) const override {
        if (!effectiveAvailable) error = "runtime proof unavailable";
        return effectiveAvailable;
    }
    bool ensureManagedSettings(const DesktopManagedSettings&, std::string&) override {
        throw std::runtime_error("coordinator used unjournaled writer");
    }
    bool preflightJournaled(const DesktopGlobalConfigRequirements&, fic::rollback::MutationJournal&, std::string& error) override {
        if (order) order->push_back("preflight:" + name);
        if (!preflightOK) error = "ownership conflict";
        return preflightOK;
    }
    bool reconcileJournaled(const DesktopGlobalConfigRequirements& target, fic::rollback::MutationJournal& journal, std::string& error) override {
        fic::rollback::ScopeTransitionState state;
        require(fic::rollback::ScopeTransition(journal).state(state, error) && state.phase == "pending", "physical mutation before Prepared");
        ++writes; if (order) order->push_back("write:" + name);
        owned = target; if (afterWrite) afterWrite();
        if (!writeOK) error = "partial write";
        return writeOK;
    }
    bool verifyManagedSettings(const DesktopManagedSettings& values, std::string& error) override {
        if (!verifyOK) { error = "native mismatch"; return false; }
        if (values.size() != owned.size()) return false;
        for (const auto& [key, value] : values) if (!owned.count(key) || owned.at(key).value != value) return false;
        return true;
    }
};
struct Fixture {
    std::filesystem::path root;
    fic::rollback::MutationJournal journal;
    PolicyRegistry registry;
    Scope* scope;
    Contributor *first, *second;
    std::shared_ptr<Backend> gnome = std::make_shared<Backend>();
    std::shared_ptr<Backend> fly = std::make_shared<Backend>();
    static std::filesystem::path directory() {
        static int count = 0;
        auto root = std::filesystem::temp_directory_path() / ("fic-de-transaction-" + std::to_string(getpid()) + "-" + std::to_string(++count));
        std::filesystem::create_directories(root); return root;
    }
    explicit Fixture(bool advertise = true) : root(directory()), journal(root / "journal.json") {
        std::ofstream(root / "OSS.conf") << "controlled_desktop_environments.status=ENABLE\nfirst.status=ENABLE\nsecond.status=ENABLE\n";
        std::string error; require(journal.initializeOrLoad(error), error);
        require(registry.addModule("OSS", ModuleView::Standard, 0, error), error);
        auto s = std::make_unique<Scope>(root); scope = s.get(); require(registry.addPolicy(std::move(s), error), error);
        auto a = std::make_unique<Contributor>(root, "first"); first = a.get(); require(registry.addPolicy(std::move(a), error), error);
        auto b = std::make_unique<Contributor>(root, "second"); b->capability = advertise;
        second = b.get(); require(registry.addPolicy(std::move(b), error), error);
        fly->name = "fly"; fly->kind = DesktopEnvironmentKind::Fly;
    }
    ~Fixture() { std::error_code ec; std::filesystem::remove_all(root, ec); }
    DesktopGlobalReconcileReport apply() { return DesktopGlobalConfigReconciler({gnome, fly}, &journal).reconcile(registry); }
    fic::rollback::ScopeTransitionState state() {
        fic::rollback::ScopeTransitionState result; std::string error;
        require(fic::rollback::ScopeTransition(journal).state(result, error), error); return result;
    }
};
void transitions() {
    Fixture f;
    require(f.apply().successful(), "initial scope did not commit");
    require(f.state().committed == std::vector<std::string>{"GNOME"} && f.gnome->owned.at({"key"}).owners.size() == 2, "owners/initial checkpoint lost");
    f.scope->target = {DesktopEnvironmentKind::Gnome, DesktopEnvironmentKind::Fly};
    f.second->kind = DesktopEnvironmentKind::Fly; f.second->backend = "fly";
    require(f.apply().successful(), "added FLY did not commit");
    const auto previous = f.state().committed;
    f.scope->target = {DesktopEnvironmentKind::Gnome};
    f.second->disable();
    f.scope->refresh(); f.first->refresh(); f.second->refresh();
    require(f.apply().successful() && f.fly->owned.empty(), "obsolete FLY ownership not released");
    require(f.state().committed != previous, "committed scope did not change");
    fic::rollback::MutationJournal restarted(f.root / "journal.json"); std::string error;
    require(restarted.initializeOrLoad(error) && fic::rollback::ScopeTransition(restarted).requireCommitted({"GNOME"}, error), error);
    f.scope->target.clear(); const auto writes = f.gnome->writes + f.fly->writes;
    require(!f.apply().successful() && f.state().phase == "failed" && f.state().committed == std::vector<std::string>{"GNOME"}, "empty target lost previous checkpoint");
    require(writes == f.gnome->writes + f.fly->writes, "UNCONFIGURED mutated resources");
}
void sessionScopeTransitions() {
    using Kind = DesktopEnvironmentKind;
    const std::vector<std::pair<DesktopEnvironmentSet, DesktopEnvironmentSet>> cases = {
        {{Kind::Kde,Kind::Gnome},{Kind::Gnome}},
        {{Kind::Kde,Kind::Gnome},{Kind::Kde}},
        {{Kind::Kde,Kind::Xfce},{Kind::Kde}},
        {{Kind::Kde},{Kind::Kde,Kind::Gnome}},
        {{Kind::Kde,Kind::Xfce},{Kind::Gnome}},
        {{Kind::Gnome,Kind::Fly},{Kind::Gnome}},
        {{Kind::Kde},{Kind::Xfce}},
        {{Kind::Gnome},{Kind::Kde,Kind::Gnome}},
        {{Kind::Gnome},{Kind::Gnome,Kind::Fly}}
    };
    for (const auto& [previous,target] : cases) {
        Fixture f;
        const auto configure = [&](const DesktopEnvironmentSet& value) {
            f.scope->target=value;
            f.first->sessionOnlyRoute = !value.count(Kind::Gnome);
            f.first->kind = f.first->sessionOnlyRoute ? Kind::Kde : Kind::Gnome;
            f.first->mode = f.first->sessionOnlyRoute ? EnforcementMode::SessionOnly : EnforcementMode::MandatoryGlobal;
            f.second->sessionOnlyRoute = !value.count(Kind::Fly);
            f.second->kind = f.second->sessionOnlyRoute ? Kind::Xfce : Kind::Fly;
            f.second->backend = "fly";
            f.second->mode = f.second->sessionOnlyRoute ? EnforcementMode::SessionOnly : EnforcementMode::MandatoryGlobal;
        };
        configure(previous); require(f.apply().successful(), "initial mixed checkpoint failed");
        configure(target); require(f.apply().successful() && f.state().phase == "committed", "SessionOnly wedged global checkpoint");
        require(f.gnome->owned.empty() == !target.count(Kind::Gnome), "GNOME ensure/release mismatch");
        require(f.fly->owned.empty() == !target.count(Kind::Fly), "FLY ensure/release mismatch");
    }
}

void unrelatedFlyDoesNotBlockGnome() {
    Fixture f;
    FlySystemBackendOptions options;
    options.trustedRoot=f.root;options.configPath=f.root/"themerc";
    options.trustedOwner=getuid();options.trustedGroup=getgid();options.lockPath=f.root/"fly.lock";
    const std::string foreign="[Theme]\nName=Foreign\n";
    std::ofstream(options.configPath)<<foreign;
    auto fly=std::make_shared<FlySystemBackend>(options);
    DesktopGlobalConfigReconciler coordinator({f.gnome,fly},&f.journal);
    require(coordinator.reconcile(f.registry).successful()&&f.gnome->writes>0,
            "unmanaged foreign FLY layout blocked GNOME ensure");
    std::ifstream in(options.configPath);const std::string actual{std::istreambuf_iterator<char>(in),{}};
    require(actual==foreign,"coordinator modified unrelated FLY bytes");
    std::ofstream(options.configPath)<<foreign<<"# FIC-DE 123 unexpected\n";
    const auto writes=f.gnome->writes;
    require(!coordinator.reconcile(f.registry).successful()&&f.gnome->writes==writes,
            "orphan FLY failed full preflight or mutated GNOME first");
}

void refusals() {
    for (const std::string mode : {"disabled", "invalid", "conflict", "owner", "backend", "desktop", "key", "capability", "generation", "session", "preflight", "duplicate", "runtime"}) {
        Fixture f(mode != "capability");
        if (mode == "disabled") f.scope->disable();
        if (mode == "invalid") f.scope->valid = false;
        if (mode == "conflict") f.second->value = "false";
        if (mode == "owner") f.second->ownerOverride = {"OSS", "DesktopEnvironment", "first"};
        if (mode == "backend") f.second->backend = "unknown";
        if (mode == "desktop") f.second->kind = DesktopEnvironmentKind::Kde;
        if (mode == "key") f.second->key.clear();
        if (mode == "capability") f.second->capability = false;
        if (mode == "generation") f.second->generation = false;
        if (mode == "session") f.second->mode = EnforcementMode::SessionOnly;
        if (mode == "preflight") f.fly->preflightOK = false;
        if (mode == "duplicate") f.fly->kind = DesktopEnvironmentKind::Gnome;
        if (mode == "runtime") f.gnome->effectiveAvailable = false;
        require(!f.apply().successful() && f.gnome->writes + f.fly->writes == 0, "preflight mutated state: " + mode);
    }
}
void partialRecovery() {
    Fixture f; require(f.apply().successful(), "initial commit");
    f.scope->target = {DesktopEnvironmentKind::Gnome, DesktopEnvironmentKind::Fly};
    f.second->kind = DesktopEnvironmentKind::Fly; f.second->backend = "fly";
    std::vector<std::string> order; f.gnome->order = &order; f.fly->order = &order;
    f.fly->writeOK = false;
    require(!f.apply().successful() && f.state().phase == "partial" && f.state().committed == std::vector<std::string>{"GNOME"}, "partial claimed committed");
    require(order.size() >= 4 && order[0] == "preflight:gnome" && order[1] == "preflight:fly", "physical mutation before all preflights");
    f.fly->writeOK = true; require(f.apply().successful(), "partial retry failed");
    f.gnome->afterWrite = [&] { f.scope->target = {DesktopEnvironmentKind::Fly}; };
    require(!f.apply().successful() && f.state().phase == "partial", "obsolete configured target committed");
    f.gnome->afterWrite = {}; f.scope->target = {DesktopEnvironmentKind::Gnome, DesktopEnvironmentKind::Fly};
    f.fly->verifyOK = false;
    require(!f.apply().successful() && f.state().phase == "partial", "native verification failure committed");
    f.fly->verifyOK = true; require(f.apply().successful(), "verification failure retry failed");
    f.gnome->afterWrite = [&] { std::ofstream(f.root / "OSS.conf", std::ios::app) << "# external writer\n"; };
    require(!f.apply().successful() && f.state().phase == "partial", "external intent version change committed");
}
}
int main() { unrelatedFlyDoesNotBlockGnome(); transitions(); sessionScopeTransitions(); refusals(); partialRecovery(); }
