#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include <fic/core/config/ModuleConfigFileHandler.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

class FakeBackend final : public DesktopSystemBackend {
public:
    std::string name = "fake";
    DesktopEnvironmentKind kind = DesktopEnvironmentKind::Gnome;
    DesktopManagedSettings effective;
    std::map<std::string, std::string> foreign{{"administrator", "keep"}};
    std::vector<DesktopManagedSettings> ensures;
    int verifies = 0;
    bool failEnsure = false;
    bool failVerify = false;

    std::string backendName() const override { return name; }
    DesktopEnvironmentKind desktop() const override { return kind; }

    bool ensureManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override {
        ensures.push_back(required);
        if (failEnsure) {
            error = "injected ensure failure";
            return false;
        }
        for (const auto& [key, value] : required) effective[key] = value;
        error.clear();
        return true;
    }

    bool verifyManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override {
        ++verifies;
        if (failVerify) {
            error = "injected verification failure";
            return false;
        }
        for (const auto& [key, value] : required) {
            const auto actual = effective.find(key);
            if (actual == effective.end() || actual->second != value) {
                error = "effective setting differs from requirement";
                return false;
            }
        }
        error.clear();
        return true;
    }
};

class ContributorPolicy final : public Policy,
                                public GlobalDesktopPolicyContributor,
                                public SessionAwarePolicy {
public:
    ContributorPolicy(const std::filesystem::path& directory,
                      std::string name,
                      std::string desiredValue)
        : value(std::move(desiredValue)) {
        moduleName = "OSS";
        submoduleName = "DesktopEnvironment";
        policyName = std::move(name);
        moduleConf = std::make_unique<ModuleConfigFileHandler>(directory, moduleName);
        if (!moduleConf->loadConfig()) throw std::runtime_error("config load failed");
    }

    std::string value;
    std::string backend = "fake";
    DesktopEnvironmentKind desktop = DesktopEnvironmentKind::Gnome;
    EnforcementMode mode = EnforcementMode::MandatoryGlobal;
    std::string setting = "setting";
    PolicyRef ownerOverride;
    std::vector<GlobalDesktopPolicyContribution> extra;
    bool failContribution = false;
    bool advertiseCapability = true;

    bool apply() override { return true; }
    std::vector<PolicyCapability> capabilities() const override {
        if (!advertiseCapability) return {};
        return {PolicyCapability::GlobalDesktopConfiguration,
                PolicyCapability::SessionAware};
    }
    SessionApplicability sessionApplicability(
        DesktopEnvironmentKind candidate, std::string& error) override {
        error.clear();
        return candidate == desktop
            ? SessionApplicability::Applicable
            : SessionApplicability::NotApplicable;
    }
    EnforcementMode enforcementMode(DesktopEnvironmentKind candidate) const override {
        return candidate == desktop
            ? mode
            : EnforcementMode::Unsupported;
    }
    void setGlobalEnforcementResults(PolicyGlobalEnforcementResults) override {}
    SessionReconcileResult reconcileSession(
        const SessionReconcileContext&,
        const PolicyGlobalEnforcementResult&) override {
        return {};
    }
    bool globalDesktopPolicyContributions(
        std::vector<GlobalDesktopPolicyContribution>& contributions,
        std::string& error) override {
        if (failContribution) {
            error = "injected contribution failure";
            return false;
        }
        const PolicyRef self{moduleName, submoduleName, policyName};
        contributions.push_back({backend, desktop,
            ownerOverride.policyName.empty() ? self : ownerOverride,
            {setting}, value});
        contributions.insert(contributions.end(), extra.begin(), extra.end());
        error.clear();
        return true;
    }
};

class CapabilityOnlyPolicy final : public Policy {
public:
    explicit CapabilityOnlyPolicy(const std::filesystem::path& directory) {
        moduleName = "OSS";
        submoduleName = "DesktopEnvironment";
        policyName = "first";
        moduleConf = std::make_unique<ModuleConfigFileHandler>(directory, moduleName);
        if (!moduleConf->loadConfig()) throw std::runtime_error("config load failed");
    }
    bool apply() override { return true; }
    std::vector<PolicyCapability> capabilities() const override {
        return {PolicyCapability::GlobalDesktopConfiguration};
    }
};

class SessionModePolicy final : public Policy, public SessionAwarePolicy {
public:
    SessionModePolicy(const std::filesystem::path& directory,
                      EnforcementMode policyMode)
        : mode(policyMode) {
        moduleName = "OSS";
        submoduleName = "DesktopEnvironment";
        policyName = "first";
        moduleConf = std::make_unique<ModuleConfigFileHandler>(directory, moduleName);
        if (!moduleConf->loadConfig()) throw std::runtime_error("config load failed");
    }
    EnforcementMode mode;
    bool apply() override { return true; }
    std::vector<PolicyCapability> capabilities() const override {
        return {PolicyCapability::SessionAware};
    }
    SessionApplicability sessionApplicability(
        DesktopEnvironmentKind desktop, std::string& error) override {
        error.clear();
        return desktop == DesktopEnvironmentKind::Gnome
            ? SessionApplicability::Applicable
            : SessionApplicability::NotApplicable;
    }
    EnforcementMode enforcementMode(DesktopEnvironmentKind desktop) const override {
        return desktop == DesktopEnvironmentKind::Gnome
            ? mode : EnforcementMode::Unsupported;
    }
    void setGlobalEnforcementResults(PolicyGlobalEnforcementResults) override {}
    SessionReconcileResult reconcileSession(
        const SessionReconcileContext&,
        const PolicyGlobalEnforcementResult&) override { return {}; }
};

void writeConfig(const std::filesystem::path& directory,
                 const std::string& first,
                 const std::string& second) {
    std::ofstream(directory / "OSS.conf")
        << "first.status=" << first << '\n'
        << "second.status=" << second << '\n';
}

PolicyRegistry makeRegistry(const std::filesystem::path& directory,
                            const std::string& firstValue,
                            const std::string& secondValue) {
    PolicyRegistry registry;
    std::string error;
    require(registry.addModule("OSS", ModuleView::Standard, 0, error),
            "module registration failed");
    require(registry.addPolicy(std::make_unique<ContributorPolicy>(
                directory, "first", firstValue), error), "first registration failed");
    require(registry.addPolicy(std::make_unique<ContributorPolicy>(
                directory, "second", secondValue), error), "second registration failed");
    return registry;
}

ContributorPolicy& policy(PolicyRegistry& registry, const std::string& name) {
    auto* result = dynamic_cast<ContributorPolicy*>(registry.findPolicy(
        {"OSS", "DesktopEnvironment", name}));
    require(result != nullptr, "contributor missing");
    return *result;
}

void requireUntouched(const std::vector<std::shared_ptr<FakeBackend>>& backends) {
    for (const auto& backend : backends) {
        require(backend->ensures.empty() && backend->verifies == 0,
                "Stage A error touched backend");
    }
}
} // namespace

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-global-desktop-config-test-" + std::to_string(::getpid()));
    fs::create_directories(root);
    const PolicyRef firstOwner{"OSS", "DesktopEnvironment", "first"};
    const PolicyRef secondOwner{"OSS", "DesktopEnvironment", "second"};
    std::string error;

    writeConfig(root, "ENABLE", "DISABLE");
    auto backend = std::make_shared<FakeBackend>();
    backend->effective[{"existing"}] = "old";
    DesktopGlobalConfigReconciler reconciler({backend});
    auto one = makeRegistry(root, "true", "ignored");
    auto report = reconciler.reconcile(one);
    require(report.successful(), report.diagnostic().c_str());
    require(backend->ensures.size() == 1 && backend->ensures.back().size() == 1 &&
                backend->ensures.back().at({"setting"}) == "true",
            "one active policy was not ensured");
    require(backend->effective.at({"existing"}) == "old" &&
                backend->foreign.at("administrator") == "keep",
            "unrelated state was changed");

    writeConfig(root, "ENABLE", "ENABLE");
    auto shared = makeRegistry(root, "true", "true");
    report = reconciler.reconcile(shared);
    require(report.successful(), report.diagnostic().c_str());
    require(backend->ensures.back().size() == 1,
            "same-value owners did not merge");
    require(report.resultFor(firstOwner, DesktopEnvironmentKind::Gnome).hasRequirement &&
                report.resultFor(firstOwner, DesktopEnvironmentKind::Gnome).verified &&
                report.resultFor(secondOwner, DesktopEnvironmentKind::Gnome).verified,
            "shared owners did not receive verified policy results");
    policy(shared, "first").extra.push_back(
        {"fake", DesktopEnvironmentKind::Gnome,
         firstOwner, {"setting"}, "true"});
    report = reconciler.reconcile(shared);
    require(report.successful(), report.diagnostic().c_str());

    writeConfig(root, "DISABLE", "ENABLE");
    auto secondOnly = makeRegistry(root, "ignored", "true");
    const auto beforeOneDisable = backend->ensures.size();
    report = reconciler.reconcile(secondOnly);
    require(report.successful(), report.diagnostic().c_str());
    require(backend->ensures.size() == beforeOneDisable + 1 &&
                backend->effective.at({"setting"}) == "true",
            "remaining requester was not enforced");

    writeConfig(root, "DISABLE", "DISABLE");
    auto disabled = makeRegistry(root, "ignored", "ignored");
    const auto beforeLastDisable = backend->ensures.size();
    const int verifiesBeforeLastDisable = backend->verifies;
    report = reconciler.reconcile(disabled);
    require(report.successful(), report.diagnostic().c_str());
    require(backend->ensures.size() == beforeLastDisable &&
                backend->verifies == verifiesBeforeLastDisable &&
                backend->effective.at({"setting"}) == "true",
            "disable changed previously applied state");

    writeConfig(root, "ENABLE", "DISABLE");
    auto changed = makeRegistry(root, "false", "ignored");
    report = reconciler.reconcile(changed);
    require(report.successful(), report.diagnostic().c_str());
    require(backend->effective.at({"setting"}) == "false",
            "enabled value change was not enforced");

    writeConfig(root, "ENABLE", "ENABLE");
    for (const std::string failure : {"conflict", "self", "unknown", "owner",
                                      "desktop", "empty", "generation"}) {
        auto firstBackend = std::make_shared<FakeBackend>();
        auto other = std::make_shared<FakeBackend>(); other->name = "other";
        other->kind = DesktopEnvironmentKind::Kde;
        DesktopGlobalConfigReconciler subject({firstBackend, other});
        auto invalid = makeRegistry(root, "true", "true");
        auto& second = policy(invalid, "second");
        if (failure == "conflict") second.value = "false";
        if (failure == "self") second.extra.push_back(
            {"fake", DesktopEnvironmentKind::Gnome,
             {"OSS", "DesktopEnvironment", "second"}, {"setting"}, "false"});
        if (failure == "unknown") second.backend = "missing";
        if (failure == "owner") second.ownerOverride = firstOwner;
        if (failure == "desktop") second.desktop = DesktopEnvironmentKind::Unknown;
        if (failure == "empty") second.setting.clear();
        if (failure == "generation") second.failContribution = true;
        const auto invalidReport = subject.reconcile(invalid);
        error = invalidReport.diagnostic();
        if (invalidReport.requirementsValid) {
            throw std::runtime_error("invalid requirements accepted: " + failure);
        }
        if (failure == "conflict" || failure == "self")
            require(error.find("conflicting global desktop setting") != std::string::npos,
                    "conflict diagnostic missing");
        requireUntouched({firstBackend, other});
    }

    PolicyRegistry capabilityMismatch;
    require(capabilityMismatch.addModule(
                "OSS", ModuleView::Standard, 0, error), error.c_str());
    auto hiddenContributor =
        std::make_unique<ContributorPolicy>(root, "first", "true");
    hiddenContributor->advertiseCapability = false;
    require(capabilityMismatch.addPolicy(
                std::move(hiddenContributor), error), error.c_str());
    auto mismatchBackend = std::make_shared<FakeBackend>();
    DesktopGlobalConfigReconciler mismatchReconciler({mismatchBackend});
    report = mismatchReconciler.reconcile(capabilityMismatch);
    require(!report.requirementsValid,
            "contributor without capability accepted");
    requireUntouched({mismatchBackend});

    for (const EnforcementMode mode : {
             EnforcementMode::MandatoryGlobal, EnforcementMode::SessionOnly}) {
        PolicyRegistry coverage;
        require(coverage.addModule("OSS", ModuleView::Standard, 0, error), error.c_str());
        require(coverage.addPolicy(
                    std::make_unique<SessionModePolicy>(root, mode), error), error.c_str());
        report = mismatchReconciler.reconcile(coverage);
        require(report.requirementsValid == (mode == EnforcementMode::SessionOnly),
                "MandatoryGlobal coverage invariant is incorrect");
        requireUntouched({mismatchBackend});
    }

    auto sessionOnlyContribution = makeRegistry(root, "true", "true");
    policy(sessionOnlyContribution, "first").mode = EnforcementMode::SessionOnly;
    report = mismatchReconciler.reconcile(sessionOnlyContribution);
    require(!report.requirementsValid,
            "SessionOnly authoritative contribution was accepted");
    requireUntouched({mismatchBackend});

    PolicyRegistry missingContributor;
    require(missingContributor.addModule(
                "OSS", ModuleView::Standard, 0, error), error.c_str());
    require(missingContributor.addPolicy(
                std::make_unique<CapabilityOnlyPolicy>(root), error), error.c_str());
    report = mismatchReconciler.reconcile(missingContributor);
    require(!report.requirementsValid,
            "capability without contributor accepted");
    requireUntouched({mismatchBackend});

    auto distinct = makeRegistry(root, "true", "false");
    policy(distinct, "second").setting = "otherSetting";
    auto distinctBackend = std::make_shared<FakeBackend>();
    DesktopGlobalConfigReconciler distinctReconciler({distinctBackend});
    report = distinctReconciler.reconcile(distinct);
    require(report.successful(), report.diagnostic().c_str());
    require(distinctBackend->ensures.back().size() == 2,
            "different physical settings were not both enforced");

    auto namespaced = makeRegistry(root, "true", "false");
    policy(namespaced, "second").backend = "other";
    policy(namespaced, "second").desktop = DesktopEnvironmentKind::Kde;
    auto other = std::make_shared<FakeBackend>(); other->name = "other";
    other->kind = DesktopEnvironmentKind::Kde;
    DesktopGlobalConfigReconciler separate({backend, other});
    report = separate.reconcile(namespaced);
    require(report.successful(), report.diagnostic().c_str());
    require(backend->effective.at({"setting"}) == "true" &&
                other->effective.at({"setting"}) == "false",
            "backend namespaces conflicted");
    require(report.backends.at("fake").attempted &&
                report.backends.at("fake").verified &&
                report.backends.at("other").attempted &&
                report.backends.at("other").verified,
            "per-backend verified results are incomplete");

    // Typed backend/desktop binding: each backend serves one canonical
    // desktop, and valid bindings with different desktops are accepted.
    auto typedGnome = std::make_shared<FakeBackend>(); typedGnome->name = "gnome";
    auto typedKde = std::make_shared<FakeBackend>(); typedKde->name = "kde";
    typedKde->kind = DesktopEnvironmentKind::Kde;
    auto crossDesktop = makeRegistry(root, "true", "false");
    policy(crossDesktop, "first").backend = "gnome";
    policy(crossDesktop, "second").backend = "kde";
    policy(crossDesktop, "second").desktop = DesktopEnvironmentKind::Kde;
    DesktopGlobalConfigReconciler typedReconciler({typedGnome, typedKde});
    report = typedReconciler.reconcile(crossDesktop);
    require(report.successful(), report.diagnostic().c_str());
    require(typedGnome->verifies == 1 && typedKde->verifies == 1,
            "typed desktop binding skipped a valid backend");
    require(report.resultFor(firstOwner, DesktopEnvironmentKind::Gnome).verified &&
                report.resultFor(secondOwner, DesktopEnvironmentKind::Kde).verified,
            "typed routing lost per-policy results");
    // Same setting name in GNOME and KDE namespaces does not conflict.
    require(typedGnome->effective.at({"setting"}) == "true" &&
                typedKde->effective.at({"setting"}) == "false",
            "cross-desktop same-name settings conflicted");

    // Per-policy isolation survives typed routing: a failed KDE backend must
    // not contaminate the verified GNOME result.
    auto routedGnome = std::make_shared<FakeBackend>(); routedGnome->name = "gnome";
    auto routedKde = std::make_shared<FakeBackend>(); routedKde->name = "kde";
    routedKde->kind = DesktopEnvironmentKind::Kde;
    routedKde->failVerify = true;
    DesktopGlobalConfigReconciler routedReconciler({routedGnome, routedKde});
    report = routedReconciler.reconcile(crossDesktop);
    require(!report.successful(), "KDE backend failure was ignored");
    require(report.resultFor(firstOwner, DesktopEnvironmentKind::Gnome).verified &&
                !report.resultFor(secondOwner, DesktopEnvironmentKind::Kde).verified,
            "typed routing broke per-policy isolation");

    // A contribution for a desktop the backend does not serve is a Stage A
    // failure even when the backend itself would ensure and verify
    // successfully: no mutation may happen.
    auto lyingGnome = std::make_shared<FakeBackend>(); lyingGnome->name = "gnome";
    auto mismatch = makeRegistry(root, "true", "ignored");
    policy(mismatch, "first").backend = "gnome";
    policy(mismatch, "first").desktop = DesktopEnvironmentKind::Kde;
    DesktopGlobalConfigReconciler mismatchBinding({lyingGnome});
    report = mismatchBinding.reconcile(mismatch);
    require(!report.requirementsValid,
            "contribution/backend desktop mismatch accepted");
    require(report.stageADiagnostic.find(
                "global desktop contribution/backend desktop mismatch") !=
                std::string::npos,
            "mismatch diagnostic missing");
    require(lyingGnome->ensures.empty() && lyingGnome->verifies == 0,
            "desktop mismatch still reached backend mutation");
    require(!report.resultFor(firstOwner, DesktopEnvironmentKind::Kde).verified,
            "mismatch produced a verified policy result");
    requireUntouched({lyingGnome});

    // A backend without a canonical desktop identity cannot be registered.
    auto anonymous = std::make_shared<FakeBackend>();
    anonymous->kind = DesktopEnvironmentKind::Unknown;
    DesktopGlobalConfigReconciler unknownDesktop({anonymous});
    report = unknownDesktop.reconcile(shared);
    require(!report.requirementsValid, "unknown backend desktop accepted");
    requireUntouched({anonymous});

    // One canonical desktop cannot be served by two system backends.
    auto primary = std::make_shared<FakeBackend>(); primary->name = "gnome-primary";
    auto secondary = std::make_shared<FakeBackend>();
    secondary->name = "gnome-secondary";
    DesktopGlobalConfigReconciler duplicateDesktop({primary, secondary});
    report = duplicateDesktop.reconcile(shared);
    require(!report.requirementsValid &&
                report.stageADiagnostic.find(
                    "duplicate desktop system backend") != std::string::npos,
            "duplicate desktop backend accepted");
    requireUntouched({primary, secondary});

    auto failures = makeRegistry(root, "one", "two");
    policy(failures, "first").backend = "first";
    policy(failures, "second").desktop = DesktopEnvironmentKind::Kde;
    for (const std::string failure : {"ensure", "verify", "multiple"}) {
        auto first = std::make_shared<FakeBackend>(); first->name = "first";
        auto second = std::make_shared<FakeBackend>(); second->name = "second";
        auto third = std::make_shared<FakeBackend>(); third->name = "third";
        second->kind = DesktopEnvironmentKind::Kde;
        third->kind = DesktopEnvironmentKind::Kde;
        // Only one registered backend may claim a canonical desktop: the KDE
        // policy uses "second" except in the "multiple" iteration, where it
        // moves to "third", so the unused backend must serve another desktop.
        if (failure == "multiple") second->kind = DesktopEnvironmentKind::Xfce;
        else third->kind = DesktopEnvironmentKind::Xfce;
        first->failEnsure = failure == "ensure" || failure == "multiple";
        first->failVerify = failure == "verify";
        policy(failures, "second").backend = failure == "multiple" ? "third" : "second";
        third->failVerify = failure == "multiple";
        DesktopGlobalConfigReconciler subject({first, second, third});
        const auto failureReport = subject.reconcile(failures);
        error = failureReport.diagnostic();
        require(!failureReport.successful(), "backend failure accepted");
        require(!failureReport.backends.at("first").verified,
                "failed backend reported verified");
        require(!failureReport.requirementsValid ||
                    error.find("first:") != std::string::npos,
                "first backend diagnostic missing");
        require(failureReport.requirementsValid,
                "valid backend registration was rejected");
        if (failure == "multiple") {
            require(error.find("third: verifyManagedSettings failed") != std::string::npos &&
                        error.find('\n') != std::string::npos,
                    "multiple errors were not aggregated");
        } else {
            require(second->effective.at({"setting"}) == "two" && second->verifies == 1,
                    "failed backend blocked later enforcement");
            require(!failureReport.resultFor(
                        firstOwner, DesktopEnvironmentKind::Gnome).verified &&
                    failureReport.resultFor(
                        secondOwner, DesktopEnvironmentKind::Kde).verified,
                    "backend failure contaminated an unrelated policy result");
            require(!failureReport.successfulForPolicy(firstOwner) &&
                        failureReport.successfulForPolicy(secondOwner),
                    "policy-scoped success used the overall backend result");
        }
    }

    auto untouched = std::make_shared<FakeBackend>();
    for (const auto& backends :
         std::vector<std::vector<std::shared_ptr<DesktopSystemBackend>>>{
             {untouched, nullptr}, {untouched, untouched}}) {
        DesktopGlobalConfigReconciler invalid(backends);
        report = invalid.reconcile(shared);
        require(!report.requirementsValid, "invalid backend accepted");
        requireUntouched({untouched});
    }

    fs::remove_all(root);
    return 0;
}
