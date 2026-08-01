#include "modules/identity_access/submodules/nss/policies/NssLocalAccountsFirstPolicy.h"

#include <algorithm>
#include <array>
#include <utility>

namespace {

void placeFilesFirst(std::vector<fic::identity::nss::NssService>& services) {
    if (std::none_of(
            services.begin(), services.end(), [](const auto& service) {
                return service.name == "files";
            })) {
        services.insert(services.begin(), {"files", {}});
        return;
    }
    std::stable_partition(
        services.begin(), services.end(), [](const auto& service) {
            return service.name == "files";
        });
}

} // namespace

NssLocalAccountsFirstPolicy::NssLocalAccountsFirstPolicy()
    : NssLocalAccountsFirstPolicy(
          fic::identity::nss::NssConfigurationOptions::production()) {
}

NssLocalAccountsFirstPolicy::NssLocalAccountsFirstPolicy(
    fic::identity::nss::NssConfigurationOptions options)
    : NssPolicy(std::move(options)) {
    this->policyName = "nss_local_accounts_first";
    this->policyTypeValue =
        std::make_unique<FixedPolicyTypeValue>("enforced");
}

bool NssLocalAccountsFirstPolicy::applyNss(
    fic::identity::nss::NssConfiguration& configuration,
    const std::string&) {
    static const std::array<const char*, 3> databases = {
        "passwd", "group", "shadow"};
    std::vector<fic::identity::nss::NssDatabaseSetting> settings;
    std::string error;
    for (const char* database : databases) {
        std::optional<std::vector<fic::identity::nss::NssService>> services;
        if (!configuration.tryGetServices(database, services, error)) {
            this->log(
                "NSS policy preflight failed for " + this->policyName +
                    "/" + database + ": " + error,
                logLevel::ERROR);
            return false;
        }
        if (!services.has_value()) {
            this->log(
                "NSS policy " + this->policyName + " requires database " +
                    database,
                logLevel::ERROR);
            return false;
        }
        placeFilesFirst(*services);
        settings.push_back({database, std::move(*services)});
    }

    if (!configuration.setDatabases(settings, error)) {
        this->log(
            "Could not apply NSS policy " + this->policyName + ": " + error,
            logLevel::ERROR);
        return false;
    }
    this->log(
        "NSS policy " + this->policyName +
            " is effective for passwd, group and shadow",
        logLevel::INFO);
    return true;
}
