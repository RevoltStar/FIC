#include "modules/identity_access/pam/PamRequiredProviders.h"

#include <algorithm>
#include <cctype>
#include <optional>
#include <set>
#include <utility>

namespace fic::identity::pam {
namespace {

std::string trimCopy(const std::string& value) {
    const auto first = std::find_if_not(
        value.begin(), value.end(), [](unsigned char c) {
            return std::isspace(c) != 0;
        });
    if (first == value.end()) {
        return {};
    }
    const auto last = std::find_if_not(
        value.rbegin(), value.rend(), [](unsigned char c) {
            return std::isspace(c) != 0;
        }).base();
    return std::string(first, last);
}

const std::vector<std::pair<std::string, PamProviderKind>>&
requiredPamProviders() {
    static const std::vector<std::pair<std::string, PamProviderKind>> providers{
        {"pam_faillock", PamProviderKind::PamFaillock},
        {"pam_pwquality", PamProviderKind::PamPwquality},
        {"pam_passwdqc", PamProviderKind::PamPasswdqc},
        {"pam_pwhistory", PamProviderKind::PamPwhistory},
    };
    return providers;
}

std::optional<PamProviderKind> requiredProvider(const std::string& name) {
    for (const auto& [providerName, provider] : requiredPamProviders()) {
        if (name == providerName) {
            return provider;
        }
    }
    return std::nullopt;
}

} // namespace

const std::vector<std::string>& requiredPamProviderNames() {
    static const std::vector<std::string> names = [] {
        std::vector<std::string> result;
        result.reserve(requiredPamProviders().size());
        for (const auto& [name, provider] : requiredPamProviders()) {
            (void)provider;
            result.push_back(name);
        }
        return result;
    }();
    return names;
}

bool parseRequiredPamProviders(const std::string& value,
                               std::vector<PamProviderKind>& providers,
                               std::string& normalized,
                               std::string& error) {
    providers.clear();
    normalized.clear();
    if (value.empty()) {
        error = "required PAM provider list must not be empty";
        return false;
    }

    std::set<PamProviderKind> seen;
    std::size_t start = 0;
    std::size_t itemNumber = 0;
    while (true) {
        ++itemNumber;
        const std::size_t comma = value.find(',', start);
        const std::string item = trimCopy(value.substr(
            start,
            comma == std::string::npos ? std::string::npos : comma - start));
        if (item.empty()) {
            error = "required PAM provider list contains an empty item at " +
                std::to_string(itemNumber);
            return false;
        }
        const auto provider = requiredProvider(item);
        if (!provider.has_value()) {
            error = "unknown or unsupported PAM provider: " + item;
            return false;
        }
        if (seen.insert(*provider).second) {
            providers.push_back(*provider);
            if (!normalized.empty()) {
                normalized += ',';
            }
            normalized += item;
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    error.clear();
    return true;
}

} // namespace fic::identity::pam
