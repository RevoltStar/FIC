#include "modules/dac/mode_and_owner/ModeAndOwnerProfilesPolicy.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <fstream>
#include <grp.h>

namespace {
using Dac = fic::platform::DacPlatformConfig;

std::string trim(const std::string& value) {
    const auto begin = std::find_if_not(value.begin(), value.end(),
        [](unsigned char c) { return std::isspace(c); });
    const auto end = std::find_if_not(value.rbegin(), value.rend(),
        [](unsigned char c) { return std::isspace(c); }).base();
    return begin < end ? std::string(begin, end) : std::string{};
}

const char* profileName(Dac::Profile profile) {
    switch (profile) {
    case Dac::Profile::System: return "system";
    case Dac::Profile::Minimum: return "minimum";
    case Dac::Profile::Optimal: return "optimal";
    case Dac::Profile::Strict: return "strict";
    }
    return "invalid";
}

bool parseProfile(const std::string& text, Dac::Profile& profile) {
    if (text == "system") profile = Dac::Profile::System;
    else if (text == "minimum") profile = Dac::Profile::Minimum;
    else if (text == "optimal") profile = Dac::Profile::Optimal;
    else if (text == "strict") profile = Dac::Profile::Strict;
    else return false;
    return true;
}

const Dac::Object* findObject(const Dac& platform, const std::string& id) {
    const auto it = std::find_if(platform.modeAndOwnerObjects.begin(),
        platform.modeAndOwnerObjects.end(),
        [&](const Dac::Object& object) { return object.id == id; });
    return it == platform.modeAndOwnerObjects.end() ? nullptr : &*it;
}

bool planUserHomes(const Dac::UserHomesObject& homes, Dac::Profile profile,
                   std::vector<std::pair<std::filesystem::path,
                                        Dac::PathContract>>& plan,
                   std::string& error) {
    std::ifstream passwd(homes.passwdPath);
    if (!passwd.is_open()) {
        error = "cannot open local account database " + homes.passwdPath.string();
        return false;
    }
    std::string line;
    while (std::getline(passwd, line)) {
        std::vector<std::string> fields;
        std::size_t begin = 0;
        for (;;) {
            const std::size_t end = line.find(':', begin);
            fields.push_back(line.substr(begin, end - begin));
            if (end == std::string::npos) break;
            begin = end + 1;
        }
        if (fields.size() != 7) {
            error = "malformed local account record";
            return false;
        }
        const std::string& account = fields[0];
        if (account.empty() || account.find_first_not_of(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") !=
                std::string::npos) {
            error = "unsafe local account name";
            return false;
        }
        char* end = nullptr;
        errno = 0;
        const unsigned long uid = std::strtoul(fields[2].c_str(), &end, 10);
        if (errno != 0 || end == fields[2].c_str() || *end != '\0') {
            error = "invalid local account user id";
            return false;
        }
        end = nullptr;
        errno = 0;
        const unsigned long gid = std::strtoul(fields[3].c_str(), &end, 10);
        if (errno != 0 || end == fields[3].c_str() || *end != '\0') {
            error = "invalid local account group id";
            return false;
        }
        const std::filesystem::path home = fields[5];
        if (home.parent_path() != homes.rootPath || home.filename() != account)
            continue;
        const struct group* groupEntry = ::getgrgid(static_cast<gid_t>(gid));
        const struct passwd* passwdEntry = ::getpwnam(account.c_str());
        if (groupEntry == nullptr || passwdEntry == nullptr ||
            passwdEntry->pw_uid != static_cast<uid_t>(uid) ||
            passwdEntry->pw_gid != static_cast<gid_t>(gid)) {
            error = "local account and NSS identity mismatch for " + account;
            return false;
        }
        Dac::PathContract contract;
        contract.metadata = {account, groupEntry->gr_name,
                             homes.directoryModes.at(profile)};
        contract.objectType = Dac::ObjectType::Directory;
        contract.required = false;
        plan.emplace_back(home, std::move(contract));
    }
    return passwd.eof();
}

bool supports(const Dac::Object& object, Dac::Profile profile) {
    return std::visit([&](const auto& target) {
        if constexpr (std::is_same_v<std::decay_t<decltype(target)>,
                                     Dac::PathCollectionObject>) {
            return !target.members.empty() &&
                std::all_of(target.members.begin(), target.members.end(),
                    [&](const Dac::CollectionMember& member) {
                        return member.profiles.count(profile) != 0;
                    });
        } else if constexpr (std::is_same_v<std::decay_t<decltype(target)>,
                                            Dac::UserHomesObject>) {
            return target.directoryModes.count(profile) != 0;
        } else {
            return target.profiles.count(profile) != 0;
        }
    }, object.target);
}
} // namespace

ModeAndOwnerProfilesPolicyTypeValue::ModeAndOwnerProfilesPolicyTypeValue(
    const Dac& platform) : platform_(platform) {
    std::ostringstream generatedDefault;
    for (std::size_t index = 0;
         index < platform_.modeAndOwnerObjects.size(); ++index) {
        if (index != 0) generatedDefault << '\n';
        generatedDefault << platform_.modeAndOwnerObjects[index].id
                         << "=system";
    }
    defaultValue = generatedDefault.str();
}

PolicyEditorSpec ModeAndOwnerProfilesPolicyTypeValue::getEditorSpec() const {
    PolicyEditorSpec spec;
    spec.editor = "textedit";
    spec.validator = "none";
    return spec;
}

bool ModeAndOwnerProfilesPolicyTypeValue::parse(
    const std::string& value, Selection& selection, std::string& error) const {
    selection.clear();
    std::istringstream input(value);
    std::string line;
    std::size_t lineNumber = 0;
    while (std::getline(input, line)) {
        ++lineNumber;
        line = trim(line);
        if (line.empty()) continue;
        const std::size_t separator = line.find('=');
        if (separator == std::string::npos ||
            line.find('=', separator + 1) != std::string::npos) {
            error = "line " + std::to_string(lineNumber) +
                    ": expected object=profile";
            return false;
        }
        const std::string id = trim(line.substr(0, separator));
        const std::string profileText = trim(line.substr(separator + 1));
        if (id.empty() || profileText.empty()) {
            error = "line " + std::to_string(lineNumber) +
                    ": object and profile must be non-empty";
            return false;
        }
        Dac::Profile profile;
        if (!parseProfile(profileText, profile)) {
            error = "unknown profile '" + profileText + "'";
            return false;
        }
        const Dac::Object* object = findObject(platform_, id);
        if (object == nullptr) {
            error = "unknown logical object '" + id + "'";
            return false;
        }
        if (!supports(*object, profile)) {
            error = "profile '" + profileText + "' is unavailable for '" +
                    id + "'";
            return false;
        }
        if (!selection.emplace(id, profile).second) {
            error = "duplicate logical object '" + id + "'";
            return false;
        }
    }
    return true;
}

bool ModeAndOwnerProfilesPolicyTypeValue::validate(const std::string& value) {
    Selection selection;
    std::string error;
    return parse(value, selection, error);
}

std::string ModeAndOwnerProfilesPolicyTypeValue::postProcessingValue(
    const std::string& value) {
    Selection selection;
    std::string error;
    if (!parse(value, selection, error)) {
        throw std::invalid_argument(error);
    }
    nlohmann::json stored = nlohmann::json::object();
    for (const auto& [id, profile] : selection) stored[id] = profileName(profile);
    return stored.dump();
}

std::string ModeAndOwnerProfilesPolicyTypeValue::reverse_postProcessingValue(
    const std::string& value) {
    try {
        const nlohmann::json stored = nlohmann::json::parse(value);
        if (!stored.is_object()) return "<invalid stored value>";
        std::ostringstream result;
        bool first = true;
        for (auto it = stored.begin(); it != stored.end(); ++it) {
            if (!it.value().is_string()) return "<invalid stored value>";
            if (!first) result << '\n';
            result << it.key() << '=' << it.value().get<std::string>();
            first = false;
        }
        return result.str();
    } catch (const nlohmann::json::exception&) {
        return "<invalid stored value>";
    }
}

std::string ModeAndOwnerProfilesPolicyTypeValue::getPolicyRestrictionInfo() {
    std::ostringstream result;
    result << "Format: object=profile. Available logical objects:";
    for (const Dac::Object& object : platform_.modeAndOwnerObjects) {
        result << "\n" << object.id << ":";
        for (Dac::Profile profile : {Dac::Profile::System,
                                    Dac::Profile::Minimum,
                                    Dac::Profile::Optimal,
                                    Dac::Profile::Strict}) {
            if (supports(object, profile)) result << ' ' << profileName(profile);
        }
    }
    return result.str();
}

DAC_mode_and_owner_profiles::DAC_mode_and_owner_profiles(const Dac& platform)
    : ModeAndOwner(), platform_(platform) {
    policyName = "mode_and_owner_profiles";
    policyTypeValue =
        std::make_unique<ModeAndOwnerProfilesPolicyTypeValue>(platform_);
}

bool DAC_mode_and_owner_profiles::apply() {
    const std::optional<std::string> value = getValue();
    if (!value) return false;
    ModeAndOwnerProfilesPolicyTypeValue::Selection selection;
    std::string error;
    const auto& valueType = static_cast<const ModeAndOwnerProfilesPolicyTypeValue&>(
        getPolicyTypeValue());
    if (!valueType.parse(*value, selection, error)) {
        log("Invalid mode_and_owner_profiles value: " + error, logLevel::ERROR);
        return false;
    }

    std::vector<std::pair<std::filesystem::path, Dac::PathContract>> pathPlan;
    std::optional<fic::platform::TcbCredentialStorageConfig> tcbPlan;
    for (const auto& [id, profile] : selection) {
        const Dac::Object* object = findObject(platform_, id);
        if (const auto* path = std::get_if<Dac::StaticPathObject>(&object->target)) {
            pathPlan.emplace_back(path->path, path->profiles.at(profile));
        } else if (const auto* collection =
                       std::get_if<Dac::PathCollectionObject>(&object->target)) {
            for (const Dac::CollectionMember& member : collection->members)
                pathPlan.emplace_back(member.path, member.profiles.at(profile));
        } else if (const auto* homes =
                       std::get_if<Dac::UserHomesObject>(&object->target)) {
            if (!planUserHomes(*homes, profile, pathPlan, error)) {
                log("UserHomes preflight failed: " + error, logLevel::ERROR);
                return false;
            }
        } else if (const auto* tcb =
                       std::get_if<Dac::TcbCredentialTreeObject>(&object->target)) {
            tcbPlan = tcb->profiles.at(profile);
        } else {
            log("Selected handler is not yet executable: " + id,
                logLevel::ERROR);
            return false;
        }
    }
    // Publish the fully validated plan only after every selected object has
    // passed semantic and handler-specific preflight.
    expected.clear();
    selectedTcb_ = std::move(tcbPlan);
    for (const auto& [path, contract] : pathPlan)
        addExpectedRule(path, contract);
    return ModeAndOwner::apply();
}

void DAC_mode_and_owner_profiles::applyAdditionalRules(
    ApplyCounters& counters) {
    if (selectedTcb_) {
        applyTcbCredentialTree(*selectedTcb_, counters);
    }
}
