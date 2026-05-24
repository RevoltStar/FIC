#include "modules/dac/submodules/modeandowner/DAC_custom_mode_and_owner.h"

#include <algorithm>
#include <cctype>
#include <regex>
#include <sstream>

namespace {
struct ModeAndOwnerRule {
    std::string path;
    std::string owner;
    std::string group;
    std::string mode;
};

std::string trim_copy(std::string value) {
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), value.end());
    return value;
}

std::vector<std::string> split_lines(const std::string& value) {
    std::vector<std::string> lines;
    std::stringstream ss(value);
    std::string line;

    while (std::getline(ss, line)) {
        line = trim_copy(line);
        if (!line.empty()) {
            lines.push_back(line);
        }
    }

    return lines;
}

bool parse_rule_line(const std::string& line, ModeAndOwnerRule& out_rule) {
    std::stringstream ss(line);
    std::string segment;
    std::vector<std::string> parts;

    while (std::getline(ss, segment, '|')) {
        parts.push_back(trim_copy(segment));
    }

    if (parts.size() != 4) {
        return false;
    }

    if (parts[0].empty() || parts[1].empty() || parts[2].empty() || parts[3].empty()) {
        return false;
    }

    if (parts[0][0] != '/') {
        return false;
    }

    static const std::regex mode_regex("^[0-7]{3,4}$");
    if (!std::regex_match(parts[3], mode_regex)) {
        return false;
    }

    out_rule.path = parts[0];
    out_rule.owner = parts[1];
    out_rule.group = parts[2];
    out_rule.mode = parts[3];
    return true;
}

bool parse_rules_text(const std::string& value, std::vector<ModeAndOwnerRule>& out_rules) {
    out_rules.clear();

    const std::vector<std::string> lines = split_lines(value);
    if (lines.empty()) {
        return true;
    }

    for (const std::string& line : lines) {
        ModeAndOwnerRule rule;
        if (!parse_rule_line(line, rule)) {
            return false;
        }
        out_rules.push_back(rule);
    }

    return true;
}

std::string join_rules_text(const std::vector<ModeAndOwnerRule>& rules) {
    std::string result;
    for (size_t i = 0; i < rules.size(); ++i) {
        if (i != 0) {
            result += "\n";
        }
        result += rules[i].path + "|" + rules[i].owner + "|" + rules[i].group + "|" + rules[i].mode;
    }
    return result;
}

class CustomModeAndOwnerPolicyTypeValue : public MultiLineTextPolicyTypeValue {
public:
    CustomModeAndOwnerPolicyTypeValue()
        : MultiLineTextPolicyTypeValue("\n", "\n") {
        this->defaultValue = "";
    }

    bool validate(const std::string& value) override {
        std::vector<ModeAndOwnerRule> rules;
        return parse_rules_text(value, rules);
    }

    std::string postProcessingValue(const std::string& value) override {
        std::vector<ModeAndOwnerRule> rules;
        if (!parse_rules_text(value, rules)) {
            return "";
        }

        json serialized = json::array();
        for (const auto& rule : rules) {
            serialized.push_back({
                {"path", rule.path},
                {"owner", rule.owner},
                {"group", rule.group},
                {"mode", rule.mode}
            });
        }

        return serialized.dump();
    }

    std::string reverse_postProcessingValue(const std::string& value) override {
        try {
            auto parsed = json::parse(value);
            if (!parsed.is_array()) {
                return value;
            }

            std::vector<ModeAndOwnerRule> rules;
            for (const auto& item : parsed) {
                if (!item.is_object()) {
                    return value;
                }

                ModeAndOwnerRule rule;
                rule.path = item.at("path").get<std::string>();
                rule.owner = item.at("owner").get<std::string>();
                rule.group = item.at("group").get<std::string>();
                rule.mode = item.at("mode").get<std::string>();
                rules.push_back(rule);
            }

            return join_rules_text(rules);
        } catch (const json::exception&) {
            return value;
        }
    }

    std::string getPolicyRestrictionInfo() override {
        return "Укажите по одному правилу на строку в формате: /path|owner|group|0644. "
               "Допускаются только абсолютные пути и права в восьмеричном виде из 3 или 4 цифр.";
    }
};
} // namespace

DAC_custom_mode_and_owner::DAC_custom_mode_and_owner()
    : ModeAndOwner() {
    this->policyName = "custom_mode_and_owner";
    this->policyTypeValue = std::make_unique<CustomModeAndOwnerPolicyTypeValue>();
}

bool DAC_custom_mode_and_owner::check_and_fix() {
    this->expected.clear();

    const std::optional valueOpt = this->getValue();
    if(!valueOpt){
        return false;
    }
    std::string value = *valueOpt;
    std::vector<ModeAndOwnerRule> rules;
    if (!parse_rules_text(value, rules)) {
        this->log("Не удалось разобрать правила custom_mode_and_owner", logLevel::ERROR);
        return false;
    }

    for (const auto& rule : rules) {
        const mode_t permissions = static_cast<mode_t>(std::stoi(rule.mode, nullptr, 8));
        this->expected.insert_or_assign(rule.path, FileStats(rule.owner, rule.group, permissions));
    }

    return this->ModeAndOwner::check_and_fix();
}
