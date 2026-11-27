#include "modules/identity_access/pam/PamNopasswdloginFragment.h"

#include <algorithm>
#include <sstream>

namespace fic::identity::pam {
namespace {

constexpr char marker[] = "# FIC_PAM_NOPASSWDLOGIN";

bool reject(std::string& error, const std::string& message) {
    error = message;
    return false;
}

std::string anchor(const PamRule& rule) {
    std::ostringstream out;
    out << pamManagementGroupName(rule.group) << ' ' << rule.control << ' ';
    if (rule.includeKind != PamIncludeKind::None) {
        out << rule.includeTarget;
    } else {
        out << rule.module;
        for (const auto& argument : rule.arguments) out << ' ' << argument;
    }
    return out.str();
}

bool sameProof(const fic::rollback::UndoRestorePamSuppression& left,
               const fic::rollback::UndoRestorePamSuppression& right) {
    return left.service == right.service && left.original == right.original &&
        left.previousAnchor == right.previousAnchor && left.nextAnchor == right.nextAnchor;
}

bool targetSpan(const std::string& content, const PamRule& target,
                std::size_t& begin, std::size_t& end, std::string& error) {
    begin = 0;
    for (std::size_t line = 1; line < target.line; ++line) {
        const auto newline = content.find('\n', begin);
        if (newline == std::string::npos) return reject(error, "Invalid PAM rule position");
        begin = newline + 1;
    }
    end = begin;
    if (target.endLine < target.line) return reject(error, "Invalid PAM rule extent");
    for (std::size_t line = target.line; line <= target.endLine; ++line) {
        end = content.find('\n', end);
        if (end == std::string::npos) return reject(error, "Suppressed PAM rule needs a following line");
        ++end;
    }
    return true;
}

} // namespace

bool referencesNopasswdlogin(const PamRule& rule) {
    for (const auto& argument : rule.arguments) {
        std::istringstream groups(argument);
        std::string group;
        while (std::getline(groups, group, ':')) {
            if (group == "nopasswdlogin") return true;
        }
    }
    return false;
}

bool planNopasswdloginSuppression(
    const std::filesystem::path& source, const std::string& service,
    const std::string& content, std::optional<fic::rollback::UndoRestorePamSuppression>& plan,
    PamRule& target, std::string& error) {
    plan.reset();
    error.clear();
    if (content.find(marker) != std::string::npos) {
        return reject(error, "PAM suppression marker requires journal-bound verification");
    }
    std::vector<PamRule> rules;
    if (!PamConfiguration::parseRulesContent(source, content, rules, error)) return false;
    const std::vector<std::string> expected{"user", "ingroup", "nopasswdlogin"};
    for (std::size_t index = 0; index < rules.size(); ++index) {
        const auto& rule = rules[index];
        if (!referencesNopasswdlogin(rule)) continue;
        if (plan || rule.group != PamManagementGroup::Auth ||
            rule.control != "sufficient" || rule.module != "pam_succeed_if.so" ||
            rule.includeKind != PamIncludeKind::None || rule.arguments != expected) {
            return reject(error, "Unsupported or duplicate nopasswdlogin PAM rule");
        }
        std::size_t begin = 0, end = 0;
        if (!targetSpan(content, rule, begin, end, error)) return false;
        fic::rollback::UndoRestorePamSuppression proof;
        proof.service = service;
        proof.original = content.substr(begin, end - begin);
        for (std::size_t previous = index; previous > 0; --previous) {
            if (rules[previous - 1].group == PamManagementGroup::Auth) {
                proof.previousAnchor = anchor(rules[previous - 1]);
                break;
            }
        }
        for (std::size_t next = index + 1; next < rules.size(); ++next) {
            if (rules[next].group == PamManagementGroup::Auth) {
                proof.nextAnchor = anchor(rules[next]);
                break;
            }
        }
        if (proof.nextAnchor.empty()) return reject(error, "Missing PAM authentication continuation");
        std::vector<std::string> remaining;
        for (std::size_t other = 0; other < rules.size(); ++other) {
            if (other != index && rules[other].group == PamManagementGroup::Auth) {
                remaining.push_back(anchor(rules[other]));
            }
        }
        std::size_t positions = 0;
        for (std::size_t gap = 0; gap <= remaining.size(); ++gap) {
            const auto previous = gap ? remaining[gap - 1] : std::string{};
            const auto next = gap < remaining.size() ? remaining[gap] : std::string{};
            if (previous == proof.previousAnchor && next == proof.nextAnchor) ++positions;
        }
        if (positions != 1) return reject(error, "Ambiguous PAM suppression placement");
        target = rule;
        plan = std::move(proof);
    }
    return true;
}

std::string nopasswdloginWrapper(
    fic::rollback::MutationId id, const fic::rollback::UndoRestorePamSuppression& proof) {
    const auto identity = " v1 service=" + proof.service + " id=" + std::to_string(id);
    std::string commented;
    for (std::size_t begin = 0; begin < proof.original.size();) {
        const auto newline = proof.original.find('\n', begin);
        const auto end = newline == std::string::npos ? proof.original.size() : newline + 1;
        commented += "# " + proof.original.substr(begin, end - begin);
        begin = end;
    }
    return std::string(marker) + " BEGIN" + identity + "\n" + commented +
        marker + " END" + identity + "\n";
}

bool restoreNopasswdloginFragment(
    const std::filesystem::path& source, const std::string& content,
    fic::rollback::MutationId id, const fic::rollback::UndoRestorePamSuppression& proof,
    std::string& restored, PamRule& target, std::string& error) {
    if (!id) return reject(error, "Missing journal mutation id");
    const auto wrapper = nopasswdloginWrapper(id, proof);
    const auto begin = content.find(wrapper);
    if (begin == std::string::npos || (begin && content[begin - 1] != '\n')) {
        return reject(error, "PAM suppression physical ownership mismatch");
    }
    auto candidate = content;
    candidate.replace(begin, wrapper.size(), proof.original);
    std::optional<fic::rollback::UndoRestorePamSuppression> observed;
    if (!planNopasswdloginSuppression(source, proof.service, candidate, observed, target, error)) {
        return false;
    }
    if (!observed || !sameProof(*observed, proof)) {
        return reject(error, "PAM suppression payload or placement mismatch");
    }
    restored = std::move(candidate);
    return true;
}

bool suppressNopasswdloginFragment(
    const std::filesystem::path& source, const std::string& content,
    fic::rollback::MutationId id, const fic::rollback::UndoRestorePamSuppression& proof,
    std::string& suppressed, std::string& error) {
    if (!id) return reject(error, "Missing journal mutation id");
    std::optional<fic::rollback::UndoRestorePamSuppression> observed;
    PamRule target;
    if (!planNopasswdloginSuppression(source, proof.service, content, observed, target, error)) {
        return false;
    }
    if (!observed || !sameProof(*observed, proof)) {
        return reject(error, "PAM suppression input changed");
    }
    std::size_t begin = 0, end = 0;
    if (!targetSpan(content, target, begin, end, error)) return false;
    auto candidate = content;
    candidate.replace(begin, end - begin, nopasswdloginWrapper(id, proof));
    suppressed = std::move(candidate);
    return true;
}

} // namespace fic::identity::pam
