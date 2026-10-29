#pragma once
#include "service/sssd/SssdDomainScope.h"
#include <variant>
#include <set>
#include <tuple>
namespace fic::service::sssd {
struct Days {std::uint32_t value;};
struct Seconds {std::uint32_t value;};
using SemanticValue=std::variant<std::monostate,Days,Seconds,bool>;
enum class ValueOrigin { Foreign, NativeDefault, FicOwned, Unknown, Proposed };
struct SettingKey {
    std::string section,key;
    bool operator<(const SettingKey& b) const {return std::tie(section,key)<std::tie(b.section,b.key);}
};
// Caller-supplied trusted assertion, NOT an ownership verifier. Future I4/I5
// must construct it from journal/CAS evidence; arbitrary callers grant no authority.
struct TrustedOwnershipContext {
    std::string graphFingerprint, proofIdentity;
    std::map<SettingKey,std::string> ownedValues;
};
struct EffectiveValue {
    SettingKey setting;
    SemanticValue value;
    ValueOrigin origin=ValueOrigin::Unknown;
    SemanticStatus status=SemanticStatus::Validated;
    bool explicitValue=false, hypothetical=false;
    std::string source, raw, diagnostic;
};
struct DomainValues {EffectiveValue cacheCredentials,accountDays,cachedAuthSeconds;std::optional<Seconds> expectedCachedAuthSeconds;};
struct EffectiveConfiguration {
    DomainScopeReference scope;
    EffectiveValue offlineDays;
    std::map<std::string,DomainValues> domains;
    std::vector<SemanticIssue> issues;
};
EffectiveConfiguration effectiveConfiguration(const SssdInputReference&,const TrustedOwnershipContext* =nullptr);
enum class ProposedOperation { Apply, Refresh, ReleasePreview };
struct ProposedSetting {SettingKey setting;SemanticValue value;}; // monostate = remove in ReleasePreview only.
struct ProposedChange {ProposedOperation operation;std::vector<ProposedSetting> settings;};
struct ConfigurationPreview {
    bool projectionAvailable=false; // Never confirms CAS, release or enrollment.
    SemanticStatus semanticStatus=SemanticStatus::NotProven;
    std::vector<SemanticIssue> semanticIssues;
    std::optional<EffectiveConfiguration> configuration;
    std::vector<SemanticIssue> issues;
};
ConfigurationPreview previewConfiguration(const SssdInputReference&,const DomainScopeReference&,
    const ProposedChange&,const TrustedOwnershipContext* =nullptr);
namespace detail_i2 {
EffectiveConfiguration effectiveProjection(const SssdInputReference&,const IniProjection&,
    const TrustedOwnershipContext*,const std::set<SettingKey>& proposed={},const OrderedGraph* hypothetical=nullptr);
bool ownershipMatches(const SssdInputReference&,const TrustedOwnershipContext&);
}
} // namespace fic::service::sssd
