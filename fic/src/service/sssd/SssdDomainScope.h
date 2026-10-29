#pragma once
#include "service/sssd/SssdVerifiedInputClosure.h"
#include <memory>
#include <optional>
namespace fic::service::sssd {
enum class SemanticStatus { Validated, Conflict, UnsupportedProvider, UnknownSemantics, UnsupportedConfiguration, InvalidInput, NotProven };
const char* semanticStatusName(SemanticStatus);
struct SemanticIssue { SemanticStatus status; std::string section, key, diagnostic; };
enum class ProviderClass { LdapPassword, Proxy, Ad, Ipa, Unknown };
struct Domain {
    std::string name, idProvider, authProvider;
    ProviderClass provider=ProviderClass::Unknown;
    bool selected=false, enabled=false, authDefault=false, dynamicPossible=false, trustedPossible=false;
    std::optional<bool> enabledSetting;
    std::vector<std::string> requiredConsumers;
    std::vector<SemanticIssue> issues;
};
struct DomainScopeData {
    unsigned formatVersion=1;
    bool hypothetical=false;
    std::string proposedGraphFingerprint;
    std::string platform, graphFingerprint, launchFingerprint, projectionFingerprint;
    // Owned immutable copy, no borrowed I1 pointers. Not a runtime receipt.
    std::shared_ptr<const SssdInputReference> input;
    std::vector<std::string> configured, selected, enabled, expectedBackends, unselected;
    std::map<std::string,Domain> domains;
    std::vector<SemanticIssue> issues;
};
// Immutable data container, not an authority token. Canonical consumers must
// verify all structural facts against the I1-derived scope, not just digests.
class DomainScopeReference {
    std::shared_ptr<const DomainScopeData> data_;
public:
    explicit DomainScopeReference(DomainScopeData data):data_(std::make_shared<const DomainScopeData>(std::move(data))){}
    const DomainScopeData& data() const {return *data_;}
};
std::string inputFingerprint(const SssdInputReference&);
DomainScopeReference domainScope(const SssdInputReference&);
// Full structural comparison, including derived facts and bound input observations.
// Matching stored fingerprints alone never establish equivalence.
bool sameScopeReference(const DomainScopeReference&,const DomainScopeReference&);
namespace detail_i2 {
using OrderedGraph=std::vector<std::pair<std::string,IniProjection>>;
OrderedGraph orderedGraph(const SssdInputReference&);
IniProjection merge(const OrderedGraph&);
DomainScopeReference scopeProjection(const SssdInputReference&,const IniProjection&,const OrderedGraph* hypothetical=nullptr);
std::optional<bool> boolean(const std::string&);
}
} // namespace fic::service::sssd
