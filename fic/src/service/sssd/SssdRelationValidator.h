#pragma once
#include "service/sssd/SssdEffectiveConfiguration.h"
namespace fic::service::sssd {
struct RelationResult {
    SemanticStatus status=SemanticStatus::Validated;
    std::map<std::string,SemanticStatus> domains;
    std::vector<SemanticIssue> issues;
    bool semanticProjectionValidated() const {return status==SemanticStatus::Validated;}
};
// No policy-enabled flags: foreign/default inputs participate unconditionally.
RelationResult validateRelations(const EffectiveConfiguration&);
}
