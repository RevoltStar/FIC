#pragma once
#include "service/sssd/SssdServiceAdmission.h"
#ifdef FIC_SSSD_I1_TESTING
#include <functional>
#endif
namespace fic::service::sssd {
struct Source {
    bool present=false;
    detail::Identity identity;
    detail::Tree tree;
};
struct IniValue { std::string value, source; };
using IniProjection = std::map<std::string,std::map<std::string,IniValue>>;
struct SssdInputReference {
    SssdLaunchReference launch;
    // Main, complete conf.d, environment, and pinned absence-parent observations.
    std::map<std::string,Source> sources;
    std::vector<std::string> order, negativeDependencies, laterForeignSnippets;
    IniProjection ini;
    std::map<std::string,std::string> consumers;
    ActivationRequest inputs; // Existing sources only; absence is NOT engine-covered.
    bool engineNeedsNegativeDependencySupport=false;
    // zzzz-fic.conf is observed, never inferred to be owned from its name.
    bool applyConflict() const { return !laterForeignSnippets.empty(); }
};
SssdInputReference capture(Deadline deadline);
void revalidate(const SssdInputReference&, Deadline deadline);
namespace detail_i1 {
// Pure bounded syntax subset, not a domain/provider semantics validator.
IniProjection project(const std::vector<std::string>& order,const std::map<std::string,std::string>& bytes);
bool loadedSnippet(const std::string& name);
void validateConsumerIdentity(const IniProjection&,const std::string& platform);
#ifdef FIC_SSSD_I1_TESTING
// Compiled out of production. Checkpoint after first complete graph read.
SssdInputReference captureForTests(const SssdLaunchReference&,const std::string& root,Deadline,
                                 const std::function<void()>& checkpoint={});
#endif
}
} // namespace fic::service::sssd
