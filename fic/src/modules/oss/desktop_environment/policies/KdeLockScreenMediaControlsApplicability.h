#ifndef KDE_LOCK_SCREEN_MEDIA_CONTROLS_APPLICABILITY_H
#define KDE_LOCK_SCREEN_MEDIA_CONTROLS_APPLICABILITY_H

#include "session/UserSession.h"

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace kde_lock_screen_media_controls {

using ContextQuery = std::function<bool(
    const UserSession&, SessionContext&, std::string&)>;
using SessionApply = std::function<bool(
    const UserSession&, const SessionContext&)>;
using ContextFailure = std::function<void(
    const UserSession&, const std::string&)>;

struct ApplicabilityResult {
    bool success = true;
    std::size_t applicableSessions = 0;
    std::size_t classificationFailures = 0;

    bool notApplicable() const {
        return success && applicableSessions == 0;
    }
};

ApplicabilityResult applyToKdeSessions(
    const std::vector<UserSession>& sessions,
    const ContextQuery& queryContext,
    const SessionApply& applySession,
    const ContextFailure& reportContextFailure);

} // namespace kde_lock_screen_media_controls

#endif // KDE_LOCK_SCREEN_MEDIA_CONTROLS_APPLICABILITY_H
