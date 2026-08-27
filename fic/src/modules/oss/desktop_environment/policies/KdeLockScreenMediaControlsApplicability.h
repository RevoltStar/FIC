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

bool applyToKdeSessions(const std::vector<UserSession>& sessions,
                        const ContextQuery& queryContext,
                        const SessionApply& applySession,
                        std::size_t& applicableSessions);

} // namespace kde_lock_screen_media_controls

#endif // KDE_LOCK_SCREEN_MEDIA_CONTROLS_APPLICABILITY_H
