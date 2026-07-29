#ifndef SESSION_LOCATOR_H
#define SESSION_LOCATOR_H

#include "session/UserSession.h"

#include <string>
#include <vector>

class SessionLocator {
public:
    static bool activeGraphicalSessions(
        const std::vector<std::string>& loginctlCandidates,
        std::vector<UserSession>& sessions,
        std::string& error);
};

#endif // SESSION_LOCATOR_H
