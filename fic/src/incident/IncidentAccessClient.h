#pragma once

#include <string>
#include <sys/types.h>

namespace fic::incident {

struct IncidentAccessReply {
    bool allowed = false;
    std::string diagnostic;
};

class IncidentAccessClient {
public:
    // Fixed production endpoint, root peer, one request and a two-second
    // deadline. No PAM argument or environment variable selects an endpoint.
    static IncidentAccessReply query();

    // Isolated socket fixture uses the same strict response checks with an
    // explicit fixture peer UID. Production remains fixed to root.
    static IncidentAccessReply queryAtPathForTests(
        const std::string& path, uid_t expectedPeerUid);
};

} // namespace fic::incident
