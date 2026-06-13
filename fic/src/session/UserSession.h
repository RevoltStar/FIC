#ifndef USER_SESSION_H
#define USER_SESSION_H

#include <string>
#include <sys/types.h>

struct UserSession {
    std::string id;
    uid_t uid = 0;
    std::string user;
    std::string type;
};

struct SessionContext {
    std::string sessionId;
    std::string desktop;
    std::string sessionType;
    std::string display;
    std::string waylandDisplay;
};

#endif // USER_SESSION_H
