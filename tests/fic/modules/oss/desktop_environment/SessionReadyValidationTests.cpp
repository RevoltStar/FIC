#include "session/SessionReadyValidation.h"

#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <vector>
#include <iostream>

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
int calls=0, failure=0;
std::vector<std::size_t> sizes;
int lookup(uid_t uid, passwd* entry, char* buffer, std::size_t size, passwd** result) {
    ++calls;sizes.push_back(size);*result=nullptr;
    if(failure==1)return 0;
    if(failure==2)return EIO;
    if(failure==3&&calls==1)return ERANGE;
    if(failure==4)return ERANGE;
    const char* name=failure==5?"":"admsys";
    std::strcpy(buffer,name);entry->pw_uid=failure==7?uid+1:uid;entry->pw_name=failure==6?nullptr:buffer;*result=entry;return 0;
}
void construction() {
    using session_ready_validation::buildSession;
    UserSession session;std::string error;
    for(const auto* type:{"wayland","x11","mir","tty"}) {
        calls=0;failure=0;
        require(buildSession(1000,1000,"3","user","active",type,true,session,error,lookup),"valid construction rejected");
        require(session.id=="3"&&session.uid==1000&&session.user=="admsys"&&session.type==type,
            "production session construction omitted NSS username");
        require(calls==1,"unexpected NSS count");
    }
    for(const auto* type:{"tty","unspecified"}) {
        calls=0;require(!buildSession(1000,1000,"3","user","active",type,false,session,error,lookup),"invalid type accepted");
        require(calls==0&&session.user.empty()&&!error.empty(),"invalid claim reached NSS");
    }
    calls=0;require(!buildSession(1000,1001,"3","user","active","wayland",false,session,error,lookup),"UID mismatch accepted");
    require(calls==0&&session.id.empty(),"mismatched UID resolved/published");
    for(int mode:{1,2,3,4,5,6,7}) {
        failure=mode;calls=0;sizes.clear();session={"stale",42,"stale","x11"};
        const bool ok=buildSession(1000,1000,"3","user","active","wayland",false,session,error,lookup);
        require(ok==(mode==3),"NSS error handling changed");
        if(ok)require(session.user=="admsys"&&calls==2&&sizes[1]>sizes[0],"ERANGE not retried with larger buffer");
        else require(session.id.empty()&&session.user.empty()&&!error.empty(),"NSS failure published incomplete/stale identity");
        if(mode==4)require(calls>1&&calls<=16&&sizes.back()<=4U*1024U*1024U,"unbounded NSS retry");
    }
    std::cout<<"NSS session construction/type/UID/errors/bounded ERANGE PASS\n";
}
}

int main() {
    construction();
    using session_ready_validation::validLogindClaim;
    require(validLogindClaim(1000, 1000, "user", "active", "wayland", false),
            "valid graphical session rejected");
    require(!validLogindClaim(1000, 1001, "user", "active", "wayland", false),
            "UID/session mismatch accepted");
    require(!validLogindClaim(1000, 1000, "manager", "active", "wayland", false),
            "non-user session accepted");
    require(!validLogindClaim(1000, 1000, "user", "closing", "x11", false),
            "closing session accepted");
    require(!validLogindClaim(1000, 1000, "user", "dead", "x11", false),
            "dead session accepted");
    require(!validLogindClaim(1000, 1000, "user", "active", "tty", false),
            "plain non-graphical TTY accepted");
    require(validLogindClaim(1000, 1000, "user", "online", "tty", true),
            "session-bound graphical startx candidate rejected");
    require(!validLogindClaim(1000, 1000, "user", "active", "unspecified", true),
            "unknown logind session type accepted");
    return 0;
}
