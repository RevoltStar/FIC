#ifndef KDE_SCREEN_LOCKER_RUNTIME_CONTEXT_RESOLVER_H
#define KDE_SCREEN_LOCKER_RUNTIME_CONTEXT_RESOLVER_H

#include "session/SessionCommandExecutor.h"
#include "session/UserSession.h"

#include <functional>
#include <string>
#include <vector>

struct KdeScreenLockerRuntimeContext {
    std::string uniqueBusOwner;
    pid_t pid = 0;
    uid_t uid = 0;
    std::vector<SessionEnvironmentOverride> kconfigEnvironment;
};

struct KdeScreenLockerRuntimeContextResolverDependencies {
    std::function<std::string(const std::vector<std::string>&)> findExecutable;
    std::function<ProcessResult(
        const UserSession&, const SessionContext&, const std::string&,
        const std::vector<std::string>&)> execute;
    std::function<bool(pid_t, std::string&, std::string&)> readEnviron;
};

class KdeScreenLockerRuntimeContextResolver {
public:
    KdeScreenLockerRuntimeContextResolver();
    explicit KdeScreenLockerRuntimeContextResolver(
        KdeScreenLockerRuntimeContextResolverDependencies dependencies);

    bool resolve(const UserSession& session, const SessionContext& context,
                 std::size_t sameUidKdeSessionCount,
                 KdeScreenLockerRuntimeContext& result,
                 std::string& error) const;
    bool validate(const UserSession& session, const SessionContext& context,
                  const KdeScreenLockerRuntimeContext& captured,
                  std::string& error) const;

private:
    KdeScreenLockerRuntimeContextResolverDependencies dependencies_;
};

#endif // KDE_SCREEN_LOCKER_RUNTIME_CONTEXT_RESOLVER_H
