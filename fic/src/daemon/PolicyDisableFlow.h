#ifndef FIC_DAEMON_POLICY_DISABLE_FLOW_H
#define FIC_DAEMON_POLICY_DISABLE_FLOW_H

#include "daemon/PolicyMutationResult.h"
#include "rollback/RollbackExecutor.h"

#include <string>

namespace fic::daemon {

PolicyMutationResult disablePolicyAfterLookup(
    const PolicyRef& policy,
    const std::string& resourceHint,
    const fic::rollback::RollbackExecutorDeps& rollbackDeps);

} // namespace fic::daemon

#endif // FIC_DAEMON_POLICY_DISABLE_FLOW_H
