#ifndef FIC_PACKAGE_TRUST_SYNC_H
#define FIC_PACKAGE_TRUST_SYNC_H

#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"

#include <cstddef>
#include <string>

namespace fic::trust {

struct PackageTrustSyncResult {
    std::size_t updated = 0;
    std::size_t unavailable = 0;
};

bool syncPackageManagedExecutables(
    const fic::platform::PlatformProfile& platform,
    const fic::platform::PlatformExecutableResolver& executables,
    PackageTrustSyncResult& result,
    std::string& error);

} // namespace fic::trust

#endif // FIC_PACKAGE_TRUST_SYNC_H
