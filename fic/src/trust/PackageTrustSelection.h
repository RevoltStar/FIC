#ifndef FIC_PACKAGE_TRUST_SELECTION_H
#define FIC_PACKAGE_TRUST_SELECTION_H

#include "platform/PlatformProfile.h"

#include <istream>
#include <vector>

namespace fic::trust {

std::vector<fic::platform::ExecutableId> selectAffectedExecutableIds(
    const fic::platform::PlatformExecutables& executables,
    std::istream& affectedPaths);

} // namespace fic::trust

#endif // FIC_PACKAGE_TRUST_SELECTION_H
