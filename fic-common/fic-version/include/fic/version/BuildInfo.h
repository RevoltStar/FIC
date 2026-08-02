#ifndef FIC_BUILD_INFO_H
#define FIC_BUILD_INFO_H

#include <fic/version/ProductVersion.h>

#include <ostream>
#include <string_view>

namespace fic::version {

inline void writeBuildInfo(std::ostream& output, std::string_view component)
{
    output << "component=" << component << '\n'
           << "product_version=" << PRODUCT_VERSION << '\n'
           << "build_kind=" << BUILD_KIND << '\n'
           << "build_commit=" << BUILD_COMMIT << '\n'
           << "release_tag=" << RELEASE_TAG << '\n'
           << "ipc_api_version=" << IPC_API_VERSION << '\n'
           << "config_schema_version=" << CONFIG_SCHEMA_VERSION << '\n'
           << "device_db_schema_version=" << DEVICE_DB_SCHEMA_VERSION << '\n';
}

} // namespace fic::version

#endif // FIC_BUILD_INFO_H
