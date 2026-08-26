#ifndef FIC_IDENTITY_LOCAL_GROUP_DATABASE_H
#define FIC_IDENTITY_LOCAL_GROUP_DATABASE_H

#include <filesystem>
#include <string>

namespace fic::identity {

bool isValidLocalGroupName(const std::string& value);
bool localGroupExistsExactlyOnce(
    const std::filesystem::path& path,
    const std::string& expected);

} // namespace fic::identity

#endif
