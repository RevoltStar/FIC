#ifndef FIC_COMMAND_HASH_STORE_INTERNAL_H
#define FIC_COMMAND_HASH_STORE_INTERNAL_H

#include <string>

namespace command_hash_store_detail {

bool validateExecutablePathSyntax(const std::string& executable,
                                  std::string& error);
bool validateCommandHashStoreKey(const std::string& executable,
                                 std::string& error);
bool calculateSha256FromFd(int descriptor, std::string& hash,
                           std::string& error);
bool calculateValidatedExecutableSha256(const std::string& executable,
                                        std::string& hash,
                                        std::string& error);

} // namespace command_hash_store_detail

#endif // FIC_COMMAND_HASH_STORE_INTERNAL_H
