#ifndef COMMAND_HASH_STORE_H
#define COMMAND_HASH_STORE_H

#include <string>
#include <functional>
#include <vector>

class CommandHashStore {
public:
    static bool saveHash(const std::string& executable, std::string& error);
    static bool saveHashes(const std::vector<std::string>& executables,
                           std::string& error);
    static bool updateHashes(const std::vector<std::string>& executables,
                             const std::vector<std::string>& removedExecutables,
                             std::string& error,
                           // Rechecked while holding the existing hash-store
                           // mutation lock, before reading/updating managed data.
                           const std::function<bool(std::string&)>& admission = {});
    static bool verifyHash(const std::string& executable, std::string& error);
};

#endif // COMMAND_HASH_STORE_H
