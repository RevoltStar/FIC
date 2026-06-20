#ifndef COMMAND_HASH_STORE_H
#define COMMAND_HASH_STORE_H

#include <string>

class CommandHashStore {
public:
    static bool saveHash(const std::string& executable, std::string& error);
    static bool verifyHash(const std::string& executable, std::string& error);

private:
    static bool isValidExecutablePath(const std::string& executable, std::string& error);
    static std::string calculateSha256(const std::string& executable, std::string& error);
};

#endif // COMMAND_HASH_STORE_H
