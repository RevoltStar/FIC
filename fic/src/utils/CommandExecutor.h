#ifndef COMMANDEXECUTOR_H
#define COMMANDEXECUTOR_H

#include <string>
#include <memory>
#include <openssl/evp.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>
#include <cstring>
#include "utils/ConfigFileHandler.h"

class CommandExecutor {
private:
    static std::string commandHashFilePath;
    static std::unique_ptr<ConfigFileHandler> cfh;

    static bool isSymlink(const std::string& path);
    static bool checkCommandIsValid(const std::string& command);

public:
    // Calculate a SHA-256 hash for the command file.
    static std::string calcHashbyCommand(const std::string& command);

    // Calculate and store the command hash.
    static bool calcHash(const std::string& command);

    // Get the stored command hash.
    static std::string getHash(const std::string& command);

    // Verify the command hash.
    static bool checkHash(const std::string& command);

    // Execute the command after hash verification.
    static bool execute(const std::string& command, const std::string& param = "");
};

#endif // COMMANDEXECUTOR_H
