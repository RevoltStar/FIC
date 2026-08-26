#ifndef SSHCONFIGFILE_H
#define SSHCONFIGFILE_H

#include <fic/core/fs/FileHandler.h>

#include <cstddef>
#include <string>
#include <unordered_map>

class SshConfigFileHandler : public FileHandler {
public:
    explicit SshConfigFileHandler(const std::string& filepath);

    bool loadConfig() override;
    std::string getValue(const std::string& parameter) const override;
    bool setValue(const std::string& parameter, const std::string& value) override;
    void printConfig() const override;
    bool isParameterExists(const std::string& parameter) const;

private:
    bool findFirstMatchLine(std::size_t& line) const;

    std::unordered_map<std::string, std::string> config_;
    std::unordered_map<std::string, std::string> canonicalNames_;
};

#endif // SSHCONFIGFILE_H
