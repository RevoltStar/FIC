#ifndef SSH_H
#define SSH_H

#include "modules/net/NET.h"
#include "utils/FileHandler.h"

#include <memory>
#include <string>
#include <unordered_map>

class SshConfigFileHandler : public FileHandler {
public:
    SshConfigFileHandler(const std::string& filepath);

    bool loadConfig() override;
    std::string getValue(const std::string& parameter) const override;
    bool setValue(const std::string& parameter, const std::string& value) override;
    void printConfig() const override;
    bool isParameterExists(const std::string& parameter) const;

private:
    static std::string trimCopy(std::string value);
    static std::string toLower(std::string value);
    static bool isCommentOrEmpty(const std::string& line);
    static std::string stripInlineComment(const std::string& line);
    static bool parseDirective(const std::string& line, std::string& parameter, std::string& value);
    size_t findFirstMatchLine() const;

    std::unordered_map<std::string, std::string> config_;
    std::unordered_map<std::string, std::string> canonicalNames_;
};

class Ssh : public Net
{
protected:
    const static std::string sshPath;
    static std::unique_ptr<SshConfigFileHandler> sshConfig;
    std::string sshParameter;

public:
    Ssh();
    bool check_and_fix() override;
    virtual ~Ssh();
};

#endif // SSH_H
