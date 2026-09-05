#ifndef FIC_SUDO_SECURE_PATH_POLICY_TYPE_VALUE_H
#define FIC_SUDO_SECURE_PATH_POLICY_TYPE_VALUE_H

#include <fic/policy/PolicyTypeValue.h>

#include <string>
#include <vector>

class SudoSecurePathPolicyTypeValue final
    : public MultiLineTextPolicyTypeValue
{
public:
    explicit SudoSecurePathPolicyTypeValue(std::string defaultValue);

    bool validate(const std::string& value) override;
    std::string postProcessingValue(const std::string& value) override;
    std::string reverse_postProcessingValue(const std::string& value) override;
    std::string getPolicyRestrictionInfo() override;

private:
    static std::string trimCopy(std::string value);
    static bool isSeparator(char value);
    static std::vector<std::string> splitSecurePath(const std::string& value);
    static std::string joinSecurePath(
        const std::vector<std::string>& paths,
        const std::string& delimiter);
    static bool isValidAbsoluteDirectoryPath(const std::string& path);
};

#endif // FIC_SUDO_SECURE_PATH_POLICY_TYPE_VALUE_H
