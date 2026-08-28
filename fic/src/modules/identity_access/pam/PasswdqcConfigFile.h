#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWDQC_CONFIG_FILE_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWDQC_CONFIG_FILE_H

#include <array>
#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace fic::identity::pam {

struct PasswdqcMinimums {
    std::array<std::optional<unsigned int>, 5> values;

    bool operator==(const PasswdqcMinimums& other) const {
        return values == other.values;
    }
};

class PasswdqcMinimumsCodec {
public:
    static bool parse(const std::string& value,
                      PasswdqcMinimums& result,
                      std::string& error);
    static std::string serialize(const PasswdqcMinimums& value);
};

enum class PasswdqcDirectiveKind {
    Minimums,
    Maximum,
    PassphraseWords,
    MatchLength,
    Similar,
    RandomBits,
    Wordlist,
    Denylist,
    Filter,
    Enforce,
    NonUnix,
    Retry,
    AskOldAuthToken,
    CheckOldAuthToken,
    UseFirstPass,
    UseAuthToken,
    NoAudit,
    Config
};

struct PasswdqcDirective {
    PasswdqcDirectiveKind kind = PasswdqcDirectiveKind::Minimums;
    std::string option;
    std::string value;
    std::filesystem::path source;
    std::size_t line = 0;
};

struct PasswdqcEffectiveState {
    PasswdqcMinimums minimums;
    unsigned int maximum = 72;
    unsigned int passphraseWords = 3;
    unsigned int matchLength = 4;
    std::string similar = "deny";
    unsigned int randomBits = 47;
    std::string wordlist;
    std::string denylist;
    std::string filter;
    std::string enforce = "everyone";
    unsigned int retry = 3;
    bool nonUnix = false;
    bool askOldAuthToken = false;
    bool askOldAuthTokenDuringUpdate = false;
    bool checkOldAuthToken = false;
    bool useFirstPass = false;
    bool useAuthToken = false;
    bool noAudit = false;

    PasswdqcEffectiveState();

    bool managedValue(const std::string& option,
                      std::string& value,
                      std::string& error) const;
};

class PasswdqcConfigEvaluator {
public:
    static constexpr std::size_t maximumDepth = 16;
    static constexpr std::size_t maximumTotalBytes = 1024U * 1024U;
    static constexpr std::size_t maximumLineBytes = 8190;

    static bool evaluate(const std::filesystem::path& root,
                         PasswdqcEffectiveState& state,
                         std::string& error);
};

class PasswdqcConfigFile {
public:
    using Writer = std::function<bool(
        const std::string&,
        const std::string&,
        const AtomicWriteOptions&,
        std::string*)>;

    static bool setValue(const std::filesystem::path& path,
                         const std::string& option,
                         const std::string& value,
                         std::string& error,
                         Writer writer = {});

    static bool hasEffectiveValue(const std::filesystem::path& path,
                                  const std::string& option,
                                  const std::string& expectedValue,
                                  std::string& error);

    static bool hasOnlyValue(const std::filesystem::path& path,
                             const std::string& option,
                             const std::string& expectedValue,
                             std::string& error) {
        return hasEffectiveValue(path, option, expectedValue, error);
    }

    static bool validateNativeValue(const std::string& option,
                                    const std::string& value,
                                    std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWDQC_CONFIG_FILE_H
