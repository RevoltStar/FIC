#ifndef FIC_IDENTITY_ACCESS_PAM_OPTION_VALUE_CODEC_H
#define FIC_IDENTITY_ACCESS_PAM_OPTION_VALUE_CODEC_H

#include <string>

namespace fic::identity::pam {

enum class PamOptionValueEncoding {
    Direct,
    YesNoInteger,
    MinimumCredit
};

class PamOptionValueCodec {
public:
    static bool encode(PamOptionValueEncoding encoding,
                       const std::string& logicalValue,
                       std::string& nativeValue,
                       std::string& error);

    static bool decode(PamOptionValueEncoding encoding,
                       const std::string& nativeValue,
                       std::string& logicalValue,
                       std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_OPTION_VALUE_CODEC_H
