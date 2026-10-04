#include "fic/core/integrity/ContentDigest.h"

#include <openssl/evp.h>

#include <memory>

namespace fic::core {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

} // namespace

std::string ContentDigest::sha256Hex(const std::string& content) {
    using ContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    ContextPtr context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context) {
        return {};
    }
    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        return {};
    }
    if (!content.empty() &&
        EVP_DigestUpdate(context.get(), content.data(), content.size()) != 1) {
        return {};
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(context.get(), digest, &length) != 1) {
        return {};
    }

    std::string hex;
    hex.reserve(length * 2);
    for (unsigned int index = 0; index < length; ++index) {
        hex.push_back(kHexDigits[digest[index] >> 4]);
        hex.push_back(kHexDigits[digest[index] & 0x0f]);
    }
    return hex;
}

bool ContentDigest::isCanonicalSha256Hex(const std::string& digest) {
    if (digest.size() != 64) {
        return false;
    }
    for (const char c : digest) {
        const bool isDigit = c >= '0' && c <= '9';
        const bool isLowerHex = c >= 'a' && c <= 'f';
        if (!isDigit && !isLowerHex) {
            return false;
        }
    }
    return true;
}

} // namespace fic::core