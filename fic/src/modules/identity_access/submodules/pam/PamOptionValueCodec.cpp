#include "modules/identity_access/submodules/pam/PamOptionValueCodec.h"

#include <charconv>
#include <limits>

namespace fic::identity::pam {
namespace {

bool parseNonNegative(const std::string& value, unsigned int& parsed) {
    if (value.empty()) {
        return false;
    }
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), parsed, 10);
    return result.ec == std::errc{} &&
        result.ptr == value.data() + value.size() &&
        parsed < static_cast<unsigned int>(std::numeric_limits<int>::max());
}

} // namespace

bool PamOptionValueCodec::encode(PamOptionValueEncoding encoding,
                                 const std::string& logicalValue,
                                 std::string& nativeValue,
                                 std::string& error) {
    error.clear();
    switch (encoding) {
    case PamOptionValueEncoding::Direct:
        nativeValue = logicalValue;
        return true;
    case PamOptionValueEncoding::YesNoInteger:
        if (logicalValue == "yes") {
            nativeValue = "1";
            return true;
        }
        if (logicalValue == "no") {
            nativeValue = "0";
            return true;
        }
        error = "expected yes or no";
        return false;
    case PamOptionValueEncoding::MinimumCredit: {
        unsigned int minimum = 0;
        if (!parseNonNegative(logicalValue, minimum)) {
            error = "expected a non-negative integer";
            return false;
        }
        nativeValue = minimum == 0
            ? "0"
            : "-" + std::to_string(minimum);
        return true;
    }
    }
    error = "unsupported PAM option value encoding";
    return false;
}

bool PamOptionValueCodec::decode(PamOptionValueEncoding encoding,
                                 const std::string& nativeValue,
                                 std::string& logicalValue,
                                 std::string& error) {
    error.clear();
    switch (encoding) {
    case PamOptionValueEncoding::Direct:
        logicalValue = nativeValue;
        return true;
    case PamOptionValueEncoding::YesNoInteger:
        if (nativeValue == "1") {
            logicalValue = "yes";
            return true;
        }
        if (nativeValue == "0") {
            logicalValue = "no";
            return true;
        }
        error = "expected native boolean value 0 or 1";
        return false;
    case PamOptionValueEncoding::MinimumCredit:
        if (nativeValue == "0") {
            logicalValue = "0";
            return true;
        }
        if (nativeValue.size() > 1 && nativeValue.front() == '-') {
            unsigned int minimum = 0;
            const std::string magnitude = nativeValue.substr(1);
            if (parseNonNegative(magnitude, minimum) && minimum != 0) {
                logicalValue = magnitude;
                return true;
            }
        }
        error = "expected native minimum-credit value 0 or a negative integer";
        return false;
    }
    error = "unsupported PAM option value encoding";
    return false;
}

} // namespace fic::identity::pam
