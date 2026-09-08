#ifndef FIC_AUDIT_LOG_VALUE_H
#define FIC_AUDIT_LOG_VALUE_H

#include <string>

// Keep untrusted audit values on one line and safe inside quoted fields.
// Operate on bytes so UTF-8 is preserved without locale-dependent conversion.
inline std::string sanitize_log_value(const std::string& value) {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string sanitized;
    sanitized.reserve(value.size());
    for (const unsigned char ch : value) {
        if (ch == '\n' || ch == '\r' || ch == '\t') {
            sanitized += ' ';
        } else if (ch < 0x20 || ch == 0x7f) {
            sanitized += "\\x";
            sanitized += hex[ch >> 4];
            sanitized += hex[ch & 0x0f];
        } else {
            if (ch == '"' || ch == '\\') {
                sanitized += '\\';
            }
            sanitized += static_cast<char>(ch);
        }
    }
    return sanitized;
}

#endif // FIC_AUDIT_LOG_VALUE_H
