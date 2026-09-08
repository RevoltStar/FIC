#include "daemon/AuditLogValue.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <cassert>
#include <string>
#include <utility>
#include <vector>

namespace {
void assertSafeValue(const std::string& value) {
    for (const unsigned char ch : value) {
        assert(ch >= 0x20 && ch != 0x7f);
    }

    // Every quote/backslash in the value must be escaped. A literal backslash
    // must not disguise a generated control-byte escape or close the field.
    for (std::size_t index = 0; index < value.size(); ++index) {
        assert(value[index] != '"');
        if (value[index] == '\\') {
            assert(++index < value.size());
            assert(value[index] == '\\' || value[index] == '"' || value[index] == 'x');
        }
    }

    const std::string record = "message=\"" + value + "\" ok=false\n";
    assert(std::count(record.begin(), record.end(), '\n') == 1);
    assert(record.find('\n') == record.size() - 1);
    assert(record.find('\r') == std::string::npos);
    assert(record.find('\x1b') == std::string::npos);
}
} // namespace

int main() {
    const std::vector<std::pair<std::string, std::string>> cases = {
        {"", ""},
        {"ASCII 0123 !@#$%^&*()_+-=[]{};:',.<>/?", "ASCII 0123 !@#$%^&*()_+-=[]{};:',.<>/?"},
        {std::string(1, '\x1b'), R"(\x1B)"},
        {std::string(1, '\x07'), R"(\x07)"},
        {std::string(1, '\0'), R"(\x00)"},
        {std::string(1, '\x7f'), R"(\x7F)"},
        {"\n", " "},
        {"\r", " "},
        {"\t", " "},
        {"line1\nline2\r\tend", "line1 line2  end"},
        {"\"", R"(\")"},
        {"\\", R"(\\)"},
        {R"(\x1B)", R"(\\x1B)"},
        {R"(value" ok=true message="forged\)", R"(value\" ok=true message=\"forged\\)"},
        {u8"Привет, мир! café 日本語 😀", u8"Привет, мир! café 日本語 😀"},
        {"\x1b[31mred\x1b[0m", R"(\x1B[31mred\x1B[0m)"},
        {std::string("A\0B", 3) + "\x1b[2J\x07\x7f\n\r\t\"\\",
         R"(A\x00B\x1B[2J\x07\x7F   \"\\)"},
        {std::string(u8"текст") + '\x1b' + u8"日本語", u8"текст\\x1B日本語"},
    };
    for (const auto& [input, expected] : cases) {
        const auto actual = sanitize_log_value(input);
        assert(actual == expected);
        assertSafeValue(actual);
    }

    // Exhaust every C0 byte and DEL, both independently and in one value.
    const std::vector<std::string> expectedControls = {
        R"(\x00)", R"(\x01)", R"(\x02)", R"(\x03)", R"(\x04)", R"(\x05)", R"(\x06)", R"(\x07)",
        R"(\x08)", " ", " ", R"(\x0B)", R"(\x0C)", " ", R"(\x0E)", R"(\x0F)",
        R"(\x10)", R"(\x11)", R"(\x12)", R"(\x13)", R"(\x14)", R"(\x15)", R"(\x16)", R"(\x17)",
        R"(\x18)", R"(\x19)", R"(\x1A)", R"(\x1B)", R"(\x1C)", R"(\x1D)", R"(\x1E)", R"(\x1F)",
    };
    std::string controls, expected;
    for (unsigned int byte = 0; byte < 0x20; ++byte) {
        const std::string input(1, static_cast<char>(byte));
        assert(sanitize_log_value(input) == expectedControls[byte]);
        controls += input;
        expected += expectedControls[byte];
    }
    controls += '\x7f';
    expected += R"(\x7F)";
    assert(sanitize_log_value(controls) == expected);
    assertSafeValue(sanitize_log_value(controls));

    // All high bytes must survive verbatim, regardless of char signedness.
    std::string highBytes;
    for (unsigned int byte = 0x80; byte <= 0xff; ++byte) {
        highBytes += static_cast<char>(byte);
    }
    assert(sanitize_log_value(highBytes) == highBytes);
    assertSafeValue(sanitize_log_value(highBytes));
    return 0;
}
