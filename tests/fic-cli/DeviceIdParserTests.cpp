#include "DeviceIdParser.h"

#include <limits>
#include <stdexcept>
#include <string>

namespace {
void require(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

void requireRejected(const std::string& text)
{
    int value = 77;
    std::string error;
    require(!fic::cli::parseDeviceId(text, value, error),
            "invalid device ID was accepted: " + text);
    require(value == 77, "failed parse modified the output value");
    require(error.find("Invalid device ID") != std::string::npos,
            "failed parse did not provide a clear error");
}

void requireAccepted(const std::string& text, int expected)
{
    int value = 0;
    std::string error;
    require(fic::cli::parseDeviceId(text, value, error),
            "valid device ID was rejected: " + text);
    require(value == expected, "device ID parsed to an unexpected value");
    require(error.empty(), "successful parse retained an error");
}
}

int main()
{
    for (const std::string& invalid : {
             std::string(), std::string("abc"), std::string("123abc"),
             std::string("+123"), std::string("-1"), std::string("0"),
             std::string(" 123"), std::string("123 ")}) {
        requireRejected(invalid);
    }
    requireRejected(std::to_string(std::numeric_limits<int>::max()) + "0");

    requireAccepted("1", 1);
    requireAccepted("42", 42);
    requireAccepted("00123", 123);
    requireAccepted(std::to_string(std::numeric_limits<int>::max()),
                    std::numeric_limits<int>::max());
    return 0;
}
