#ifndef FIC_CLI_DEVICE_ID_PARSER_H
#define FIC_CLI_DEVICE_ID_PARSER_H

#include <string>

namespace fic::cli {

bool parseDeviceId(const std::string& text, int& value, std::string& error);

} // namespace fic::cli

#endif // FIC_CLI_DEVICE_ID_PARSER_H
