#ifndef FIC_CLI_POLICY_SET_COMMAND_H
#define FIC_CLI_POLICY_SET_COMMAND_H

#include <nlohmann/json_fwd.hpp>

#include <string>

namespace fic::cli {

bool makePolicySetRequest(int argc,
                          char* argv[],
                          nlohmann::json& request,
                          std::string& error);

} // namespace fic::cli

#endif // FIC_CLI_POLICY_SET_COMMAND_H
