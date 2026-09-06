#ifndef FIC_CALC_HASH_COMMAND_H
#define FIC_CALC_HASH_COMMAND_H

#include <nlohmann/json_fwd.hpp>

#include <string>

nlohmann::json calcHashCommandResponse(const std::string& executable);

#endif // FIC_CALC_HASH_COMMAND_H
