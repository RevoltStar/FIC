#ifndef FIC_DEVICE_TREE_SNAPSHOT_H
#define FIC_DEVICE_TREE_SNAPSHOT_H

#include <string>

#include <nlohmann/json_fwd.hpp>

class DB;

namespace fic::device_control {

nlohmann::json device_tree_snapshot_response(
    DB& db,
    const nlohmann::json& request,
    const std::string& bootId);

}

#endif
