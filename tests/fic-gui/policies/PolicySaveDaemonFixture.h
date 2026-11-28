#pragma once
#include <fic/policy/PolicyDependency.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <map>
#include <string>
#include <stdexcept>
#include <vector>

class PolicyRegistry;
namespace policy_save_test {
inline const std::string de = "controlled_desktop_environments";
inline const std::string deConsumer = "absence_of_uncontrolled_desktop_environments";
inline const std::string dm = "controlled_display_managers";
inline const std::string dmConsumer = "absence_of_uncontrolled_display_managers";
inline void require(bool ok, const std::string& message) {
    if (!ok) throw std::runtime_error(message);
}
struct Fixture {
    std::filesystem::path root;
    std::map<std::string, bool> enabled;
    std::map<std::string, std::string> values;
    std::vector<PolicyDependency> ownerDependencies;
    bool backendRequires = true;
    std::vector<std::string> commands;
    std::string failCommand;
    int listCalls = 0;

    Fixture();
    ~Fixture();
    void reset();
    void persist();
    nlohmann::json request(const nlohmann::json& request);
    void expect(const std::vector<std::string>& expected);
    PolicyRegistry registry();
};
}
