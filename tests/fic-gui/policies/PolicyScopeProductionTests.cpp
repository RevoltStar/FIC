#include "PolicySaveDaemonFixture.h"
#include "policy/registry/PolicyRegistryMutation.h"
#include <fic/core/config/ModuleConfigFileHandler.h>
#include <fstream>
#include <iterator>

using namespace policy_save_test;
void productionScopeMutations(Fixture& f) {
    const auto configBytes = [&] {
        std::ifstream input(f.root / "config/OSS.conf");
        return std::string(std::istreambuf_iterator<char>(input), {});
    };
    for (const auto& name : {de, dm}) {
        const std::string first = name == de ? "GNOME" : "SDDM";
        const std::string second = name == de ? "KDE" : "GDM";
        std::string error;
        f.reset();
        auto before = configBytes();
        {
            auto registry = f.registry();
            require(!enable(registry, "OSS", name, &error) &&
                error.find(name) != std::string::npos && configBytes() == before,
                "production enable accepted empty scope or wrote configuration");
        }
        f.values[name] = "[\"UNKNOWN\"]"; f.persist(); before = configBytes();
        {
            auto registry = f.registry();
            require(!enable(registry, "OSS", name, &error) &&
                error.find(name) != std::string::npos && configBytes() == before,
                "production enable accepted malformed scope or wrote configuration");
        }
        f.values[name] = "[\"" + first + "\"]"; f.persist();
        {
            auto registry = f.registry();
            require(enable(registry, "OSS", name, &error),
                "production enable rejected valid scope: " + error);
        }
        ModuleConfigFileHandler config("OSS");
        require(config.loadConfig() && config.getPolicyStatus(name) == "ENABLE",
                "production enable did not save ENABLE");
        before = configBytes();
        {
            auto registry = f.registry();
            require(!setPolicyValue(registry, "OSS", name, "", error) &&
                error.find(name) != std::string::npos && configBytes() == before,
                "production set cleared enabled scope or changed configuration");
            require(setPolicyValue(registry, "OSS", name, second, error), error);
        }
        ModuleConfigFileHandler replacement("OSS");
        require(replacement.loadConfig() && replacement.getPolicyStatus(name) == "ENABLE" &&
                replacement.getPolicyValue(name) == "[\"" + second + "\"]",
                "production set did not replace enabled scope");
        f.enabled[name] = true; f.values[name] = "[]"; f.persist();
        {
            auto registry = f.registry();
            require(setPolicyValue(registry, "OSS", name, first, error),
                    "production set could not repair ENABLE + []: " + error);
        }
        f.reset();
        {
            auto registry = f.registry();
            require(setPolicyValue(registry, "OSS", name, "", error),
                    "production set could not clear disabled scope: " + error);
        }
        ModuleConfigFileHandler disabled("OSS");
        require(disabled.loadConfig() && disabled.getPolicyStatus(name) == "DISABLE" &&
                disabled.getPolicyValue(name) == "[]",
                "clearing disabled scope changed status or serialization");
    }
}
