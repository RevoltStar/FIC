#include "modules/dac/sudo/SudoProviderCapabilities.h"

#include <iostream>
#include <stdexcept>

using namespace fic::sudoers;
int main() {
    try {
        SudoProviderCapabilities capabilities;
        std::string error;
        const auto require = [](bool condition) {
            if (!condition) throw std::runtime_error("provider capability admission regression");
        };
        for (const std::string version : {"1.9.13p3", "1.9.16p2", "1.9.15p5", "1.9.17p2"}) {
            require(classifySudoProviderVersion("Sudo version " + version + "\n", capabilities, error));
            require(capabilities.provider == SudoProvider::Classic);
            require(capabilities.envReset == SudoCapabilityGuarantee::Configurable);
            require(capabilities.exemptGroupDisabled == SudoCapabilityGuarantee::Configurable);
        }
        require(classifySudoProviderVersion("sudo-rs 0.2.13-0ubuntu1.2\n", capabilities, error));
        require(capabilities.provider == SudoProvider::Rust);
        require(capabilities.envReset == SudoCapabilityGuarantee::VerifiedByConstruction);
        require(capabilities.exemptGroupDisabled == SudoCapabilityGuarantee::VerifiedByConstruction);
        require(!capabilities.continuationArgumentsProven);
        for (const std::string unknown : {"", "sudo-rs 0.2.12", "sudo-rs 0.3.0", "Sudo version 99.0", "sudo unknown"}) {
            require(!classifySudoProviderVersion(unknown, capabilities, error));
            require(capabilities.provider == SudoProvider::Unknown);
            require(capabilities.envReset == SudoCapabilityGuarantee::Unknown);
            require(!error.empty());
        }
        std::cout << "provider version admission and construction capabilities PASS\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
