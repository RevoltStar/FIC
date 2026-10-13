#include "modules/dac/sudo/SudoersManagedInclude.h"

#include <iostream>
#include <stdexcept>

using namespace fic::sudoers;

int main() {
    const std::filesystem::path path = "/etc/sudoers.d/99-fic.conf";
    const std::string foreign = "# preserved\r\nDefaults env_reset\n";
    const auto block = managedIncludeBlock(path);
    unsigned checks = 0;
    auto check = [&](const std::string& text, ManagedIncludeState expected) {
        ++checks;
        if (inspectManagedInclude(text, path).state != expected)
            throw std::runtime_error("managed include check " + std::to_string(checks));
    };
    try {
        check(foreign, ManagedIncludeState::Absent);
        check(foreign + block, ManagedIncludeState::Present);
        check(foreign + block + "\n", ManagedIncludeState::Present);
        check(foreign + block.substr(0, block.size() - 1), ManagedIncludeState::Present);
        check(foreign + block + "# foreign\n", ManagedIncludeState::Conflict);
        check(foreign + block + " \n", ManagedIncludeState::Conflict);
        check(foreign + block + block, ManagedIncludeState::Conflict);
        check("#@FIC_INCLUDE_UNKNOWN\n", ManagedIncludeState::Conflict);
        check("#@FIC_INCLUDE_END\n", ManagedIncludeState::Conflict);
        check("#@FIC_INCLUDE_BEGIN\n", ManagedIncludeState::Conflict);
        check("# foreign " + block, ManagedIncludeState::Conflict);
        check("#@FIC_INCLUDE_BEGIN\n@include /etc/sudoers.d/foreign\n#@FIC_INCLUDE_END\n",
              ManagedIncludeState::Conflict);
        // Duplicate foreign includes are graph/semantic concerns, not an
        // automatic placement conflict.
        check("@include /etc/sudoers.d/99-fic.conf\n" + foreign + block,
              ManagedIncludeState::Present);
        if (inspectManagedInclude(foreign, "/etc/sudoers.d/../99-fic.conf").state !=
                ManagedIncludeState::Conflict)
            throw std::runtime_error("noncanonical path accepted");
        ++checks;
        std::cout << checks << " managed include checks PASS\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
