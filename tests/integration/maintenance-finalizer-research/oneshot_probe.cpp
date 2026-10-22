// Research fixture only. No FIC state, journal, security hooks or daemon startup.
#include <fstream>
#include <iostream>
#include <string>
int main() {
    std::ifstream input("/var/lib/m1-delivery/package-state");
    std::string state; std::getline(input,state);
    std::ofstream attempts("/var/lib/m1-delivery/attempts",std::ios::app);
    attempts << state << '\n'; attempts.close();
    if (state != "installed") {
        std::cout << "DEFERRED: package state not proven; fence retained\n";
        return 0;
    }
    std::ofstream accepted("/var/lib/m1-delivery/accepted");
    accepted << "fixture proof accepted\n";
    std::cout << "ACCEPTED: fixture proof only, no FIC mutation\n";
}
