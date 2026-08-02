#include <fic/version/BuildInfo.h>
#include <fic/version/ProductVersion.h>

#include <cassert>
#include <sstream>
#include <string>

int main() {
    assert(std::string(fic::version::PRODUCT_VERSION).find('.') != std::string::npos);
    assert(std::string(fic::version::BUILD_KIND) == "development" ||
           std::string(fic::version::BUILD_KIND) == "release");

    std::ostringstream output;
    fic::version::writeBuildInfo(output, "fic-version-test");
    const std::string buildInfo = output.str();
    assert(buildInfo.find("component=fic-version-test\n") != std::string::npos);
    assert(buildInfo.find(std::string("product_version=") +
                          fic::version::PRODUCT_VERSION + "\n") != std::string::npos);
    assert(buildInfo.find(std::string("build_kind=") +
                          fic::version::BUILD_KIND + "\n") != std::string::npos);
    assert(buildInfo.find(std::string("build_commit=") +
                          fic::version::BUILD_COMMIT + "\n") != std::string::npos);
    assert(buildInfo.find(std::string("release_tag=") +
                          fic::version::RELEASE_TAG + "\n") != std::string::npos);
}
