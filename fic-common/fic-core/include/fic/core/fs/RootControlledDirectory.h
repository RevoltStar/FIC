#ifndef FIC_CORE_ROOT_CONTROLLED_DIRECTORY_H
#define FIC_CORE_ROOT_CONTROLLED_DIRECTORY_H
#include <filesystem>
#include <string>
namespace fic::core {
// Opens an EXISTING absolute normalized directory by walking from a pinned /
// descriptor. Every ancestor is a real root-owned directory with no group/other
// write; no symlink aliases, creation, metadata repair or implicit fallback.
// Returns an owned O_CLOEXEC descriptor (caller closes), or -1 with diagnostic.
int openRootControlledDirectory(const std::filesystem::path&, std::string& error);
}
#endif
