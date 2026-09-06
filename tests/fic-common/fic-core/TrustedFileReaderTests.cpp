#include <fic/core/fs/TrustedFileReader.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition)
        throw std::runtime_error(message);
}

void writeFile(const fs::path& path, const std::string& content,
               mode_t mode = 0644) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not create fixture");
    output << content;
    output.close();
    require(::chmod(path.c_str(), mode) == 0, "could not chmod fixture");
}

void runTests() {
    std::string pattern =
        (fs::temp_directory_path() / "fic-trusted-reader-XXXXXX").string();
    char* created = ::mkdtemp(pattern.data());
    require(created != nullptr, "mkdtemp failed");
    const fs::path root(created);
    struct Cleanup {
        fs::path path;
        ~Cleanup() { std::error_code ignored; fs::remove_all(path, ignored); }
    } cleanup{root};

    fic::core::TrustedFileReadOptions options;
    options.expectedOwner = ::geteuid();
    options.forbiddenMode = S_IWGRP | S_IWOTH;
    const fs::path target = root / "target";
    std::string content;
    std::string error;

    writeFile(target, "trusted\n");
    require(fic::core::readTrustedFile(
                target, options, content, error) && content == "trusted\n",
            "trusted regular file was rejected: " + error);

    const fs::path link = root / "link";
    fs::create_symlink(target, link);
    require(!fic::core::readTrustedFile(link, options, content, error),
            "symbolic link was accepted");

    for (const mode_t mode : {0664, 0646}) {
        writeFile(target, "unsafe\n", mode);
        require(!fic::core::readTrustedFile(target, options, content, error),
                "writable untrusted file was accepted");
    }

    writeFile(target, "trusted\n");
    auto wrongOwner = options;
    wrongOwner.expectedOwner = ::geteuid() + 1;
    require(!fic::core::readTrustedFile(
                target, wrongOwner, content, error),
            "wrong file owner was accepted");

    require(!fic::core::readTrustedFile(root, options, content, error),
            "directory was accepted");
    auto readErrorOptions = options;
    readErrorOptions.requireRegularFile = false;
    content = "stale";
    require(!fic::core::readTrustedFile(
                root, readErrorOptions, content, error) && content.empty(),
            "descriptor read error was accepted or exposed partial content");
    const fs::path fifo = root / "fifo";
    require(::mkfifo(fifo.c_str(), 0600) == 0, "mkfifo failed");
    require(!fic::core::readTrustedFile(fifo, options, content, error),
            "FIFO was accepted");
    auto deviceOptions = options;
    deviceOptions.expectedOwner.reset();
    require(!fic::core::readTrustedFile(
                "/dev/null", deviceOptions, content, error),
            "device was accepted");

    writeFile(target, "original\n");
    const fs::path opened = root / "opened";
    bool replaced = false;
    require(fic::core::readTrustedFile(
                target, options, content, error, nullptr,
                [&](const fs::path& path) {
                    require(path == target, "unexpected validated path");
                    fs::rename(target, opened);
                    writeFile(target, "replacement\n");
                    replaced = true;
                }) &&
                replaced && content == "original\n" &&
                std::ifstream(target).good(),
            "pathname replacement changed trusted descriptor content: " +
                error);
}

} // namespace

int main() {
    try {
        runTests();
    } catch (const std::exception& exception) {
        std::cerr << exception.what() << '\n';
        return 1;
    }
    return 0;
}
