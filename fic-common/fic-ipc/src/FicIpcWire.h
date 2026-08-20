#ifndef FIC_IPC_WIRE_H
#define FIC_IPC_WIRE_H

#include <arpa/inet.h>

#include <cstdint>
#include <cstring>
#include <string>

namespace fic::ipc::wire {

inline constexpr std::uint32_t RESPONSE_MAGIC = 0x00464943; // FIC
inline constexpr std::size_t HEADER_BYTES = sizeof(std::uint32_t) * 4U;

inline std::string responseFrame(const std::string& response,
                                 std::size_t offset,
                                 std::size_t chunkBytes) {
    const std::uint32_t words[] = {
        htonl(RESPONSE_MAGIC),
        htonl(static_cast<std::uint32_t>(response.size())),
        htonl(static_cast<std::uint32_t>(offset)),
        htonl(static_cast<std::uint32_t>(chunkBytes))
    };
    std::string frame(HEADER_BYTES + chunkBytes, '\0');
    std::memcpy(frame.data(), words, HEADER_BYTES);
    std::memcpy(frame.data() + HEADER_BYTES, response.data() + offset, chunkBytes);
    return frame;
}

inline bool parseResponseHeader(const char* frame,
                                std::size_t frameBytes,
                                std::size_t& totalBytes,
                                std::size_t& offset,
                                std::size_t& chunkBytes,
                                std::string& error) {
    if (frameBytes < HEADER_BYTES) {
        error = "response frame is shorter than its header";
        return false;
    }

    std::uint32_t words[4]{};
    std::memcpy(words, frame, HEADER_BYTES);
    if (ntohl(words[0]) != RESPONSE_MAGIC) {
        error = "response frame has invalid magic";
        return false;
    }
    totalBytes = ntohl(words[1]);
    offset = ntohl(words[2]);
    chunkBytes = ntohl(words[3]);
    if (frameBytes != HEADER_BYTES + chunkBytes) {
        error = "response frame length does not match its header";
        return false;
    }
    return true;
}

} // namespace fic::ipc::wire

#endif // FIC_IPC_WIRE_H
