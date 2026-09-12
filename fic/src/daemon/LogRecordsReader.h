#ifndef FIC_LOG_RECORDS_READER_H
#define FIC_LOG_RECORDS_READER_H

#include <filesystem>
#include <string>

#include <nlohmann/json.hpp>

namespace fic::daemon {

inline constexpr int MAX_LOG_RECORDS_PER_PAGE = 500;
inline constexpr std::size_t MAX_LOG_LINE_BYTES = 16U * 1024U;
inline constexpr std::size_t MAX_LOG_PAGE_BYTES = 768U * 1024U;

nlohmann::json readLogRecords(
    const std::filesystem::path& logDirectory,
    const std::string& bootId,
    const std::string& cursor,
    int limit);

} // namespace fic::daemon

#endif // FIC_LOG_RECORDS_READER_H
