#include "IncidentHistoryService.h"
#include <QThread>
#include <stdexcept>
#include <utility>
namespace { class HistoryTransportError : public std::runtime_error { public: using std::runtime_error::runtime_error; }; }
IncidentHistoryService::IncidentHistoryService(IncidentService::RequestFunction request) : request_(std::move(request)) {}
nlohmann::json IncidentHistoryService::request(const nlohmann::json& payload) const {
    const auto result = request_ ? request_(payload) : fic::ipc::Client().requestWithStatus(payload);
    if (!result.hasResponse) throw HistoryTransportError(result.error);
    const auto& j = result.response;
    if (!j.is_object() || !j.at("ok").is_boolean() || !j.at("message").is_string() ||
        !j.at("api_version").is_number_integer() || j.at("api_version") != fic::ipc::API_VERSION)
        throw std::runtime_error("Invalid history response envelope");
    if (!j.at("ok").get<bool>()) throw std::runtime_error(j.at("message").get<std::string>());
    return j;
}
IncidentHistorySnapshot IncidentHistoryService::refresh() {
    // Publish a batch only after all of its requests validate. Failure leaves the
    // prior records/cursor/acquisition time intact, so retries cannot duplicate a
    // partially applied batch or discard cached history on boot/rotation changes.
    auto candidate = data_;
    try {
        const auto boot = request({{"command", "boot_id"}}).at("boot_id").get<std::string>();
        if (boot.empty() || boot.size() > 128 || boot.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos)
            throw std::runtime_error("Invalid history boot_id");
        if (candidate.bootId != QString::fromStdString(boot)) {
            candidate = {}; candidate.bootId = QString::fromStdString(boot);
            candidate.generation = data_.generation + 1;
        }
        qsizetype bytes = 0;
        for (const auto& e : candidate.events) bytes += e.memoryBytes();
        bool resetOnce = false, acquiredPage = false;
        for (int pages = 0; pages < MaxPages;) {
            if (QThread::currentThread()->isInterruptionRequested()) throw std::runtime_error("History acquisition interrupted");
            const auto j = request({{"command", "log_records"}, {"boot_id", boot},
                {"cursor", candidate.cursor.toStdString()}, {"limit", PageSize}});
            if (j.at("boot_id").get<std::string>() != boot || !j.at("records").is_array() ||
                j.at("records").size() > PageSize || !j.at("has_more").is_boolean() ||
                !j.at("reload_required").is_boolean()) throw std::runtime_error("Invalid history page");
            if (j.at("reload_required").get<bool>()) {
                if (resetOnce) throw std::runtime_error("Repeated stale history cursor");
                resetOnce = true;
                candidate = {}; candidate.bootId = QString::fromStdString(boot);
                candidate.generation = data_.generation + 1;
                candidate.reloaded = true; bytes = 0;
                candidate.hasMore = true; acquiredPage = false; continue;
            }
            const auto cursor = QString::fromStdString(j.at("next_cursor").get<std::string>());
            if (cursor.isEmpty() || cursor.size() > 34 || (j.at("has_more").get<bool>() && cursor == candidate.cursor))
                throw std::runtime_error("Invalid or non-progressing history cursor");
            ++pages; // Reload attempts do not consume the successful-page budget.
            for (const auto& record : j.at("records")) {
                bool damaged = false;
                auto e = IncidentAuditEvent::parse(record, damaged);
                candidate.damaged = candidate.damaged || damaged || (e && e->truncated);
                if (!e) continue;
                bytes += e->memoryBytes(); candidate.events.append(std::move(*e));
                while (candidate.events.size() > MaxEvents || bytes > MaxMemoryBytes) {
                    const auto& oldest = candidate.events.front(); bytes -= oldest.memoryBytes();
                    candidate.generation = data_.generation + 1;
                    candidate.events.removeFirst(); candidate.trimmed = true;
                }
            }
            candidate.cursor = cursor; candidate.hasMore = j.at("has_more").get<bool>(); acquiredPage = true;
            if (!candidate.hasMore) break;
        }
        if (!acquiredPage) throw std::runtime_error("History reload pending");
        candidate.acquired = QDateTime::currentDateTimeUtc(); candidate.stale = false; candidate.transportFailed = false; candidate.error.clear();
        data_ = std::move(candidate);
    } catch (const std::exception& e) {
        data_.stale = true; data_.transportFailed = dynamic_cast<const HistoryTransportError*>(&e) != nullptr;
        data_.error = QString::fromUtf8(e.what());
    }
    return data_;
}
