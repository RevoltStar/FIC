#include "IncidentAuditModel.h"
#include "shared/i18n/QLocalizationManager.h"
#include <QCryptographicHash>
#include <fic/ipc/FicIpcClient.h>
#include <stdexcept>
namespace {
constexpr std::size_t MaxLine = 16U * 1024U;
QString field(const nlohmann::json& j, const char* key) {
    if (!j.contains(key)) return {};
    if (!j.at(key).is_string()) throw std::runtime_error("Invalid audit string");
    return QString::fromStdString(j.at(key).get<std::string>()).left(512);
}
}
qsizetype IncidentAuditEvent::memoryBytes() const {
    return sizeof(*this) + raw.size() + 2 * (timestamp.size() + event.size() + previous.size() +
        severity.size() + source.size() + reason.size() + diagnostic.size() + identity.size());
}
std::optional<IncidentAuditEvent> IncidentAuditEvent::parse(const nlohmann::json& record, bool& damaged) {
    damaged = false;
    try {
        if (!record.is_object() || !record.contains("category") || !record.at("category").is_string())
            throw std::runtime_error("Invalid log record");
        if (record.at("category") != "audit") return {};
        if (record.contains("line_truncated") && record.at("line_truncated").get<bool>()) {
            damaged = true; return {};
        }
        const auto& line = record.at("line").get_ref<const std::string&>();
        if (line.size() > MaxLine) throw std::runtime_error("Audit line too large");
        const auto first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos || line[first] != '{') return {}; // Logger text is not structured audit.
        auto j = nlohmann::json::parse(line, [](int depth, nlohmann::json::parse_event_t, nlohmann::json&) {
            if (depth > 16) throw std::runtime_error("Audit depth exceeded");
            return true;
        });
        std::string validation;
        if (!j.is_object() || !fic::ipc::validate_json_value(j, 0, validation)) throw std::runtime_error("Invalid audit JSON");
        if (j.value("component", std::string()) != "fic" || !j.contains("event")) return {};
        const QString event = field(j, "event");
        if (event != "incident_raise" && event != "incident_clear" && event != "incident_persistence_failed" &&
            event != "incident_action_failed" && event != "incident_mode_preflight_failed" &&
            event != "incident_mode_registry_failed" && event != "ssh_bridge_degraded") return {};
        // Administrative command/request/result audit does not describe a controller event.
        if (j.contains("command")) return {};
        if (!j.contains("timestamp")) throw std::runtime_error("Missing audit timestamp");
        IncidentAuditEvent e;
        e.event = event; e.timestamp = field(j,"timestamp");
        e.previous = field(j,"previous_severity"); e.severity = field(j,"effective_severity");
        e.source = field(j,"source"); e.reason = field(j,"reason");
        e.diagnostic = field(j,"runtime_state");
        for (const auto key : {"message", "detail"}) {
            const auto value = field(j,key);
            if (!value.isEmpty()) e.diagnostic += (e.diagnostic.isEmpty() ? "" : " | ") + value;
        }
        if (j.contains("result")) {
            if (!j.at("result").is_object()) throw std::runtime_error("Invalid audit result");
            e.diagnostic += " " + QString::fromStdString(j.at("result").dump()).left(512);
        }
        e.truncated = j.value("record_truncated", false) || j.contains("truncated_fields");
        e.raw = QByteArray::fromStdString(line);
        // log_records has no physical record ID/offset. Coalesce identical lines
        // from the same file (including replay following cursor expiration).
        const auto& filename = record.at("source_file").get_ref<const std::string&>();
        if (filename.size() > MaxLine) throw std::runtime_error("Audit source path too large");
        const auto origin = QByteArray::fromStdString(filename);
        e.identity = QString::fromLatin1(QCryptographicHash::hash(origin + '\0' + e.raw, QCryptographicHash::Sha256).toHex());
        return e;
    } catch (const std::exception&) { damaged = true; return {}; }
}
int IncidentAuditModel::rowCount(const QModelIndex& parent) const { return parent.isValid() ? 0 : events_.size(); }
int IncidentAuditModel::columnCount(const QModelIndex& parent) const { return parent.isValid() ? 0 : 7; }
QVariant IncidentAuditModel::data(const QModelIndex& index, int role) const {
    const auto* e = eventAt(index.row());
    if (!index.isValid() || !e || index.column() < 0 || index.column() >= 7) return {};
    // Raw daemon data is displayed only in a PlainText details viewer.
    if (role != Qt::DisplayRole) return {};
    const QString fields[] = {e->timestamp,e->event,e->previous,e->severity,e->source,e->reason,e->diagnostic};
    return fields[index.column()];
}
QVariant IncidentAuditModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal || section < 0 || section >= 7) return {};
    const char* keys[] = {"time", "event", "previous", "final", "source", "reason", "result"};
    return QLocalizationManager::getLang(QString("[incident:%1]").arg(keys[section]));
}
const IncidentAuditEvent* IncidentAuditModel::eventAt(int row) const {
    return row >= 0 && row < events_.size() ? &events_[row] : nullptr;
}
void IncidentAuditModel::update(const QVector<IncidentAuditEvent>& events) {
    bool prefix = events.size() >= events_.size();
    for (int i = 0; prefix && i < events_.size(); ++i) prefix = events[i].identity == events_[i].identity;
    if (prefix) {
        if (events.size() == events_.size()) return;
        beginInsertRows({}, events_.size(), events.size() - 1); events_ = events; endInsertRows();
    } else { beginResetModel(); events_ = events; endResetModel(); }
}
void IncidentAuditFilter::setFilters(QString event, QString severity, QString source, QString search) {
    event_ = std::move(event); severity_ = std::move(severity); source_ = std::move(source); search_ = std::move(search);
    invalidateFilter();
}
bool IncidentAuditFilter::filterAcceptsRow(int row, const QModelIndex&) const {
    const auto* model = static_cast<const IncidentAuditModel*>(sourceModel());
    const auto* e = model ? model->eventAt(row) : nullptr;
    return e && (event_.isEmpty() || e->event == event_) &&
        (severity_.isEmpty() || e->severity == severity_ || e->previous == severity_) &&
        (source_.isEmpty() || e->source.contains(source_, Qt::CaseInsensitive)) &&
        (search_.isEmpty() || QString::fromUtf8(e->raw).contains(search_, Qt::CaseInsensitive));
}
