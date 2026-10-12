#include "IncidentService.h"
#include <utility>
IncidentService::IncidentService(RequestFunction request) : request_(std::move(request)) {}
IncidentService::Reply IncidentService::request(const nlohmann::json& payload, bool parseStatus) const {
    Reply reply;
    try {
        auto r = request_ ? request_(payload) : fic::ipc::Client().requestWithStatus(payload);
        if (!r.hasResponse) { reply.failure = Failure::Transport; reply.message = QString::fromStdString(r.error); return reply; }
        reply.reachable = true;
        const auto& j = r.response;
        if (!j.is_object() || !j.at("ok").is_boolean() || !j.at("message").is_string() ||
            !j.at("api_version").is_number_integer() || j.at("api_version") != fic::ipc::API_VERSION)
            throw std::runtime_error("Invalid incident response envelope");
        reply.message = QString::fromStdString(j.at("message").get<std::string>());
        if (!j.at("ok").get<bool>()) { reply.failure = Failure::Daemon; return reply; }
        if (parseStatus) reply.status = IncidentStatus::parse(j);
    } catch (const std::exception& e) {
        reply.failure = Failure::Protocol;
        reply.message = QString::fromUtf8(e.what());
    }
    return reply;
}
IncidentService::Reply IncidentService::status() const { return request({{"command", "incident_status"}}, true); }
IncidentService::Reply IncidentService::action(const QString& command, const QString& severity) const {
    if (command == "incident_clear") return request({{"command", "incident_clear"}}, false);
    if (command == "incident_raise" && (severity == "SOFT" || severity == "STANDARD" || severity == "HARD" || severity == "ISOLATE"))
        return request({{"command", "incident_raise"}, {"value", severity.toStdString()}}, false);
    Reply reply; reply.failure = Failure::Protocol; reply.message = "Invalid incident action"; return reply;
}
IncidentWorker::IncidentWorker(IncidentService::RequestFunction request) : service_(std::move(request)) {}
void IncidentWorker::run(quint64 sequence, QString command, QString severity) {
    if (!command.isEmpty()) emit actionFinished(service_.action(command, severity));
    emit statusFinished(sequence, service_.status());
}
