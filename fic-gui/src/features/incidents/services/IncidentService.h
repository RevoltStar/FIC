#pragma once
#include <functional>
#include <memory>
#include "features/incidents/models/IncidentAuditModel.h"
#include <QObject>
#include <fic/ipc/FicIpcClient.h>
#include "features/incidents/models/IncidentStatus.h"

class IncidentService {
public:
    using RequestFunction = std::function<fic::ipc::Client::RequestResult(const nlohmann::json&)>;
    enum class Failure { None, Transport, Daemon, Protocol };
    struct Reply {
        Failure failure = Failure::None;
        bool reachable = false;
        QString message;
        std::optional<IncidentStatus> status;
    };
    explicit IncidentService(RequestFunction request = {});
    Reply status() const;
    Reply action(const QString& command, const QString& severity = {}) const;
private:
    Reply request(const nlohmann::json& payload, bool parseStatus) const;
    RequestFunction request_;
};
Q_DECLARE_METATYPE(IncidentService::Reply)

class IncidentHistoryService;
class IncidentWorker : public QObject {
    Q_OBJECT
public:
    explicit IncidentWorker(IncidentService::RequestFunction request = {});
    ~IncidentWorker() override;
public slots:
    void run(quint64 sequence, QString command, QString severity);
    void refreshHistory();
signals:
    void actionFinished(IncidentService::Reply reply);
    void statusFinished(quint64 sequence, IncidentService::Reply reply);
    void historyFinished(IncidentHistorySnapshot snapshot);
    void localizationFinished(QByteArray bundle);
private:
    IncidentService::RequestFunction transport_;
    bool localizationAttempted_ = false;
    IncidentService service_;
    std::unique_ptr<IncidentHistoryService> history_;
};
