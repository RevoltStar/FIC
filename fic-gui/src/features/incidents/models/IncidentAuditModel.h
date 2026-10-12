#pragma once
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QByteArray>
#include <QDateTime>
#include <QVector>
#include <optional>
#include <nlohmann/json.hpp>

struct IncidentAuditEvent {
    QString timestamp, event, previous, severity, source, reason, diagnostic;
    QByteArray raw;
    bool truncated = false;
    qsizetype memoryBytes() const;
    static std::optional<IncidentAuditEvent> parse(const nlohmann::json& record, bool& damaged);
};

struct IncidentHistorySnapshot {
    QVector<IncidentAuditEvent> events;
    quint64 generation = 0; // Replacement/eviction boundary, not an event ID.
    QString bootId, cursor, error;
    QDateTime acquired;
    bool stale = false, transportFailed = false, hasMore = false, trimmed = false, damaged = false, reloaded = false;
};
Q_DECLARE_METATYPE(IncidentHistorySnapshot)

class IncidentAuditModel : public QAbstractTableModel {
public:
    explicit IncidentAuditModel(QObject* parent = nullptr) : QAbstractTableModel(parent) {}
    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void update(const QVector<IncidentAuditEvent>& events, quint64 generation = 0);
    void retranslate() { emit headerDataChanged(Qt::Horizontal, 0, 6); }
    const IncidentAuditEvent* eventAt(int row) const;
private:
    QVector<IncidentAuditEvent> events_;
    quint64 generation_ = 0;
};

class IncidentAuditFilter : public QSortFilterProxyModel {
public:
    explicit IncidentAuditFilter(QObject* parent = nullptr) : QSortFilterProxyModel(parent) {}
    void setFilters(QString event, QString severity, QString source, QString search);
protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override;
private:
    QString event_, severity_, source_, search_;
};
