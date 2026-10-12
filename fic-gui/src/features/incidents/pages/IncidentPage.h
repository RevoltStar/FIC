#pragma once
#include <QWidget>
#include <QThread>
#include "features/incidents/services/IncidentService.h"
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QComboBox;
class QVBoxLayout;
class IncidentPage : public QWidget {
    Q_OBJECT
public:
    explicit IncidentPage(QWidget* parent = nullptr, IncidentService::RequestFunction request = {});
    ~IncidentPage() override;
    const IncidentSnapshot& snapshot() const { return snapshot_; }
public slots:
    void refresh();
    // Used after UI confirmation; transport may be injected for offscreen tests.
    void executeConfirmedAction(const QString& command, const QString& severity = {});
signals:
    void request(quint64 sequence, QString command, QString severity);
    void updated();
private:
    void submit(const QString& command = {}, const QString& severity = {});
    void render();
    IncidentSnapshot snapshot_;
    QThread thread_;
    bool busy_ = false;
    quint64 sequence_ = 0;
    QLabel *warning_, *summary_, *operation_;
    QPlainTextEdit* details_;
    QPushButton *refresh_, *raise_, *clear_;
    QComboBox* severity_;
};
