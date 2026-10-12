#pragma once
#include <QWidget>
#include "features/incidents/models/IncidentAuditModel.h"
class QLabel;
class QPlainTextEdit;
class QPushButton;
class IncidentHistoryView : public QWidget {
    Q_OBJECT
public:
    explicit IncidentHistoryView(QWidget* parent = nullptr);
    void updateSnapshot(const IncidentHistorySnapshot& snapshot);
    void setBusy(bool busy);
    void retranslate();
signals:
    void refreshRequested();
private:
    IncidentAuditModel* model_;
    IncidentAuditFilter* filter_;
    QLabel* warning_;
    QPlainTextEdit* details_;
    QPushButton* refresh_;
};
