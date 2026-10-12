#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "features/policies/services/PolicyService.h"
#include "features/incidents/services/IncidentService.h"

class IncidentPage;
class QPushButton;
class QString;
class QWidget;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr, PolicyService::RequestFunction policyRequest = {},
                        IncidentService::RequestFunction incidentRequest = {});
    ~MainWindow() override;

    void addModules();

private:
    void clearModules();
    void showModules();
    void showRefreshFallback(const QString& error);

    Ui::MainWindow* ui;
    IncidentPage* incidentPage_ = nullptr;
    PolicyService::RequestFunction policyRequest_;
    QWidget* refreshFallback_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
};

#endif // MAINWINDOW_H
