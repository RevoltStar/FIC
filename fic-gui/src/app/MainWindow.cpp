#include "app/MainWindow.h"
#include "features/incidents/pages/IncidentPage.h"

#include "ui_MainWindow.h"

#include <algorithm>
#include <QMessageBox>
#include <QPushButton>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QWidget>

#include "features/policies/pages/ModulePageFactory.h"
#include "features/policies/services/PolicyService.h"
#include "shared/i18n/QLocalizationManager.h"

MainWindow::MainWindow(QWidget* parent, PolicyService::RequestFunction policyRequest,
                       IncidentService::RequestFunction incidentRequest)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , policyRequest_(std::move(policyRequest))
{
    ui->setupUi(this);
    ui->statusbar->hide();
    incidentPage_ = new IncidentPage(ui->tab_modules, std::move(incidentRequest));
    ui->tab_modules->addTab(incidentPage_, QLocalizationManager::getLang("[incident:title]"));
    addModules();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::addModules()
{
    QWidget* selected = ui->tab_modules->currentWidget();
    const QString selectedName = selected ? selected->objectName() : QString();
    clearModules();

    PolicyService service(policyRequest_);
    std::vector<ModuleDescriptor> modules;
    QString error;
    if (!service.loadModules(modules, error)) {
        showRefreshFallback(error);
        return;
    }

    std::sort(
        modules.begin(),
        modules.end(),
        [](const ModuleDescriptor& left, const ModuleDescriptor& right) {
            if (left.displayOrder != right.displayOrder) {
                return left.displayOrder < right.displayOrder;
            }
            return left.name < right.name;
        });

    const ModulePageFactory factory;
    for (const ModuleDescriptor& module : modules) {
        std::vector<PolicyDescriptor> policies;
        if (!service.loadPolicies(module.name, policies, error)) {
            showRefreshFallback(QString::fromStdString(module.name) + ": " + error);
            return;
        }
        QWidget* page = factory.create(module, policies, ui->tab_modules);
        if (page == nullptr) {
            QMessageBox::warning(this, "FIC daemon", "Unsupported module view");
            return;
        }
        page->setObjectName(QString::fromStdString(module.name));
        ui->tab_modules->addTab(
            page,
            QLocalizationManager::getLang(
                QString::fromStdString("[module:" + module.name + "]")));
    }

    showModules();
    ui->tab_modules->setTabText(ui->tab_modules->indexOf(incidentPage_), QLocalizationManager::getLang("[incident:title]"));
    for (int i = 0; i < ui->tab_modules->count(); ++i)
        if (ui->tab_modules->widget(i)->objectName() == selectedName) ui->tab_modules->setCurrentIndex(i);
}

void MainWindow::clearModules()
{
    for (int i = ui->tab_modules->count() - 1; i >= 0; --i) {
        QWidget* page = ui->tab_modules->widget(i);
        if (page == incidentPage_) continue;
        ui->tab_modules->removeTab(i);
        delete page;
    }
}

void MainWindow::showModules()
{
    if (refreshFallback_ != nullptr) {
        refreshFallback_->hide();
    }
    if (refreshButton_ != nullptr) {
        refreshButton_->setToolTip({});
    }
    ui->tab_modules->show();
    ui->statusbar->hide();
}

void MainWindow::showRefreshFallback(const QString& error)
{
    if (refreshFallback_ == nullptr) {
        refreshFallback_ = new QWidget(ui->centralwidget);
        auto* layout = new QVBoxLayout(refreshFallback_);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->addStretch();

        refreshButton_ = new QPushButton(QLocalizationManager::getLang("[incident:refresh]"), refreshFallback_);
        connect(refreshButton_, &QPushButton::clicked, this, &MainWindow::addModules);
        layout->addWidget(refreshButton_, 0, Qt::AlignCenter);
        layout->addStretch();

        ui->verticalLayout->addWidget(refreshFallback_);
    }

    ui->tab_modules->show();
    refreshFallback_->show();
    refreshButton_->setToolTip(error);
    ui->statusbar->showMessage(error);
    ui->statusbar->show();
}
