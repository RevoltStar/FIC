#include "app/MainWindow.h"

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

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->statusbar->hide();
    addModules();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::addModules()
{
    clearModules();

    PolicyService service;
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
        ui->tab_modules->addTab(
            page,
            QLocalizationManager::getLang(
                QString::fromStdString("[module:" + module.name + "]")));
    }

    showModules();
}

void MainWindow::clearModules()
{
    while (ui->tab_modules->count() > 0) {
        QWidget* page = ui->tab_modules->widget(0);
        ui->tab_modules->removeTab(0);
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

        refreshButton_ = new QPushButton("Обновить", refreshFallback_);
        connect(refreshButton_, &QPushButton::clicked, this, &MainWindow::addModules);
        layout->addWidget(refreshButton_, 0, Qt::AlignCenter);
        layout->addStretch();

        ui->verticalLayout->addWidget(refreshFallback_);
    }

    ui->tab_modules->hide();
    refreshFallback_->show();
    refreshButton_->setToolTip(error);
    refreshButton_->setFocus(Qt::OtherFocusReason);
    ui->statusbar->hide();
}
