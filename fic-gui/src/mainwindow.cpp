#include "mainwindow.h"

#include "./ui_mainwindow.h"

#include <algorithm>
#include <QMessageBox>

#include "pages/ModulePageFactory.h"
#include "services/PolicyService.h"
#include "wrappers/QLocalizationManager.h"

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    addModules();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::addModules()
{
    while (ui->tab_modules->count() > 0) {
        QWidget* page = ui->tab_modules->widget(0);
        ui->tab_modules->removeTab(0);
        delete page;
    }

    PolicyService service;
    std::vector<ModuleDescriptor> modules;
    QString error;
    if (!service.loadModules(modules, error)) {
        QMessageBox::warning(this, "FIC daemon", error);
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
            QMessageBox::warning(
                this,
                "FIC daemon",
                QString::fromStdString(module.name) + ": " + error);
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
}
