// mainwindow.h
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "core/CheckAndFix.h"
#include "core/main_function.h"

#include <QScrollArea>
#include <QCheckBox>
#include <QMessageBox>
#include <QSpinBox>
#include <QTextEdit>
#include <QComboBox>
#include <QPushButton>

#include "DeviceAttributeList.h"
#include "DeviceTree.h"
#include "wrappers/QLocalizationManager.h"
#include "LogViewer.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    //Создать все политики
    void addModules();

private slots:
    void onDeviceClicked(const DeviceInfo& device);
    void onAttributesUpdated(int deviceId, int attributeCount);

private:
    Ui::MainWindow *ui;
    DeviceTree *deviceTree;
    DeviceAttributeList *deviceAttributeList;
    LogViewer *logViewer; // Добавьте этот указатель

    //Создать вкладку политики.
    QWidget* createPolicyPage(const std::map<std::string, std::map<std::string, std::shared_ptr<CheckAndFix>>>& submoduleMap,
                                 const std::string moduleName, QWidget* parent = nullptr);
    //Массив политик
    std::map<std::string, std::map<std::string, std::map<std::string ,std::shared_ptr<CheckAndFix>>>> cafMap;
};

#endif // MAINWINDOW_H
