// mainwindow.h
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QCheckBox>
#include <QComboBox>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QTextEdit>

#include <string>
#include <vector>

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

    void addModules();

private slots:
    void onDeviceClicked(const DeviceInfo& device);
    void onAttributesUpdated(int deviceId, int attributeCount);

private:
    struct PolicyInfo {
        std::string moduleName;
        std::string submoduleName;
        std::string policyName;
        std::string editor;
        std::string value;
        std::string defaultValue;
        std::string restriction;
        std::vector<std::string> possibleValues;
        bool enabled = false;
        bool isSet = false;
        bool valueValid = true;
        int min = 0;
        int max = 0;
    };

    enum class PolicyEditorType { CheckBox, SpinBox, TextEdit, ComboBox, Unknown };

    Ui::MainWindow *ui;
    DeviceTree *deviceTree;
    DeviceAttributeList *deviceAttributeList;
    LogViewer *logViewer;

    QWidget* createPolicyPage(const std::vector<PolicyInfo>& policies,
                              const std::string moduleName,
                              QWidget* parent = nullptr);
    std::vector<PolicyInfo> loadPoliciesFromDaemon(QStringList& errors) const;
    PolicyEditorType editorTypeFromString(const std::string& editor) const;
    bool validatePolicyValue(const PolicyInfo& policy, const std::string& value, QString* error) const;
};

#endif // MAINWINDOW_H