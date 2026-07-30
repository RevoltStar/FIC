#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <fic/ipc/FicIpcClient.h>

#include <QApplication>
#include <QClipboard>
#include <QStringList>
#include <QSignalBlocker>
#include <QWheelEvent>
#include <algorithm>
#include <map>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <vector>

namespace {
class NoWheelSpinBox : public QSpinBox
{
public:
    using QSpinBox::QSpinBox;

protected:
    void wheelEvent(QWheelEvent* event) override
    {
        event->ignore();
    }
};

QString currentBootIdFromDaemon()
{
    const auto response = fic::ipc::Client().request({{"command", "boot_id"}});
    if (!response.value("ok", false)) {
        return {};
    }
    return QString::fromStdString(response.value("boot_id", ""));
}

QString policyApplySummaryText(const nlohmann::json& response)
{
    if (!response.contains("summary") || !response["summary"].is_object()) {
        return QString::fromStdString(response.value("message", "unknown daemon response"));
    }

    const auto& summary = response["summary"];
    return QString("Total: %1, applied: %2, failed: %3, disabled: %4, not found: %5")
        .arg(summary.value("total", 0))
        .arg(summary.value("applied", 0))
        .arg(summary.value("failed", 0))
        .arg(summary.value("disabled", 0))
        .arg(summary.value("not_found", 0));
}

QString policyApplyDetailsText(const nlohmann::json& response)
{
    QStringList lines;

    if (response.contains("results") && response["results"].is_array()) {
        for (const auto& item : response["results"]) {
            QString policyRef = QString::fromStdString(item.value("module", ""));
            const QString submodule = QString::fromStdString(item.value("submodule", ""));
            if (!submodule.isEmpty()) {
                policyRef += ":" + submodule;
            }
            policyRef += ":" + QString::fromStdString(item.value("policy", ""));

            QString line = QString("%1 %2")
                .arg(policyRef)
                .arg(QString::fromStdString(item.value("status", "unknown")));

            const QString message = QString::fromStdString(item.value("message", ""));
            if (!message.isEmpty()) {
                line += " - " + message;
            }

            lines << line;

            if (item.contains("diagnostics") && item["diagnostics"].is_array()) {
                for (const auto& diagnostic : item["diagnostics"]) {
                    QString diagnosticLine = QString("  [%1] [%2]")
                        .arg(QString::fromStdString(diagnostic.value("timestamp", "")))
                        .arg(QString::fromStdString(diagnostic.value("level", "UNKNOWN")));
                    const QString category = QString::fromStdString(diagnostic.value("category", ""));
                    if (!category.isEmpty()) {
                        diagnosticLine += " [" + category + "]";
                    }
                    diagnosticLine += " " + QString::fromStdString(diagnostic.value("message", ""));
                    lines << diagnosticLine;
                }
            }
            if (item.value("diagnostics_truncated", false)) {
                lines << "  ... diagnostics truncated";
            }
        }
    }

    return lines.join("\n");
}

void showPolicyApplyResult(QWidget* parent, const nlohmann::json& response)
{
    const bool ok = response.value("ok", false);
    QMessageBox messageBox(parent);
    messageBox.setIcon(ok ? QMessageBox::Information : QMessageBox::Warning);
    messageBox.setWindowTitle(ok ? "Policies applied" : "Policy apply failed");
    messageBox.setText(QString::fromStdString(response.value("message", ok ? "OK" : "ERROR")));
    messageBox.setInformativeText(policyApplySummaryText(response));

    const QString details = policyApplyDetailsText(response);
    if (!details.isEmpty()) {
        messageBox.setDetailedText(details);
    }

    messageBox.exec();
}
} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // Создаем виджет дерева устройств
    deviceTree = new DeviceTree(this);

    // Добавляем виджет в gridLayoutTreeView
    ui->gridLayoutTreeView->addWidget(deviceTree, 0, 0);
    ui->gridLayout_3->setColumnMinimumWidth(0, 660);
    ui->gridLayout_3->setColumnStretch(0, 2);
    ui->gridLayout_3->setColumnStretch(1, 1);

    auto stabilizeValueLabel = [](QLabel *label) {
        label->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    };
    stabilizeValueLabel(ui->subsystemLabel);
    stabilizeValueLabel(ui->controlLevelLabel);
    stabilizeValueLabel(ui->devpathLabel);
    stabilizeValueLabel(ui->currentBootTimeLabel);
    stabilizeValueLabel(ui->deviceBootTimeLabel);
    ui->devpathLabel->setWordWrap(true);

    setupDeviceDetailsPanel();
    connect(deviceTree, &DeviceTree::deviceClicked,
               this, &MainWindow::onDeviceClicked);
    connect(deviceAttributeList, &DeviceAttributeList::attributesUpdated,
               this, &MainWindow::onAttributesUpdated);

    // Загружаем дерево устройств
    deviceTree->loadDeviceTree();
    ui->label_currentBootTime->setText("Текущий boot_id ОС:");
    ui->label_deviceBootTime->setText("boot_id устройства в БД:");
    ui->currentBootTimeLabel->setText(currentBootIdFromDaemon());
    ui->deviceBootTimeLabel->setText("[NO SET]");

    // СОЗДАЕМ И ИНИЦИАЛИЗИРУЕМ LogViewer С СУЩЕСТВУЮЩИМИ ЭЛЕМЕНТАМИ UI
    this->logViewer = new LogViewer(this);

    // Инициализируем LogViewer существующими UI элементами
    this->logViewer->initializeUI(
        ui->combo_log_level,        // QComboBox* comboLogLevel
        ui->comboBox,               // QComboBox* comboLogType (внимание: в UI он называется comboBox)
        ui->lineEdit_search,        // QLineEdit* lineEditSearch
        ui->checkBox_autoscroll,    // QCheckBox* checkAutoScroll
        ui->checkBox_wordwrap,      // QCheckBox* checkWordWrap
        ui->checkBox_pause,         // QCheckBox* checkPause
        ui->btn_refresh_logs,       // QPushButton* btnRefresh
        ui->btn_clear_logs,         // QPushButton* btnClear
        ui->btn_export_logs,        // QPushButton* btnExport
        ui->textBrowser_logs,       // QTextBrowser* textBrowser
        ui->label_log_count,        // QLabel* labelLogCount
        ui->label_log_size,         // QLabel* labelLogSize
        ui->label_last_update       // QLabel* labelLastUpdate
    );

    // Храним указатель как член класса (добавьте в mainwindow.h)
    // LogViewer* logViewer; // Добавьте в private секцию mainwindow.h

    this->addModules();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setupDeviceDetailsPanel()
{
    deviceControlCombo = new QComboBox(this);
    deviceControlCombo->addItem("Запрещено", "blocked");
    deviceControlCombo->addItem("Разрешено", "allowed");
    deviceControlCombo->addItem("Постоянно", "permanent");
    deviceControlCombo->addItem("Не контролируется", "ignored");
    deviceControlCombo->setToolTip("Явно задать уровень контроля выбранного устройства");

    deviceGlobalRuleCheck = new QCheckBox("Во всей системе", this);
    deviceGlobalRuleCheck->setToolTip("Применять правило к этой идентичности независимо от положения в дереве");

    deviceResetControlButton = new QPushButton("Сбросить", this);
    deviceResetControlButton->setToolTip("Сбросить явное правило до наследования");

    copyDevpathButton = new QPushButton("Копировать путь", this);
    copyDeviceSummaryButton = new QPushButton("Копировать сведения", this);
    deviceControlCombo->setEnabled(false);
    deviceGlobalRuleCheck->setEnabled(false);
    deviceResetControlButton->setEnabled(false);
    copyDevpathButton->setEnabled(false);
    copyDeviceSummaryButton->setEnabled(false);

    ui->gridLayout_11->addWidget(deviceControlCombo, 0, 1);
    ui->gridLayout_11->addWidget(deviceGlobalRuleCheck, 0, 2);
    ui->gridLayout_11->addWidget(deviceResetControlButton, 0, 3);
    ui->gridLayout_6->addWidget(copyDevpathButton, 0, 1);
    ui->gridLayout_6->addWidget(copyDeviceSummaryButton, 0, 2);

    deviceAttributeList = new DeviceAttributeList(this);
    deviceEventList = new DeviceEventList(this);
    deviceDetailsTabs = new QTabWidget(this);
    deviceDetailsTabs->addTab(deviceAttributeList, "Параметры");
    deviceDetailsTabs->addTab(deviceEventList, "События");

    ui->deviceParamListViewLabel->setText("Сведения об устройстве");
    QLayoutItem* oldItem = ui->gridLayoutListView->replaceWidget(ui->deviceParamListView, deviceDetailsTabs);
    if (oldItem) {
            delete oldItem->widget();
            delete oldItem;
    }

    connect(deviceControlCombo, QOverload<int>::of(&QComboBox::activated),
            this, [this](int index) {
                if (currentDevice.id <= 0) {
                    return;
                }
                deviceTree->applyControlLevelToCurrentDevice(deviceControlCombo->itemData(index).toString());
            });
    connect(deviceGlobalRuleCheck, &QCheckBox::toggled,
            this, [this](bool checked) {
                if (currentDevice.id <= 0 || checked == currentDevice.ignore_hierarchy) {
                    return;
                }
                deviceTree->applyIgnoreHierarchyToCurrentDevice(checked);
            });
    connect(deviceResetControlButton, &QPushButton::clicked,
            this, [this]() {
                if (currentDevice.id > 0) {
                    deviceTree->resetCurrentDeviceControl();
                }
            });
    connect(copyDevpathButton, &QPushButton::clicked,
            this, [this]() {
                QApplication::clipboard()->setText(QString::fromStdString(currentDevice.devpath));
                ui->statusbar->showMessage("Путь устройства скопирован", 2000);
            });
    connect(copyDeviceSummaryButton, &QPushButton::clicked,
            this, [this]() {
                QApplication::clipboard()->setText(deviceSummaryText(currentDevice));
                ui->statusbar->showMessage("Сведения об устройстве скопированы", 2000);
            });
}

QString MainWindow::deviceSummaryText(const DeviceInfo& device) const
{
    return QString("id: %1\nsubsystem: %2\ncontrol_level: %3\neffective_control_level: %4\n"
                   "effective_source: %5\nignore_hierarchy: %6\nconnected: %7\n"
                   "devpath: %8\nboot_id: %9\nlast_event_at: %10")
        .arg(device.id)
        .arg(QString::fromStdString(device.subsystem))
        .arg(QString::fromStdString(device.control_level))
        .arg(QString::fromStdString(device.effective_control_level))
        .arg(QString::fromStdString(device.effective_source))
        .arg(device.ignore_hierarchy ? "true" : "false")
        .arg(device.connected ? "true" : "false")
        .arg(QString::fromStdString(device.devpath))
        .arg(QString::fromStdString(device.boot_id))
        .arg(QString::fromStdString(device.last_event_at));
}

void MainWindow::onDeviceClicked(const DeviceInfo& device)
{
    currentDevice = device;
    auto setLabelValue = [](QLabel *label, const QString& value) {
        label->setText(value);
        label->setToolTip(value);
    };

    // Обновляем метки в интерфейсе
    setLabelValue(ui->subsystemLabel, QString::fromStdString(device.subsystem));
    const QString effectiveControl = QString::fromStdString(
        device.effective_control_level.empty() ? device.control_level : device.effective_control_level);
    const QString assignedControl = QString::fromStdString(device.control_level);
    setLabelValue(ui->controlLevelLabel,
                  device.control_explicit
                      ? effectiveControl
                      : effectiveControl + " (унаследовано)");

    setLabelValue(ui->devpathLabel, QString::fromStdString(device.devpath));
    setLabelValue(ui->currentBootTimeLabel, currentBootIdFromDaemon());
    setLabelValue(ui->deviceBootTimeLabel, QString::fromStdString(device.boot_id));

    {
        QSignalBlocker comboBlocker(deviceControlCombo);
        const QString comboControl = assignedControl.isEmpty() ? effectiveControl : assignedControl;
        const int controlIndex = deviceControlCombo->findData(comboControl);
        deviceControlCombo->setCurrentIndex(controlIndex >= 0 ? controlIndex : 0);
        deviceControlCombo->setEnabled(device.id > 0);
    }
    {
        QSignalBlocker checkBlocker(deviceGlobalRuleCheck);
        deviceGlobalRuleCheck->setChecked(device.ignore_hierarchy);
        deviceGlobalRuleCheck->setEnabled(device.id > 0);
    }
    deviceResetControlButton->setEnabled(device.id > 0 && device.control_explicit);
    copyDevpathButton->setEnabled(!device.devpath.empty());
    copyDeviceSummaryButton->setEnabled(device.id > 0);

    //Выводим параметры выбранного устройства
    deviceAttributeList->showDeviceAttributes(device.id);
    deviceEventList->showDeviceEvents(device.id);
    //ui->deviceParamListView->adddeviceTree->loadDeviceAttributes();
}
void MainWindow::onAttributesUpdated(int deviceId, int attributeCount)
{
    // Можно обновить статусбар или другую информацию
    if (attributeCount > 0) {
        ui->statusbar->showMessage(QString("Загружено %1 атрибутов устройства").arg(attributeCount), 3000);
    } else {
        ui->statusbar->showMessage("У устройства нет атрибутов", 3000);
    }
}
QWidget* MainWindow::createPolicyPage(const std::vector<PolicyInfo>& policies,
                                      const std::string moduleName,
                                      QWidget* parent) {
    QWidget* mainWidget = new QWidget(parent);
    QVBoxLayout* mainLayout = new QVBoxLayout(mainWidget);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    QScrollArea* scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QFrame* contentFrame = new QFrame();
    contentFrame->setFrameShape(QFrame::Box);
    contentFrame->setLineWidth(1);

    QGridLayout* gridLayout = new QGridLayout(contentFrame);
    gridLayout->setContentsMargins(10, 10, 10, 10);
    gridLayout->setSpacing(10);
    gridLayout->setColumnMinimumWidth(1, 200);

    QString cellStyle = "QFrame { border: 1px solid #d0d0d0; border-radius: 3px; padding: 5px; }";
    QString submoduleHeaderStyle = "QLabel {"
                                 "  font-weight: bold;"
                                 "  font-size: 14px;"
                                 "  color: palette(window-text);"
                                 "  background-color: palette(midlight);"
                                 "  padding: 8px;"
                                 "  border-radius: 4px;"
                                 "}";

    QFont headerFont;
    headerFont.setBold(true);

    QFrame* enabledHeaderFrame = new QFrame();
    enabledHeaderFrame->setStyleSheet(cellStyle);
    QLabel* enabledHeader = new QLabel(QLocalizationManager::getLang("[module:all][col:is_policy_active]"), enabledHeaderFrame);
    enabledHeader->setFont(headerFont);
    enabledHeader->setAlignment(Qt::AlignCenter);
    QVBoxLayout* enabledHeaderLayout = new QVBoxLayout(enabledHeaderFrame);
    enabledHeaderLayout->addWidget(enabledHeader);

    QFrame* nameHeaderFrame = new QFrame();
    nameHeaderFrame->setStyleSheet(cellStyle);
    QLabel* nameHeader = new QLabel(QLocalizationManager::getLang("[module:all][col:policy_name]"), nameHeaderFrame);
    nameHeader->setFont(headerFont);
    QVBoxLayout* nameHeaderLayout = new QVBoxLayout(nameHeaderFrame);
    nameHeaderLayout->addWidget(nameHeader);

    QFrame* valueHeaderFrame = new QFrame();
    valueHeaderFrame->setStyleSheet(cellStyle);
    QLabel* valueHeader = new QLabel(QLocalizationManager::getLang("[module:all][col:policy_value]"), valueHeaderFrame);
    valueHeader->setFont(headerFont);
    QVBoxLayout* valueHeaderLayout = new QVBoxLayout(valueHeaderFrame);
    valueHeaderLayout->addWidget(valueHeader);

    QFrame* descHeaderFrame = new QFrame();
    descHeaderFrame->setStyleSheet(cellStyle);
    QLabel* descHeader = new QLabel(QLocalizationManager::getLang("[module:all][col:policy_descr]"), descHeaderFrame);
    descHeader->setFont(headerFont);
    QVBoxLayout* descHeaderLayout = new QVBoxLayout(descHeaderFrame);
    descHeaderLayout->addWidget(descHeader);

    gridLayout->addWidget(enabledHeaderFrame, 0, 0);
    gridLayout->addWidget(nameHeaderFrame, 0, 1);
    gridLayout->addWidget(valueHeaderFrame, 0, 2);
    gridLayout->addWidget(descHeaderFrame, 0, 3);

    struct PolicyRowControl {
        PolicyInfo policy;
        QCheckBox* activeCheckbox;
        QWidget* valueWidget;
        PolicyEditorType type;
    };

    struct PendingPolicyChange {
        std::string policyName;
        std::string value;
        bool enabled;
        bool valueConfigurable;
    };

    std::vector<PolicyRowControl> policyControls;
    std::map<std::string, std::vector<PolicyInfo>> policiesBySubmodule;
    for (const PolicyInfo& policy : policies) {
        policiesBySubmodule[policy.submoduleName].push_back(policy);
    }

    int row = 1;
    for (const auto& [submoduleName, submodulePolicies] : policiesBySubmodule) {
        QFrame* submoduleFrame = new QFrame();
        submoduleFrame->setStyleSheet(submoduleHeaderStyle);
        QHBoxLayout* submoduleLayout = new QHBoxLayout(submoduleFrame);
        submoduleLayout->setContentsMargins(0, 0, 0, 0);

        QLabel* submoduleLabel = new QLabel(
            QLocalizationManager::getLang(
                QString::fromStdString("[module:" + moduleName + "][submodule:" + submoduleName + "]")
            )
        );
        submoduleLabel->setAlignment(Qt::AlignCenter);
        submoduleLayout->addWidget(submoduleLabel);

        gridLayout->addWidget(submoduleFrame, row, 0, 1, 4);
        row++;

        for (const PolicyInfo& policy : submodulePolicies) {
            const std::string strLangTpl = "[module:" + moduleName + "][policy:" + policy.policyName + "]";
            const std::string strLangTplDescr = strLangTpl + "[description]";

            QFrame* enabledFrame = new QFrame();
            enabledFrame->setStyleSheet(cellStyle);
            QCheckBox* activeCheckbox = new QCheckBox(enabledFrame);
            activeCheckbox->setChecked(policy.enabled && policy.valueValid);
            QVBoxLayout* enabledLayout = new QVBoxLayout(enabledFrame);
            enabledLayout->addWidget(activeCheckbox, 0, Qt::AlignCenter);

            QFrame* nameFrame = new QFrame();
            nameFrame->setStyleSheet(cellStyle);
            QLabel* nameLabel = new QLabel(QLocalizationManager::getLang(QString::fromStdString(strLangTpl)), nameFrame);
            nameLabel->setWordWrap(true);
            QVBoxLayout* nameLayout = new QVBoxLayout(nameFrame);
            nameLayout->addWidget(nameLabel);

            QFrame* valueFrame = new QFrame();
            valueFrame->setStyleSheet(cellStyle);
            QWidget* controlWidget = nullptr;
            PolicyEditorType type = editorTypeFromString(policy.editor);
            const std::string value = policy.valueValid ? policy.value : policy.defaultValue;

            switch(type) {
                case PolicyEditorType::Label: {
                     QLabel* label = new QLabel(QLocalizationManager::getLang(QString::fromStdString("[utils:policytypevalue][type:fixedpolicytypevalue]")));
                    label->setWordWrap(true);
                    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
                    controlWidget = label;
                    break;
                }
                case PolicyEditorType::SpinBox: {
                    QSpinBox* spinBox = new NoWheelSpinBox();
                    spinBox->setRange(policy.min, policy.max);
                    try {
                        spinBox->setValue(std::stoi(value));
                    } catch (const std::exception&) {
                        spinBox->setValue(policy.min);
                    }
                    controlWidget = spinBox;
                    break;
                }
                case PolicyEditorType::TextEdit: {
                    QTextEdit* textEdit = new QTextEdit();
                    QString text = QString::fromStdString(value);
                    const QString delimiter = QString::fromStdString(policy.textDelimiter);
                    if (!delimiter.isEmpty() && delimiter != "\n") {
                        text.replace(delimiter, "\n");
                    }
                    textEdit->setPlainText(text);
                    controlWidget = textEdit;
                    break;
                }
                case PolicyEditorType::ComboBox: {
                    QComboBox* comboBox = new QComboBox();
                    for (const std::string& possibleValue : policy.possibleValues) {
                        comboBox->addItem(QString::fromStdString(possibleValue));
                    }
                    int valueIndex = comboBox->findText(QString::fromStdString(value));
                    if (valueIndex >= 0) {
                        comboBox->setCurrentIndex(valueIndex);
                    }
                    controlWidget = comboBox;
                    break;
                }
                default: {
                    QLabel* label = new QLabel("Unsupported policy type: " + QString::fromStdString(policy.editor));
                    label->setWordWrap(true);
                    controlWidget = label;
                    activeCheckbox->setEnabled(false);
                    break;
                }
            }

            policyControls.push_back({
                policy,
                activeCheckbox,
                controlWidget,
                type
            });

            QVBoxLayout* valueLayout = new QVBoxLayout(valueFrame);
            valueLayout->addWidget(controlWidget);

            QFrame* descFrame = new QFrame();
            descFrame->setStyleSheet(cellStyle);
            QTextEdit* descEdit = new QTextEdit(descFrame);
            QString description = QLocalizationManager::getLang(QString::fromStdString(strLangTplDescr)) +
                "\n--------------------------------\n" +
                QString::fromStdString(policy.restriction);
            if (!policy.valueValid) {
                description += "\n--------------------------------\nCurrent config value is invalid; default value is shown.";
            }
            descEdit->setPlainText(description);
            descEdit->setReadOnly(true);
            descEdit->setMaximumHeight(100);
            QVBoxLayout* descLayout = new QVBoxLayout(descFrame);
            descLayout->addWidget(descEdit);

            gridLayout->addWidget(enabledFrame, row, 0);
            gridLayout->addWidget(nameFrame, row, 1);
            gridLayout->addWidget(valueFrame, row, 2);
            gridLayout->addWidget(descFrame, row, 3);

            row++;
        }
    }

    gridLayout->setColumnStretch(1, 1);
    gridLayout->setColumnStretch(3, 2);

    scrollArea->setWidget(contentFrame);
    mainLayout->addWidget(scrollArea);

    QPushButton* applyButton = new QPushButton(QLocalizationManager::getLang("[apply_button]"));
    applyButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    applyButton->setMinimumHeight(40);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setContentsMargins(10, 10, 10, 10);
    buttonLayout->addWidget(applyButton);

    mainLayout->addLayout(buttonLayout);

    QObject::connect(applyButton, &QPushButton::clicked, this, [this, moduleName, policyControls]() {
        std::vector<PendingPolicyChange> changes;
        QStringList validationErrors;

        for (const auto& row : policyControls) {
            std::string value;

            switch(row.type) {
                case PolicyEditorType::Label: {
                    value = row.policy.valueValid ? row.policy.value : row.policy.defaultValue;
                    break;
                }
                case PolicyEditorType::SpinBox: {
                    QSpinBox* spinBox = qobject_cast<QSpinBox*>(row.valueWidget);
                    value = spinBox ? std::to_string(spinBox->value()) : "";
                    break;
                }
                case PolicyEditorType::TextEdit: {
                    QTextEdit* textEdit = qobject_cast<QTextEdit*>(row.valueWidget);
                    QString text = textEdit ? textEdit->toPlainText() : "";
                    const QString delimiter = QString::fromStdString(row.policy.textDelimiter);
                    if (!delimiter.isEmpty() && delimiter != "\n") {
                        text.replace("\r\n", "\n");
                        text.replace("\n", delimiter);
                    }
                    value = text.toStdString();
                    break;
                }
                case PolicyEditorType::ComboBox: {
                    QComboBox* comboBox = qobject_cast<QComboBox*>(row.valueWidget);
                    value = comboBox ? comboBox->currentText().toStdString() : "";
                    break;
                }
                default: {
                    value = "";
                    break;
                }
            }

            QString validationError;
            if (!validatePolicyValue(row.policy, value, &validationError)) {
                validationErrors << validationError;
                continue;
            }

            changes.push_back({
                row.policy.policyName,
                value,
                row.activeCheckbox && row.activeCheckbox->isChecked(),
                row.type != PolicyEditorType::Label
            });
        }

        if (!validationErrors.isEmpty()) {
            QMessageBox::warning(
                this,
                "Validation errors",
                validationErrors.join("\n")
            );
            return;
        }

        QStringList applyErrors;
        fic::ipc::Client daemonClient;

        for (const auto& change : changes) {
            if (change.valueConfigurable) {
                auto setResponse = daemonClient.request({
                    {"command", "set_policy_value"},
                    {"module", moduleName},
                    {"policy", change.policyName},
                    {"value", change.value}
                });

                if (!setResponse.value("ok", false)) {
                    applyErrors << QString("Failed to set policy %1: %2")
                        .arg(QString::fromStdString(change.policyName))
                        .arg(QString::fromStdString(setResponse.value("message", "unknown daemon error")));
                    continue;
                }
            }

            auto stateResponse = daemonClient.request({
                {"command", change.enabled ? "enable_policy" : "disable_policy"},
                {"module", moduleName},
                {"policy", change.policyName}
            });

            if (!stateResponse.value("ok", false)) {
                applyErrors << QString("Failed to change policy state %1: %2")
                    .arg(QString::fromStdString(change.policyName))
                    .arg(QString::fromStdString(stateResponse.value("message", "unknown daemon error")));
            }
        }

        if (!applyErrors.isEmpty()) {
            QMessageBox::warning(
                this,
                "Apply errors",
                applyErrors.join("\n")
            );
            return;
        }

        const auto applyResponse = daemonClient.request({
            {"command", "apply_module"},
            {"module", moduleName}
        });

        showPolicyApplyResult(this, applyResponse);
    });

    return mainWidget;
}

std::vector<MainWindow::PolicyInfo> MainWindow::loadPoliciesFromDaemon(QStringList& errors) const {
    std::vector<PolicyInfo> result;
    fic::ipc::Client daemonClient;
    auto response = daemonClient.request({{"command", "policy_list"}, {"module", "all"}});

    if (!response.value("ok", false)) {
        errors << QString::fromStdString(response.value("message", "failed to load policies from daemon"));
        return result;
    }

    if (!response.contains("policies") || !response["policies"].is_array()) {
        errors << "Daemon response does not contain policies array";
        return result;
    }

    for (const auto& item : response["policies"]) {
        if (!item.is_object()) {
            continue;
        }

        PolicyInfo policy;
        policy.moduleName = item.value("module", "");
        policy.submoduleName = item.value("submodule", "");
        policy.policyName = item.value("policy", "");
        policy.editor = item.value("editor", "unknown");
        policy.value = item.value("value", item.value("default_value", ""));
        policy.defaultValue = item.value("default_value", "");
        policy.textDelimiter = item.value("text_delimiter", "");
        policy.restriction = item.value("restriction", "");
        policy.enabled = item.value("enabled", false);
        policy.isSet = item.value("set", false);
        policy.valueValid = item.value("value_valid", true);
        policy.min = item.value("min", 0);
        policy.max = item.value("max", 0);

        if (item.contains("possible_values") && item["possible_values"].is_array()) {
            for (const auto& possibleValue : item["possible_values"]) {
                if (possibleValue.is_string()) {
                    policy.possibleValues.push_back(possibleValue.get<std::string>());
                }
            }
        }

        if (!policy.moduleName.empty() && !policy.policyName.empty()) {
            result.push_back(policy);
        }
    }

    return result;
}

MainWindow::PolicyEditorType MainWindow::editorTypeFromString(const std::string& editor) const {
    if (editor == "label") {
        return PolicyEditorType::Label;
    }
    if (editor == "spinbox") {
        return PolicyEditorType::SpinBox;
    }
    if (editor == "textedit") {
        return PolicyEditorType::TextEdit;
    }
    if (editor == "combobox") {
        return PolicyEditorType::ComboBox;
    }
    return PolicyEditorType::Unknown;
}

bool MainWindow::validatePolicyValue(const PolicyInfo& policy, const std::string& value, QString* error) const {
    const PolicyEditorType type = editorTypeFromString(policy.editor);

    if (type == PolicyEditorType::SpinBox) {
        try {
            int parsed = std::stoi(value);
            if (parsed < policy.min || parsed > policy.max) {
                if (error != nullptr) {
                    *error = QString("Policy %1: value %2 is outside allowed range [%3; %4]")
                        .arg(QString::fromStdString(policy.policyName))
                        .arg(parsed)
                        .arg(policy.min)
                        .arg(policy.max);
                }
                return false;
            }
        } catch (const std::exception&) {
            if (error != nullptr) {
                *error = QString("Policy %1: value '%2' is not an integer")
                    .arg(QString::fromStdString(policy.policyName))
                    .arg(QString::fromStdString(value));
            }
            return false;
        }
    }

    if (type == PolicyEditorType::ComboBox) {
        if (!policy.possibleValues.empty() &&
            std::find(policy.possibleValues.begin(), policy.possibleValues.end(), value) == policy.possibleValues.end()) {
            if (error != nullptr) {
                *error = QString("Policy %1: value '%2' is not in allowed values list")
                    .arg(QString::fromStdString(policy.policyName))
                    .arg(QString::fromStdString(value));
            }
            return false;
        }
    }

    return true;
}

void MainWindow::addModules() {
    this->ui->tab_modules->setTabText(0, QLocalizationManager::getLang("[tab:DEVICES]"));
    this->ui->tab_modules->setTabText(1, QLocalizationManager::getLang("[tab:LOG]"));

    while (this->ui->tab_modules->count() > 2) {
        QWidget* widget = this->ui->tab_modules->widget(2);
        this->ui->tab_modules->removeTab(2);
        delete widget;
    }

    QStringList errors;
    const std::vector<PolicyInfo> policies = loadPoliciesFromDaemon(errors);
    if (!errors.isEmpty()) {
        QMessageBox::warning(this, "FIC daemon", "Failed to load policy data from daemon:\n" + errors.join("\n"));
        return;
    }

    std::map<std::string, std::vector<PolicyInfo>> policiesByModule;
    for (const PolicyInfo& policy : policies) {
        policiesByModule[policy.moduleName].push_back(policy);
    }

    for (const auto& [moduleName, modulePolicies] : policiesByModule) {
        const QString tabTitle =
            QLocalizationManager::getLang(QString::fromStdString("[module:" + moduleName + "]"));

        ui->tab_modules->addTab(
            createPolicyPage(modulePolicies, moduleName),
            tabTitle
        );
    }
}
