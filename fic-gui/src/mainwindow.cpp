#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "ipc/FicIpcClient.h"

#include <QStringList>
#include <QWheelEvent>
#include <algorithm>
#include <map>
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
    ui->gridLayout_3->setColumnMinimumWidth(0, 500);
    ui->gridLayout_3->setColumnStretch(0, 0);
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

    deviceAttributeList = new DeviceAttributeList(this);
    QLayoutItem* oldItem = ui->gridLayoutListView->replaceWidget(ui->deviceParamListView, deviceAttributeList);
    if (oldItem) {
            delete oldItem->widget(); // Удаляем старый QListView
            delete oldItem;
    }
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
void MainWindow::onDeviceClicked(const DeviceInfo& device)
{
    // Обновляем метки в интерфейсе
    ui->subsystemLabel->setText(QString::fromStdString(device.subsystem));
    ui->controlLevelLabel->setText(QString::fromStdString(device.control_level));

    ui->devpathLabel->setText(QString::fromStdString(device.devpath));
    ui->currentBootTimeLabel->setText(currentBootIdFromDaemon());
    ui->deviceBootTimeLabel->setText(QString::fromStdString(device.boot_id));
    //Выводим параметры выбранного устройства
    deviceAttributeList->showDeviceAttributes(device.id);
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
                    QLabel* label = new QLabel("Политика не допускает конфигурирования");
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

        QMessageBox::information(
            this,
            "Done",
            "Policies were applied successfully"
        );
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
    this->ui->tab_modules->setTabText(0, QLocalizationManager::getLang("[module:DC]"));
    this->ui->tab_modules->setTabText(1, QLocalizationManager::getLang("[module:LOG]"));

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
        if (moduleName != "DC") {
            ui->tab_modules->addTab(
                createPolicyPage(modulePolicies, moduleName),
                QLocalizationManager::getLang(
                    QString::fromStdString("[module:" + moduleName + "]")
                )
            );
        }
    }
}
