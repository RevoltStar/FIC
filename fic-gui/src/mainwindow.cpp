#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "policy/PolicyEditorFactory.h"
#include "utils/SystemBootInfo.h"
#include "ipc/FicIpcClient.h"

#include <QStringList>
#include <vector>

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
    ui->currentBootTimeLabel->setText(QString::fromStdString(SystemBootInfo::get_boot_id()));
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
    ui->currentBootTimeLabel->setText(QString::fromStdString(SystemBootInfo::get_boot_id()));
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
QWidget* MainWindow::createPolicyPage(const std::map<std::string, std::map<std::string, std::shared_ptr<CheckAndFix>>>& submoduleMap,
                         const std::string moduleName, QWidget* parent) {
    // Основной виджет
    QWidget* mainWidget = new QWidget(parent);
    QVBoxLayout* mainLayout = new QVBoxLayout(mainWidget);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // Scroll Area для содержимого
    QScrollArea* scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    // Контейнер для содержимого с границами
    QFrame* contentFrame = new QFrame();
    contentFrame->setFrameShape(QFrame::Box);
    contentFrame->setLineWidth(1);

    QGridLayout* gridLayout = new QGridLayout(contentFrame);
    gridLayout->setContentsMargins(10, 10, 10, 10);
    gridLayout->setSpacing(10);
    gridLayout->setColumnMinimumWidth(1, 200);

    // Стили
    QString cellStyle = "QFrame { border: 1px solid #d0d0d0; border-radius: 3px; padding: 5px; }";
    QString submoduleHeaderStyle = "QLabel {"
                                 "  font-weight: bold;"
                                 "  font-size: 14px;"
                                 "  color: palette(window-text);"
                                 "  background-color: palette(midlight);"
                                 "  padding: 8px;"
                                 "  border-radius: 4px;"
                                 "}";

    // Заголовки столбцов
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
        std::string policyName;
        std::shared_ptr<CheckAndFix> policyClass;
        QCheckBox* activeCheckbox;
        QWidget* valueWidget;
        PolicyEditorType type;
    };

    struct PendingPolicyChange {
        std::string policyName;
        std::string value;
        bool enabled;
    };

    std::vector<PolicyRowControl> policyControls;

    // Добавление подмодулей и политик
    int row = 1;
    for(const auto& [submoduleName, policyMap] : submoduleMap) {
        // Заголовок подмодуля
        QFrame* submoduleFrame = new QFrame();
        submoduleFrame->setStyleSheet(submoduleHeaderStyle);
        QHBoxLayout* submoduleLayout = new QHBoxLayout(submoduleFrame);
        submoduleLayout->setContentsMargins(0, 0, 0, 0);

        QLabel* submoduleLabel = new QLabel(
            QLocalizationManager::getLang(
                    QString::fromStdString(
                        "[module:"+
                        moduleName+
                        "][submodule:"+
                        submoduleName+
                        "]"
                    )
            )
        );
        submoduleLabel->setAlignment(Qt::AlignCenter);
        submoduleLayout->addWidget(submoduleLabel);

        gridLayout->addWidget(submoduleFrame, row, 0, 1, 4);
        row++;

        // Добавление политик подмодуля
        std::string strLangTpl = "";
        std::string strLangTplDescr = "";
        for (const auto& [policyName, policyClass] : policyMap) {
            strLangTpl = "[module:"+moduleName+"][policy:" + policyName + "]";
            strLangTplDescr = strLangTpl + "[description]";

            // Ячейка "Включено"
            QFrame* enabledFrame = new QFrame();
            enabledFrame->setStyleSheet(cellStyle);
            QCheckBox* activeCheckbox = new QCheckBox(enabledFrame);
            // Устанавливаем состояние из isEnable(). Если политика не установлена, то считается, что она выключена
            activeCheckbox->setChecked(policyClass->isEnable());
            QVBoxLayout* enabledLayout = new QVBoxLayout(enabledFrame);
            enabledLayout->addWidget(activeCheckbox, 0, Qt::AlignCenter);

            // Ячейка "Название"
            QFrame* nameFrame = new QFrame();
            nameFrame->setStyleSheet(cellStyle);
            QLabel* nameLabel = new QLabel(QLocalizationManager::getLang(QString::fromStdString(strLangTpl)), nameFrame);
            nameLabel->setWordWrap(true);
            QVBoxLayout* nameLayout = new QVBoxLayout(nameFrame);
            nameLayout->addWidget(nameLabel);

            // Ячейка "Значение"
            QFrame* valueFrame = new QFrame();
            valueFrame->setStyleSheet(cellStyle);
            QWidget* controlWidget = nullptr;
            //Тип GUI-элемента
            auto type = buildEditorSpec(policyClass->getPolicyTypeValue()).type;
            //Установлено ли значение политики в конфигурационном файле
            bool isPolicySet = policyClass->isPolicySet();
            std::string value;

            /*Здесь проверям, что значение в конф. файле записано корректно
            */
            if (isPolicySet) {
                std::optional valueOpt = policyClass->getValue();
                if(!valueOpt){
                    //Здесь может быть ТОЛЬКО невалидное значение, т.к. isPolicySet гарантирует, что какое-то значение записано
                        QMessageBox::warning(parent, "Ошибка",
                                             QString("Недопустимое значение в конфигурационном файле для политики %1: %2.\n"
                                                     "Учтите, что пока значение не будет валидно, политика применяться не будет.")
                                                 .arg(QString::fromStdString(policyName))
                                                 .arg(QString::fromStdString(value))
                                                 );
                    //В графический элемент запишем значение по умолчанию, политику вырубим (isEnable=DISABLE)
                    value = policyClass->getDefaultValue();
                    activeCheckbox->setChecked(false);
                }else{
                    //Значение валидно - берем его.
                    value = *valueOpt;
                }
            } else {
                //Политика не установлена - пишем значение по умолчанию
                //Это безопасно, т.к. политика по умолчанию выключена
                value = policyClass->getDefaultValue();
            }

            switch(type) {
                case PolicyEditorType::CheckBox: {
                    QCheckBox* checkBox = new QCheckBox();
                    checkBox->setChecked(value == "ENABLE");
                    controlWidget = checkBox;
                    break;
                }
                case PolicyEditorType::SpinBox: {
                    QSpinBox* spinBox = new QSpinBox();
                    spinBox->setRange(policyClass->getMin(), policyClass->getMax());
                    spinBox->setValue(std::stoi(value));

                    controlWidget = spinBox;
                    break;
                }
                case PolicyEditorType::TextEdit: {
                    QTextEdit* textEdit = new QTextEdit();
                    QString text = QString::fromStdString(value);
                    text.replace(":", "\n");
                    textEdit->setPlainText(text);

                    controlWidget = textEdit;
                    break;
                }
                case PolicyEditorType::ComboBox: {
                    QComboBox* comboBox = new QComboBox();
                    for (const std::string& possibleValue : policyClass->getPossibleValues()) {
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
                    controlWidget = new QLabel("Unknown type");
                    break;
                }
            }

            policyControls.push_back({
                policyName,
                policyClass,
                activeCheckbox,
                controlWidget,
                type
            });

            /*
            // Если значение невалидно, отключаем чекбокс "Включено"
            if (!valueValid) {
                activeCheckbox->setChecked(false);
                activeCheckbox->setEnabled(false);
            }
            */

            QVBoxLayout* valueLayout = new QVBoxLayout(valueFrame);
            valueLayout->addWidget(controlWidget);

            // Ячейка "Описание"
            QFrame* descFrame = new QFrame();
            descFrame->setStyleSheet(cellStyle);
            QTextEdit* descEdit = new QTextEdit(descFrame);
            //Получаем описание политики и добавляем ограничения
            descEdit->setPlainText(
                QLocalizationManager::getLang(QString::fromStdString(strLangTplDescr)) + "\n" +
                "--------------------------------\n" +
                QString::fromStdString(policyClass->getPolicyRestriction())
            );
            descEdit->setReadOnly(true);
            descEdit->setMaximumHeight(100);
            QVBoxLayout* descLayout = new QVBoxLayout(descFrame);
            descLayout->addWidget(descEdit);

            // Добавление строки в сетку
            gridLayout->addWidget(enabledFrame, row, 0);
            gridLayout->addWidget(nameFrame, row, 1);
            gridLayout->addWidget(valueFrame, row, 2);
            gridLayout->addWidget(descFrame, row, 3);

            row++;
        }
    }

    // Настройка растягивания
    gridLayout->setColumnStretch(1, 1);
    gridLayout->setColumnStretch(3, 2);

    scrollArea->setWidget(contentFrame);
    mainLayout->addWidget(scrollArea);

    // Кнопка "Применить"
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
                case PolicyEditorType::CheckBox: {
                    QCheckBox* checkBox = qobject_cast<QCheckBox*>(row.valueWidget);
                    value = checkBox && checkBox->isChecked() ? "ENABLE" : "DISABLE";
                    break;
                }
                case PolicyEditorType::SpinBox: {
                    QSpinBox* spinBox = qobject_cast<QSpinBox*>(row.valueWidget);
                    value = spinBox ? std::to_string(spinBox->value()) : "";
                    break;
                }
                case PolicyEditorType::TextEdit: {
                    QTextEdit* textEdit = qobject_cast<QTextEdit*>(row.valueWidget);
                    value = textEdit ? textEdit->toPlainText().toStdString() : "";
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

            if (!row.policyClass->validate(value)) {
                validationErrors << QString("Policy %1: invalid value \"%2\"")
                    .arg(QString::fromStdString(row.policyName))
                    .arg(QString::fromStdString(value));
                continue;
            }

            changes.push_back({
                row.policyName,
                value,
                row.activeCheckbox && row.activeCheckbox->isChecked()
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
void MainWindow::addModules() {
    this->cafMap = init_cafMap();
    this->ui->tab_modules->setTabText(0, QLocalizationManager::getLang("[module:DC]"));
    this->ui->tab_modules->setTabText(1, QLocalizationManager::getLang("[module:LOG]"));
    for (const auto& [moduleName, submoduleMap] : cafMap) {
        if (moduleName != "DC") {
            ui->tab_modules->addTab(
                createPolicyPage(submoduleMap, moduleName),
                QLocalizationManager::getLang(
                    QString::fromStdString("[module:" + moduleName + "]")
                )
            );
        }
    }
}
