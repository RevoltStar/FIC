#include "pages/DeviceModulePage.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSplitter>
#include <QTabWidget>
#include <QVBoxLayout>

#include "DeviceAttributeList.h"
#include "DeviceEventList.h"
#include "services/DeviceService.h"
#include "widgets/PolicyEditorWidget.h"
#include "wrappers/QLocalizationManager.h"

DeviceModulePage::DeviceModulePage(
    const std::string& module,
    const std::vector<PolicyDescriptor>& policies,
    QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    auto* tabs = new QTabWidget(this);
    events_ = new DeviceEventList(tabs);
    tabs->addTab(createTreePage(),
                 QLocalizationManager::getLang("[module:DC][page:device_tree]"));
    tabs->addTab(new PolicyEditorWidget(module, policies, tabs),
                 QLocalizationManager::getLang("[module:DC][page:general_rules]"));
    tabs->addTab(events_,
                 QLocalizationManager::getLang("[module:DC][page:events]"));
    layout->addWidget(tabs);
    deviceTree_->loadDeviceTree();
}

QWidget* DeviceModulePage::createTreePage()
{
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);
    auto* splitter = new QSplitter(Qt::Horizontal, page);
    deviceTree_ = new DeviceTree(splitter);

    auto* details = new QWidget(splitter);
    auto* detailsLayout = new QVBoxLayout(details);
    auto* summary = new QGroupBox(QString::fromUtf8(u8"Сведения об устройстве"), details);
    auto* form = new QFormLayout(summary);
    subsystem_ = new QLabel("[NO SET]", summary);
    controlLevel_ = new QLabel("[NO SET]", summary);
    devpath_ = new QLabel("[NO SET]", summary);
    currentBootId_ = new QLabel(DeviceService().currentBootId(), summary);
    deviceBootId_ = new QLabel("[NO SET]", summary);
    devpath_->setWordWrap(true);
    for (QLabel* label : {subsystem_, controlLevel_, devpath_, currentBootId_, deviceBootId_}) {
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    }
    form->addRow(QString::fromUtf8(u8"Подсистема:"), subsystem_);
    form->addRow(QString::fromUtf8(u8"Уровень контроля:"), controlLevel_);
    form->addRow(QString::fromUtf8(u8"Путь (devpath):"), devpath_);
    form->addRow(QString::fromUtf8(u8"Текущий boot_id:"), currentBootId_);
    form->addRow(QString::fromUtf8(u8"boot_id устройства:"), deviceBootId_);

    auto* policy = new QGroupBox(QString::fromUtf8(u8"Правило устройства"), details);
    auto* policyLayout = new QGridLayout(policy);
    control_ = new QComboBox(policy);
    control_->addItem(QString::fromUtf8(u8"Запрещено"), "blocked");
    control_->addItem(QString::fromUtf8(u8"Разрешено"), "allowed");
    control_->addItem(QString::fromUtf8(u8"Постоянно"), "permanent");
    control_->addItem(QString::fromUtf8(u8"Не контролируется"), "ignored");
    globalRule_ = new QCheckBox(QString::fromUtf8(u8"Во всей системе"), policy);
    childrenControl_ = new QComboBox(policy);
    childrenControl_->addItem(QString::fromUtf8(u8"Наследовать"), "inherit");
    childrenControl_->addItem(QString::fromUtf8(u8"Разрешать"), "allow");
    childrenControl_->addItem(QString::fromUtf8(u8"Запрещать"), "deny");
    reset_ = new QPushButton(QString::fromUtf8(u8"Сбросить"), policy);
    policyLayout->addWidget(new QLabel(QString::fromUtf8(u8"Устройство:"), policy), 0, 0);
    policyLayout->addWidget(control_, 0, 1);
    policyLayout->addWidget(globalRule_, 0, 2);
    policyLayout->addWidget(reset_, 0, 3);
    policyLayout->addWidget(new QLabel(QString::fromUtf8(u8"Потомки:"), policy), 1, 0);
    policyLayout->addWidget(childrenControl_, 1, 1, 1, 3);

    copyPath_ = new QPushButton(QString::fromUtf8(u8"Копировать путь"), details);
    copySummary_ = new QPushButton(QString::fromUtf8(u8"Копировать сведения"), details);
    auto* buttons = new QHBoxLayout();
    buttons->addWidget(copyPath_);
    buttons->addWidget(copySummary_);
    status_ = new QLabel(details);
    attributes_ = new DeviceAttributeList(details);
    detailsLayout->addWidget(summary);
    detailsLayout->addWidget(policy);
    detailsLayout->addLayout(buttons);
    detailsLayout->addWidget(attributes_, 1);
    detailsLayout->addWidget(status_);

    splitter->addWidget(deviceTree_);
    splitter->addWidget(details);
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 1);
    layout->addWidget(splitter);

    control_->setEnabled(false);
    globalRule_->setEnabled(false);
    childrenControl_->setEnabled(false);
    reset_->setEnabled(false);
    copyPath_->setEnabled(false);
    copySummary_->setEnabled(false);
    connect(deviceTree_, &DeviceTree::deviceClicked,
            this, [this](const DeviceInfo& device) { onDeviceClicked(device); });
    connect(attributes_, &DeviceAttributeList::attributesUpdated,
            this, [this](int, int count) {
        status_->setText(count > 0
            ? QString::fromUtf8(u8"Загружено атрибутов: %1").arg(count)
            : QString::fromUtf8(u8"У устройства нет атрибутов"));
    });
    connect(control_, QOverload<int>::of(&QComboBox::activated), this, [this](int index) {
        if (currentDevice_.id > 0) deviceTree_->applyControlLevelToCurrentDevice(control_->itemData(index).toString());
    });
    connect(globalRule_, &QCheckBox::toggled, this, [this](bool checked) {
        if (currentDevice_.id > 0 && checked != currentDevice_.ignore_hierarchy)
            deviceTree_->applyIgnoreHierarchyToCurrentDevice(checked);
    });
    connect(childrenControl_, QOverload<int>::of(&QComboBox::activated), this, [this](int index) {
        if (currentDevice_.id > 0) deviceTree_->applyChildrenControlToCurrentDevice(childrenControl_->itemData(index).toString());
    });
    connect(reset_, &QPushButton::clicked, deviceTree_, &DeviceTree::resetCurrentDeviceControl);
    connect(copyPath_, &QPushButton::clicked, this, [this]() {
        QApplication::clipboard()->setText(QString::fromStdString(currentDevice_.devpath));
    });
    connect(copySummary_, &QPushButton::clicked, this, [this]() {
        QApplication::clipboard()->setText(deviceSummary(currentDevice_));
    });
    return page;
}

void DeviceModulePage::onDeviceClicked(const DeviceInfo& device)
{
    currentDevice_ = device;
    subsystem_->setText(QString::fromStdString(device.subsystem));
    const QString effective = QString::fromStdString(
        device.effective_control_level.empty() ? device.control_level : device.effective_control_level);
    controlLevel_->setText(device.control_explicit ? effective : effective + QString::fromUtf8(u8" (унаследовано)"));
    devpath_->setText(QString::fromStdString(device.devpath));
    currentBootId_->setText(DeviceService().currentBootId());
    deviceBootId_->setText(QString::fromStdString(device.boot_id));
    {
        QSignalBlocker blocker(control_);
        const int index = control_->findData(QString::fromStdString(device.control_level));
        control_->setCurrentIndex(index >= 0 ? index : 0);
    }
    {
        QSignalBlocker blocker(globalRule_);
        globalRule_->setChecked(device.ignore_hierarchy);
    }
    {
        QSignalBlocker blocker(childrenControl_);
        const int index = childrenControl_->findData(QString::fromStdString(device.children_control));
        childrenControl_->setCurrentIndex(index >= 0 ? index : 0);
    }
    control_->setEnabled(device.id > 0);
    globalRule_->setEnabled(device.id > 0);
    childrenControl_->setEnabled(device.id > 0);
    reset_->setEnabled(device.id > 0 && device.control_explicit);
    copyPath_->setEnabled(!device.devpath.empty());
    copySummary_->setEnabled(device.id > 0);
    attributes_->showDeviceAttributes(device.id);
    events_->showDeviceEvents(device.id);
}

QString DeviceModulePage::deviceSummary(const DeviceInfo& device) const
{
    return QString("id: %1\nsubsystem: %2\ncontrol_level: %3\neffective_control_level: %4\n"
                   "effective_source: %5\nignore_hierarchy: %6\nchildren_control: %7\nconnected: %8\n"
                   "devpath: %9\nboot_id: %10\nlast_event_at: %11")
        .arg(device.id)
        .arg(QString::fromStdString(device.subsystem))
        .arg(QString::fromStdString(device.control_level))
        .arg(QString::fromStdString(device.effective_control_level))
        .arg(QString::fromStdString(device.effective_source))
        .arg(device.ignore_hierarchy ? "true" : "false")
        .arg(QString::fromStdString(device.children_control))
        .arg(device.connected ? "true" : "false")
        .arg(QString::fromStdString(device.devpath))
        .arg(QString::fromStdString(device.boot_id))
        .arg(QString::fromStdString(device.last_event_at));
}
