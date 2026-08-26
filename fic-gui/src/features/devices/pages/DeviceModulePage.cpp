#include "features/devices/pages/DeviceModulePage.h"

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
#include <QStringList>
#include <QTabWidget>
#include <QVBoxLayout>

#include "features/devices/widgets/DeviceAttributeList.h"
#include "features/devices/widgets/DeviceEventList.h"
#include "features/devices/services/DeviceService.h"
#include "features/policies/widgets/PolicyEditorWidget.h"
#include "shared/i18n/QLocalizationManager.h"

namespace {
QString deviceText(const char* key)
{
    return QLocalizationManager::getLang(
        QString::fromLatin1("[devices:ui][") + QString::fromLatin1(key) + ']');
}

QString controlLevelText(const std::string& value)
{
    if (value == "blocked") return deviceText("blocked");
    if (value == "allowed") return deviceText("allowed");
    if (value == "permanent") return deviceText("permanent");
    if (value == "ignored") return deviceText("ignored");
    return QString::fromStdString(value);
}

QString childrenPolicyText(const std::string& value)
{
    if (value == "inherit") return deviceText("inherit");
    if (value == "allow") return deviceText("allow");
    if (value == "deny") return deviceText("deny");
    return QString::fromStdString(value);
}
}

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
    auto* summary = new QGroupBox(deviceText("device_details"), details);
    auto* form = new QFormLayout(summary);
    subsystem_ = new QLabel(deviceText("not_set"), summary);
    controlLevel_ = new QLabel(deviceText("not_set"), summary);
    devpath_ = new QLabel(deviceText("not_set"), summary);
    currentBootId_ = new QLabel(DeviceService().currentBootId(), summary);
    deviceBootId_ = new QLabel(deviceText("not_set"), summary);
    devpath_->setWordWrap(true);
    for (QLabel* label : {subsystem_, controlLevel_, devpath_, currentBootId_, deviceBootId_}) {
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    }
    form->addRow(deviceText("subsystem"), subsystem_);
    form->addRow(deviceText("control_level"), controlLevel_);
    form->addRow(deviceText("devpath"), devpath_);
    form->addRow(deviceText("current_boot_id"), currentBootId_);
    form->addRow(deviceText("device_boot_id"), deviceBootId_);

    auto* policy = new QGroupBox(deviceText("device_rule"), details);
    auto* policyLayout = new QGridLayout(policy);
    control_ = new QComboBox(policy);
    control_->addItem(deviceText("blocked"), "blocked");
    control_->addItem(deviceText("allowed"), "allowed");
    control_->addItem(deviceText("permanent"), "permanent");
    control_->addItem(deviceText("ignored"), "ignored");
    globalRule_ = new QCheckBox(deviceText("system_wide_rule"), policy);
    childrenControl_ = new QComboBox(policy);
    childrenControl_->addItem(deviceText("inherit"), "inherit");
    childrenControl_->addItem(deviceText("allow"), "allow");
    childrenControl_->addItem(deviceText("deny"), "deny");
    reset_ = new QPushButton(deviceText("reset"), policy);
    policyLayout->addWidget(new QLabel(deviceText("device"), policy), 0, 0);
    policyLayout->addWidget(control_, 0, 1);
    policyLayout->addWidget(globalRule_, 0, 2);
    policyLayout->addWidget(reset_, 0, 3);
    policyLayout->addWidget(new QLabel(deviceText("children_policy"), policy), 1, 0);
    policyLayout->addWidget(childrenControl_, 1, 1, 1, 3);

    copyPath_ = new QPushButton(deviceText("copy_path"), details);
    copySummary_ = new QPushButton(deviceText("copy_summary"), details);
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
            ? deviceText("attributes_loaded").arg(count)
            : deviceText("no_attributes"));
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
    const QString localizedEffective = controlLevelText(effective.toStdString());
    controlLevel_->setText(device.control_explicit
        ? localizedEffective
        : deviceText("inherited_value").arg(localizedEffective));
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
    const auto line = [](const QString& label, const QString& value) {
        return QStringLiteral("%1: %2").arg(label, value);
    };
    return QStringList{
        line(deviceText("summary_id"), QString::number(device.id)),
        line(deviceText("summary_subsystem"), QString::fromStdString(device.subsystem)),
        line(deviceText("summary_control_level"), controlLevelText(device.control_level)),
        line(deviceText("summary_effective_control_level"),
             controlLevelText(device.effective_control_level)),
        line(deviceText("summary_effective_source"),
             QString::fromStdString(device.effective_source)),
        line(deviceText("summary_ignore_hierarchy"),
             deviceText(device.ignore_hierarchy ? "yes" : "no")),
        line(deviceText("summary_children_policy"),
             childrenPolicyText(device.children_control)),
        line(deviceText("summary_connected"), deviceText(device.connected ? "yes" : "no")),
        line(deviceText("summary_devpath"), QString::fromStdString(device.devpath)),
        line(deviceText("summary_boot_id"), QString::fromStdString(device.boot_id)),
        line(deviceText("summary_last_event"), QString::fromStdString(device.last_event_at))
    }.join('\n');
}
