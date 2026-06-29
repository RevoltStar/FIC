#include "DeviceTree.h"
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QHeaderView>
#include <QMenu>
#include <QMessageBox>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QStyle>
#include <fic/ipc/FicIpcClient.h>
#include "wrappers/QLocalizationManager.h"
#include <algorithm>
#include <cctype>
#include <exception>
#include <iomanip>
#include <sstream>
#include <sys/utsname.h> // Для получения времени старта ОС

namespace {
constexpr int RoleSubsystem = Qt::UserRole + 1;
constexpr int RoleDevpath = Qt::UserRole + 2;
constexpr int RoleEffectiveControl = Qt::UserRole + 3;
constexpr int RoleConnected = Qt::UserRole + 4;
constexpr int RoleBootValid = Qt::UserRole + 5;

std::string upperCopy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

std::string normalizePciClassKey(std::string value)
{
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char ch) {
        return std::isxdigit(ch) == 0;
    }), value.end());

    while (value.length() < 6) {
        value = "0" + value;
    }
    if (value.length() > 6) {
        value = value.substr(value.length() - 6);
    }

    value = upperCopy(value);
    return value.substr(0, 2) + "|" + value.substr(2, 2) + "|" + value.substr(4, 2);
}

std::string normalizeUsbTypePart(std::string value)
{
    if (value.empty()) {
        return "00";
    }

    const bool containsHexLetter = std::any_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isalpha(ch) != 0;
    });

    try {
        const unsigned long number = std::stoul(value, nullptr, containsHexLetter ? 16 : 10);
        std::stringstream ss;
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (number & 0xFF);
        return ss.str();
    } catch (const std::exception&) {
        value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char ch) {
            return std::isxdigit(ch) == 0;
        }), value.end());
        while (value.length() < 2) {
            value = "0" + value;
        }
        if (value.length() > 2) {
            value = value.substr(value.length() - 2);
        }
        return upperCopy(value);
    }
}

std::string normalizeUsbTypeKey(const std::string& type)
{
    std::vector<std::string> parts;
    std::stringstream ss(type);
    std::string token;

    while (std::getline(ss, token, '/')) {
        parts.push_back(normalizeUsbTypePart(token));
    }

    if (parts.empty()) {
        return "";
    }
    while (parts.size() < 3) {
        parts.push_back("00");
    }
    if (parts.size() > 3) {
        parts.resize(3);
    }

    return parts[0] + "|" + parts[1] + "|" + parts[2];
}

std::string lastPathComponent(const std::string& path)
{
    const std::size_t end = path.find_last_not_of('/');
    if (end == std::string::npos) {
        return {};
    }

    const std::size_t begin = path.find_last_of('/', end);
    if (begin == std::string::npos) {
        return path.substr(0, end + 1);
    }

    return path.substr(begin + 1, end - begin);
}

std::string compactDevpathLabel(const std::string& devpath)
{
    const std::string leaf = lastPathComponent(devpath);
    if (!leaf.empty()) {
        return leaf;
    }

    return devpath.empty() ? "unknown" : devpath;
}

std::string localizeDeviceClass(const std::string& subsystem, const std::string& classKey)
{
    if (classKey.empty()) {
        return "";
    }

    const std::string key = "[devices:class][subsystem:" + subsystem + "][class:" + classKey + "]";
    const QString localized = QLocalizationManager::getLang(QString::fromStdString(key));
    return localized.toStdString() == key ? "" : localized.toStdString();
}

fic::ipc::Client deviceClient()
{
    return fic::ipc::Client(fic::ipc::DEFAULT_DEVICE_SOCKET_PATH);
}

void fillDeviceFromJson(DeviceInfo& device, const nlohmann::json& item)
{
    device.id = item.value("id", -1);
    device.device_hash = item.value("device_hash", "");
    device.devpath = item.value("devpath", "");
    device.subsystem = item.value("subsystem", "");
    device.device_type = item.value("device_type", "");
    device.parent_id = item.value("parent_id", 0);
    device.control_level = item.value("control_level", "");
    device.control_explicit = item.value("control_explicit", true);
    device.ignore_hierarchy = item.value("ignore_hierarchy", false);
    device.effective_control_level = item.value("effective_control_level", device.control_level);
    device.effective_source = item.value("effective_source", "");
    device.effective_source_device_id = item.value("effective_source_device_id", -1);
    device.effective_reason = item.value("effective_reason", "");
    device.connected = item.value("connected", false);
    device.boot_id = item.value("boot_id", "");
    device.created_at = item.value("created_at", "");
    device.last_event_at = item.value("last_event_at", "");
    device.notes = item.value("notes", "");
}
} // namespace

DeviceTree::DeviceTree(QWidget *parent)
    : QWidget(parent)
{
    setupUI();
    setupRefreshTimer();
}

DeviceTree::~DeviceTree()
{
}

void DeviceTree::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    QHBoxLayout *filterLayout = new QHBoxLayout();
    searchEdit = new QLineEdit(this);
    searchEdit->setPlaceholderText("Поиск: имя, путь, subsystem");
    quickFilterCombo = new QComboBox(this);
    quickFilterCombo->addItem("Все устройства", "all");
    quickFilterCombo->addItem("Заблокированные", "blocked");
    quickFilterCombo->addItem("Постоянные", "permanent");
    quickFilterCombo->addItem("USB", "usb");
    quickFilterCombo->addItem("Диски", "block");
    quickFilterCombo->addItem("История", "history");
    btnClearFilter = new QPushButton("Сбросить", this);
    filterStatsLabel = new QLabel(this);
    filterStatsLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    filterLayout->addWidget(searchEdit, 1);
    filterLayout->addWidget(quickFilterCombo);
    filterLayout->addWidget(btnClearFilter);
    filterLayout->addWidget(filterStatsLabel);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    btnExpandAll = new QPushButton("Развернуть все", this);
    btnCollapseAll = new QPushButton("Свернуть все", this);
    chkShowHistory = new QCheckBox("История", this);
    chkShowHistory->setToolTip(
        "Показать отключенные устройства и прошлые экземпляры. "
        "По умолчанию дерево показывает только текущую загрузку."
    );

    buttonLayout->addWidget(btnExpandAll);
    buttonLayout->addWidget(btnCollapseAll);
    buttonLayout->addWidget(chkShowHistory);
    buttonLayout->addStretch();

    // Дерево устройств
    treeWidget = new QTreeWidget(this);
    treeWidget->setColumnCount(2);
    treeWidget->setHeaderLabels({"Устройство", "Статус"});
    treeWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    treeWidget->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    treeWidget->setTextElideMode(Qt::ElideNone);
    treeWidget->setWordWrap(false);
    treeWidget->setIndentation(14);
    treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    treeWidget->setMinimumWidth(640);
    setMinimumWidth(660);
    setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    treeWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    treeWidget->header()->setStretchLastSection(false);
    treeWidget->header()->setSectionResizeMode(0, QHeaderView::Interactive);
    treeWidget->header()->setSectionResizeMode(1, QHeaderView::Fixed);
    treeWidget->setColumnWidth(0, 520);
    treeWidget->setColumnWidth(1, 96);

    filterTimer = new QTimer(this);
    filterTimer->setSingleShot(true);
    filterTimer->setInterval(250);

    connect(treeWidget, &QTreeWidget::itemExpanded,
            this, &DeviceTree::onItemExpanded);
    connect(btnExpandAll, &QPushButton::clicked,
            this, &DeviceTree::expandAllNodes);
    connect(btnCollapseAll, &QPushButton::clicked,
            this, &DeviceTree::collapseAllNodes);
    connect(searchEdit, &QLineEdit::textChanged,
            this, &DeviceTree::scheduleFilterUpdate);
    connect(quickFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int) {
                scheduleFilterUpdate();
            });
    connect(btnClearFilter, &QPushButton::clicked,
            this, [this]() {
                searchEdit->clear();
                quickFilterCombo->setCurrentIndex(0);
                scheduleFilterUpdate();
            });
    connect(filterTimer, &QTimer::timeout,
            this, &DeviceTree::applyDeviceFilter);
    connect(chkShowHistory, &QCheckBox::toggled,
            this, [this](bool) {
                refreshPreservingState();
            });
    connect(treeWidget, &QTreeWidget::itemClicked,
            this, &DeviceTree::onItemClicked);
    connect(treeWidget, &QTreeWidget::currentItemChanged,
            this, [this](QTreeWidgetItem *current, QTreeWidgetItem *previous) {
                Q_UNUSED(previous);
                onItemClicked(current, 0);
            });
    connect(treeWidget, &QWidget::customContextMenuRequested,
            this, &DeviceTree::showControlLevelContextMenu);

    mainLayout->addLayout(filterLayout);
    mainLayout->addLayout(buttonLayout);
    mainLayout->addWidget(treeWidget);

    // Устанавливаем макет для виджета
    setLayout(mainLayout);
}

int DeviceTree::currentDeviceId() const
{
    QTreeWidgetItem *item = treeWidget == nullptr ? nullptr : treeWidget->currentItem();
    if (item == nullptr || !item->data(0, Qt::UserRole).isValid())
    {
        return -1;
    }

    return item->data(0, Qt::UserRole).toInt();
}

void DeviceTree::applyControlLevelToCurrentDevice(const QString &controlLevel)
{
    const int deviceId = currentDeviceId();
    if (deviceId <= 0)
    {
        return;
    }

    setDeviceControlLevel(deviceId, controlLevel.toStdString());
}

void DeviceTree::applyIgnoreHierarchyToCurrentDevice(bool ignoreHierarchy)
{
    const int deviceId = currentDeviceId();
    if (deviceId <= 0)
    {
        return;
    }

    setDeviceIgnoreHierarchy(deviceId, ignoreHierarchy);
}

void DeviceTree::resetCurrentDeviceControl()
{
    const int deviceId = currentDeviceId();
    if (deviceId <= 0)
    {
        return;
    }

    resetDeviceControl(deviceId);
}


DeviceInfo DeviceTree::fetchDeviceById(int deviceId) const
{
    DeviceInfo device{};
    device.id = -1;

    auto response = deviceClient().request({{"command", "device_get"}, {"device_id", deviceId}});
    if (!response.value("ok", false) || !response.contains("device") || !response["device"].is_object()) {
        qDebug() << "Failed to load device:" << QString::fromStdString(response.value("message", "unknown daemon error"));
        return device;
    }

    fillDeviceFromJson(device, response["device"]);
    return device;
}

std::vector<DeviceInfo> DeviceTree::fetchChildDevices(int parentId, bool includeDisconnected) const
{
    std::vector<DeviceInfo> children;
    auto response = deviceClient().request({
        {"command", "device_children"},
        {"parent_id", parentId},
        {"include_disconnected", includeDisconnected}
    });
    if (!response.value("ok", false) || !response.contains("children") || !response["children"].is_array()) {
        qDebug() << "Failed to load device children:" << QString::fromStdString(response.value("message", "unknown daemon error"));
        return children;
    }

    for (const auto& childJson : response["children"]) {
        if (!childJson.is_object()) {
            continue;
        }
        DeviceInfo child{};
        fillDeviceFromJson(child, childJson);
        if (child.id != -1) {
            children.push_back(child);
        }
    }

    return children;
}

std::map<std::string, std::string> DeviceTree::fetchDeviceAttributes(int deviceId) const
{
    std::map<std::string, std::string> attributes;
    auto response = deviceClient().request({{"command", "device_attributes"}, {"device_id", deviceId}});
    if (!response.value("ok", false) || !response.contains("attributes") || !response["attributes"].is_object()) {
        qDebug() << "Failed to load device attributes:" << QString::fromStdString(response.value("message", "unknown daemon error"));
        return attributes;
    }

    for (auto it = response["attributes"].begin(); it != response["attributes"].end(); ++it) {
        if (it.value().is_string()) {
            attributes[it.key()] = it.value().get<std::string>();
        }
    }
    return attributes;
}

std::string DeviceTree::getDeviceAttribute(int deviceId, const std::string& attributeName, const std::string& defaultValue) const
{
    const auto attributes = fetchDeviceAttributes(deviceId);
    auto it = attributes.find(attributeName);
    if (it == attributes.end()) {
        return defaultValue;
    }
    return it->second;
}

bool DeviceTree::updateDeviceControlLevelRemote(int deviceId, const std::string& controlLevel, QString *errorMessage) const
{
    auto response = deviceClient().request({
        {"command", "device_update_control_level"},
        {"device_id", deviceId},
        {"control_level", controlLevel}
    });
    if (!response.value("ok", false)) {
        const QString message = QString::fromStdString(response.value("message", "unknown daemon error"));
        if (errorMessage != nullptr) {
            *errorMessage = message;
        }
        qDebug() << "Failed to update device control level:" << message;
        return false;
    }
    return true;
}

bool DeviceTree::updateDeviceIgnoreHierarchyRemote(int deviceId, bool ignoreHierarchy, QString *errorMessage) const
{
    auto response = deviceClient().request({
        {"command", "device_update_ignore_hierarchy"},
        {"device_id", deviceId},
        {"ignore_hierarchy", ignoreHierarchy}
    });
    if (!response.value("ok", false)) {
        const QString message = QString::fromStdString(response.value("message", "unknown daemon error"));
        if (errorMessage != nullptr) {
            *errorMessage = message;
        }
        qDebug() << "Failed to update ignore_hierarchy:" << message;
        return false;
    }
    return true;
}

bool DeviceTree::resetDeviceControlRemote(int deviceId, QString *errorMessage) const
{
    auto response = deviceClient().request({
        {"command", "device_reset_control"},
        {"device_id", deviceId}
    });
    if (!response.value("ok", false)) {
        const QString message = QString::fromStdString(response.value("message", "unknown daemon error"));
        if (errorMessage != nullptr) {
            *errorMessage = message;
        }
        qDebug() << "Failed to reset device control:" << message;
        return false;
    }
    return true;
}

bool DeviceTree::deleteDeviceRemote(int deviceId, QString *errorMessage) const
{
    auto response = deviceClient().request({{"command", "device_delete"}, {"device_id", deviceId}});
    if (!response.value("ok", false)) {
        const QString message = QString::fromStdString(response.value("message", "unknown daemon error"));
        if (errorMessage != nullptr) {
            *errorMessage = message;
        }
        qDebug() << "Failed to delete device:" << message;
        return false;
    }
    return true;
}

void DeviceTree::setupRefreshTimer()
{
    refreshTimer = new QTimer(this);
    refreshTimer->setInterval(5000);

    connect(refreshTimer, &QTimer::timeout,
            this, &DeviceTree::refreshPreservingState);
    refreshTimer->start();
}

void DeviceTree::scheduleDeviceTreeRefresh()
{
    refreshPreservingState();
}

void DeviceTree::scheduleFilterUpdate()
{
    if (filterTimer != nullptr)
    {
        filterTimer->start();
    }
}

void DeviceTree::onItemClicked(QTreeWidgetItem *item, int column)
{
    Q_UNUSED(column);

    // Получаем ID устройства из данных элемента
    if (item == nullptr)
    {
        return;
    }

    int deviceId = item->data(0, Qt::UserRole).toInt();

    // Получаем информацию об устройстве из базы данных
    DeviceInfo device = fetchDeviceById(deviceId);

    if (device.id != -1)
    {
        // Отправляем сигнал с данными устройства
        emit deviceClicked(device);
    }
}

void DeviceTree::showControlLevelContextMenu(const QPoint &position)
{
    QTreeWidgetItem *item = treeWidget->itemAt(position);
    if (item == nullptr || !item->data(0, Qt::UserRole).isValid())
    {
        return;
    }

    treeWidget->setCurrentItem(item);

    int deviceId = item->data(0, Qt::UserRole).toInt();
    const std::string currentBootId = getSystemBootId();
    bool canDelete = false;
    DeviceInfo device = fetchDeviceById(deviceId);
    if (device.id != -1)
    {
        canDelete = canDeleteDeviceSubtree(deviceId, currentBootId);
    }

    if (device.id == -1)
    {
        return;
    }

    QMenu menu(this);
    QMenu *controlMenu = menu.addMenu("Уровень контроля");

    auto addControlAction = [&](const QString &title, const std::string &controlLevel)
    {
        QAction *action = controlMenu->addAction(title);
        action->setCheckable(true);
        action->setChecked(device.control_explicit && device.control_level == controlLevel);
        connect(action, &QAction::triggered, this, [this, deviceId, controlLevel]() {
            setDeviceControlLevel(deviceId, controlLevel);
        });
    };

    addControlAction("Запрещено", "blocked");
    addControlAction("Разрешено", "allowed");
    addControlAction("Постоянно", "permanent");
    addControlAction("Не контролируется", "ignored");

    menu.addSeparator();
    QAction *ignoreHierarchyAction = menu.addAction("Действует во всей системе");
    ignoreHierarchyAction->setCheckable(true);
    ignoreHierarchyAction->setChecked(device.ignore_hierarchy);
    connect(ignoreHierarchyAction, &QAction::triggered, this, [this, deviceId](bool checked) {
        setDeviceIgnoreHierarchy(deviceId, checked);
    });

    QAction *resetControlAction = menu.addAction("Сбросить до наследования");
    resetControlAction->setEnabled(device.control_explicit);
    connect(resetControlAction, &QAction::triggered, this, [this, deviceId]() {
        resetDeviceControl(deviceId);
    });

    menu.addSeparator();
    QAction *copyDevpathAction = menu.addAction("Копировать devpath");
    copyDevpathAction->setEnabled(!device.devpath.empty());
    connect(copyDevpathAction, &QAction::triggered, this, [device]() {
        QApplication::clipboard()->setText(QString::fromStdString(device.devpath));
    });

    menu.addSeparator();
    QAction *deleteAction = menu.addAction("Удалить");
    deleteAction->setEnabled(canDelete);
    const QString deviceName = item->text(0);
    connect(deleteAction, &QAction::triggered, this, [this, deviceId, deviceName]() {
        deleteDeviceFromDatabase(deviceId, deviceName);
    });

    menu.exec(treeWidget->viewport()->mapToGlobal(position));
}

void DeviceTree::setDeviceControlLevel(int deviceId, const std::string &controlLevel)
{
    if (deviceId <= 0)
    {
        return;
    }
    DeviceInfo device = fetchDeviceById(deviceId);
    if (device.id == -1)
    {
        return;
    }

    QString errorMessage;
    bool updated = updateDeviceControlLevelRemote(deviceId, controlLevel, &errorMessage);
    if (updated)
    {
        device.control_level = controlLevel;
        device.control_explicit = true;
    }

    if (!updated)
    {
        QMessageBox::warning(this,
                             "Контроль устройств",
                             errorMessage.isEmpty() ? "Не удалось обновить уровень контроля." : errorMessage);
        qDebug() << "Failed to update control_level for device" << deviceId;
        return;
    }

    refreshPreservingState();
    emit deviceClicked(fetchDeviceById(deviceId));
}

void DeviceTree::setDeviceIgnoreHierarchy(int deviceId, bool ignoreHierarchy)
{
    if (deviceId <= 0)
    {
        return;
    }

    QString errorMessage;
    if (!updateDeviceIgnoreHierarchyRemote(deviceId, ignoreHierarchy, &errorMessage))
    {
        QMessageBox::warning(this,
                             "Контроль устройств",
                             errorMessage.isEmpty() ? "Не удалось обновить область действия правила." : errorMessage);
        return;
    }

    refreshPreservingState();
    emit deviceClicked(fetchDeviceById(deviceId));
}

void DeviceTree::resetDeviceControl(int deviceId)
{
    if (deviceId <= 0)
    {
        return;
    }

    QString errorMessage;
    if (!resetDeviceControlRemote(deviceId, &errorMessage))
    {
        QMessageBox::warning(this,
                             "Контроль устройств",
                             errorMessage.isEmpty() ? "Не удалось сбросить правило до наследования." : errorMessage);
        return;
    }

    refreshPreservingState();
    emit deviceClicked(fetchDeviceById(deviceId));
}

bool DeviceTree::canDeleteDevice(const DeviceInfo& device)
{
    if (device.id <= 0 || device.id == 1 || device.parent_id <= 0)
    {
        return false;
    }

    if (device.boot_id == "-1")
    {
        return false;
    }

    const std::string currentBootId = getSystemBootId();
    if (currentBootId.empty())
    {
        return false;
    }

    return device.boot_id != currentBootId;
}

bool DeviceTree::canDeleteDeviceSubtree(int deviceId, const std::string &currentBootId)
{
    if (currentBootId.empty())
    {
        return false;
    }

    DeviceInfo device = fetchDeviceById(deviceId);
    if (device.id <= 0 || device.id == 1 || device.parent_id <= 0 ||
        device.boot_id == "-1" || device.boot_id == currentBootId)
    {
        return false;
    }

    const std::vector<DeviceInfo> children = fetchChildDevices(deviceId, true);
    for (const DeviceInfo &child : children)
    {
        if (!canDeleteDeviceSubtree(child.id, currentBootId))
        {
            return false;
        }
    }

    return true;
}

void DeviceTree::deleteDeviceFromDatabase(int deviceId, const QString &deviceName)
{
    DeviceInfo device = fetchDeviceById(deviceId);

    if (device.id == -1)
    {
        refreshPreservingState();
        return;
    }

    if (!canDeleteDevice(device))
    {
        QMessageBox::warning(this,
                             "Удаление устройства",
                             "Это устройство нельзя удалить: оно является корневым или относится к текущей загрузке.");
        return;
    }

    const QMessageBox::StandardButton answer =
        QMessageBox::question(this,
                              "Удаление устройства",
                              "Удалить устройство \"" + deviceName + "\" и всех его потомков из БД?",
                              QMessageBox::Yes | QMessageBox::No,
                              QMessageBox::No);

    if (answer != QMessageBox::Yes)
    {
        return;
    }

    const std::string currentBootId = getSystemBootId();
    device = fetchDeviceById(deviceId);
    bool deleted = false;
    QString errorMessage;
    if (device.id != -1 && canDeleteDeviceSubtree(deviceId, currentBootId))
    {
        deleted = deleteDeviceRemote(deviceId, &errorMessage);
    }

    if (!deleted)
    {
        QMessageBox::warning(this,
                             "Удаление устройства",
                             errorMessage.isEmpty()
                                 ? "Не удалось удалить устройство. Возможно, оно уже изменилось или снова относится к текущей загрузке."
                                 : errorMessage);
        refreshPreservingState();
        return;
    }

    refreshPreservingState();
}
// Функция для получения времени старта ОС
std::string DeviceTree::getSystemBootId()
{
    const auto response = deviceClient().request({{"command", "boot_id"}});
    if (!response.value("ok", false)) {
        qDebug() << "Failed to load boot_id:" << QString::fromStdString(response.value("message", "unknown daemon error"));
        return "";
    }
    return response.value("boot_id", "");
}

// Проверка, совпадает ли время старта устройства с временем старта ОС
bool DeviceTree::isDeviceBootIdValid(const DeviceInfo &device)
{
    static std::string systemBootId;
    if (systemBootId.empty()) {
        systemBootId = getSystemBootId();
    }

    // Сравниваем boot_id с временем старта системы
    // Или на равенство -1 (для предустановленных устройств)
    return device.boot_id == systemBootId || device.boot_id == "-1";
}

bool DeviceTree::filterActive() const
{
    const QString mode = quickFilterCombo == nullptr
        ? QStringLiteral("all")
        : quickFilterCombo->currentData().toString();
    return !searchEdit->text().trimmed().isEmpty() || mode != "all";
}

bool DeviceTree::itemMatchesFilter(QTreeWidgetItem *item) const
{
    if (item == nullptr || !item->data(0, Qt::UserRole).isValid())
    {
        return false;
    }

    const QString query = searchEdit == nullptr ? QString() : searchEdit->text().trimmed();
    if (!query.isEmpty())
    {
        const QString haystack =
            item->text(0) + "\n" +
            item->text(1) + "\n" +
            item->data(0, RoleSubsystem).toString() + "\n" +
            item->data(0, RoleDevpath).toString() + "\n" +
            item->toolTip(0);
        if (!haystack.contains(query, Qt::CaseInsensitive))
        {
            return false;
        }
    }

    const QString mode = quickFilterCombo == nullptr
        ? QStringLiteral("all")
        : quickFilterCombo->currentData().toString();
    if (mode == "all")
    {
        return true;
    }

    const QString subsystem = item->data(0, RoleSubsystem).toString();
    const QString effectiveControl = item->data(0, RoleEffectiveControl).toString();
    if (mode == "blocked")
    {
        return effectiveControl == "blocked";
    }
    if (mode == "permanent")
    {
        return effectiveControl == "permanent";
    }
    if (mode == "usb")
    {
        return subsystem == "usb";
    }
    if (mode == "block")
    {
        return subsystem == "block";
    }
    if (mode == "history")
    {
        return !item->data(0, RoleBootValid).toBool();
    }

    return true;
}

bool DeviceTree::applyFilterToItem(QTreeWidgetItem *item, int &totalCount, int &visibleCount)
{
    if (item == nullptr)
    {
        return false;
    }

    const bool hasDevice = item->data(0, Qt::UserRole).isValid();
    if (hasDevice)
    {
        ++totalCount;
    }

    const bool selfMatches = !filterActive() || itemMatchesFilter(item);
    bool childMatches = false;
    for (int i = 0; i < item->childCount(); ++i)
    {
        childMatches = applyFilterToItem(item->child(i), totalCount, visibleCount) || childMatches;
    }

    const bool showItem = !filterActive() || selfMatches || childMatches;
    item->setHidden(!showItem);
    if (showItem && hasDevice)
    {
        ++visibleCount;
    }
    if (filterActive() && childMatches)
    {
        item->setExpanded(true);
    }

    return showItem && hasDevice;
}

void DeviceTree::applyDeviceFilter()
{
    if (treeWidget == nullptr)
    {
        return;
    }

    const bool active = filterActive();
    if (active)
    {
        treeWidget->setUpdatesEnabled(false);
        for (int i = 0; i < treeWidget->topLevelItemCount(); ++i)
        {
            expandNodeRecursively(treeWidget->topLevelItem(i));
        }
        treeWidget->setUpdatesEnabled(true);
    }

    int totalCount = 0;
    int visibleCount = 0;
    treeWidget->setUpdatesEnabled(false);
    for (int i = 0; i < treeWidget->topLevelItemCount(); ++i)
    {
        applyFilterToItem(treeWidget->topLevelItem(i), totalCount, visibleCount);
    }
    treeWidget->setUpdatesEnabled(true);

    if (filterStatsLabel != nullptr)
    {
        filterStatsLabel->setText(QString("%1/%2").arg(visibleCount).arg(totalCount));
        filterStatsLabel->setToolTip(active
            ? "Показано устройств после фильтрации"
            : "Загружено устройств в дереве");
    }
}

void DeviceTree::setupTreeItemMetadata(QTreeWidgetItem *item, const DeviceInfo &device)
{
    if (item == nullptr)
    {
        return;
    }

    const std::string effectiveLevel = device.effective_control_level.empty()
        ? device.control_level
        : device.effective_control_level;

    item->setData(0, RoleSubsystem, QString::fromStdString(device.subsystem));
    item->setData(0, RoleDevpath, QString::fromStdString(device.devpath));
    item->setData(0, RoleEffectiveControl, QString::fromStdString(effectiveLevel));
    item->setData(0, RoleConnected, device.connected);
    item->setData(0, RoleBootValid, isDeviceBootIdValid(device));

    QStyle::StandardPixmap icon = QStyle::SP_FileIcon;
    if (device.subsystem == "__computer__")
    {
        icon = QStyle::SP_ComputerIcon;
    }
    else if (device.subsystem == "block")
    {
        icon = QStyle::SP_DriveHDIcon;
    }
    else if (device.subsystem == "usb")
    {
        icon = QStyle::SP_DriveNetIcon;
    }
    else if (device.subsystem == "pci" || device.subsystem == "__pci__")
    {
        icon = QStyle::SP_ComputerIcon;
    }
    else if (device.subsystem == "memory" || device.subsystem == "__memory__")
    {
        icon = QStyle::SP_DriveFDIcon;
    }

    item->setIcon(0, style()->standardIcon(icon));
}

std::string DeviceTree::generateNodeName(const DeviceInfo &device)
{
    std::string device_name = "[" + device.subsystem + "] [" + compactDevpathLabel(device.devpath) + "]";
    if (device.subsystem == "__computer__")
    {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0)
        {
            device_name = "Компьютер [" + std::string(hostname) + "]";
        }
        else
        {
            device_name = "Компьютер";
        }
        return device_name;
    }
    if (device.subsystem == "__cpu__")
    {
        device_name = "Процессоры";
        return device_name;
    }
    if (device.subsystem == "__board__")
    {
        device_name = "Материнские платы";
        return device_name;
    }
    if (device.subsystem == "__memory__")
    {
        device_name = "Оперативная память";
        return device_name;
    }
    if (device.subsystem == "__virtual__")
    {
        device_name = "[Виртуальное устройство] [" + compactDevpathLabel(device.devpath) + "]";
        return device_name;
    }
    if (device.subsystem == "cpu")
    {
        std::string model_name = getDeviceAttribute(device.id, "Model name", "Unknown Model");
        device_name = "Процессор [" + model_name + "]";
        return device_name;
    }
    if (device.subsystem == "board")
    {
        std::string manufacturer = getDeviceAttribute(device.id, "Manufacturer", "Unknown Manufacturer");
        std::string product_name = getDeviceAttribute(device.id, "Product Name", "Unknown Product Name");
        device_name = "Материнская плата [" + manufacturer + "]" + " [" + product_name + "]";
        return device_name;
    }
    if (device.subsystem == "memory")
    {
        std::string manufacturer = getDeviceAttribute(device.id, "Manufacturer", "Unknown Manufacturer");
        std::string size = getDeviceAttribute(device.id, "Size", "Unknown Size");
        std::string locator = getDeviceAttribute(device.id, "Locator", "Unknown Locator");
        std::string serial_number = getDeviceAttribute(device.id, "Serial Number", "Unknown Serial");
        device_name = "ОЗУ [" + manufacturer + "] " + "[" + serial_number + "]" + " [" + size + "] " + "[" + locator + "]";
        return device_name;
    }
    if (device.subsystem == "__udev__")
    {
        device_name = "Устройства ядра";
        return device_name;
    }
    if (device.subsystem == "__pci__")
    {
        device_name = "PCI-мост";
        return device_name;
    }
    /*pci*/
    if (device.subsystem == "pci")
    {
        std::string pci_class = getDeviceAttribute(device.id, "PCI_CLASS", "");
        std::string pci_id = getDeviceAttribute(device.id, "PCI_ID", "");
        std::string pci_class_prepared = normalizePciClassKey(pci_class);
        std::string pci_device_info = localizeDeviceClass("pci", pci_class_prepared);
        device_name = pci_device_info.empty() ? "[PCI] class " + pci_class_prepared : pci_device_info;
        if (!pci_id.empty())
        {
            device_name += " [" + pci_id + "]";
        }
        return device_name;
    }
    if (device.subsystem == "usb")
    {
        std::string type = getDeviceAttribute(device.id, "TYPE", "");
        std::string usb_class_prepared = normalizeUsbTypeKey(type);
        std::string usb_class_info = localizeDeviceClass("usb", usb_class_prepared);
        if (!usb_class_info.empty())
        {
            return usb_class_info;
        }
        return usb_class_prepared.empty() ? "[USB]" : "[USB] class " + usb_class_prepared;
    }
    if (device.subsystem == "block")
    {
        std::string major_digit = getDeviceAttribute(device.id, "MAJOR", "");
        std::string minor_digit = getDeviceAttribute(device.id, "MINOR", "");

        if (major_digit.empty() || minor_digit.empty())
        {
            device_name = "[block] [MAJOR/MINOR отсутствуют]";
            return device_name;
        }

        int major_num = 0;
        int minor_num = 0;

        try
        {
            major_num = std::stoi(major_digit);
            minor_num = std::stoi(minor_digit);
        }
        catch (const std::exception &)
        {
            device_name = "[block] [Некорректные MAJOR/MINOR: " + major_digit + ":" + minor_digit + "]";
            return device_name;
        }

        std::string major;
        std::string minor;

        auto alphaSuffix = [](int index)
        {
            // 0 -> a
            // 1 -> b
            // ...
            // 25 -> z
            // 26 -> aa
            // 27 -> ab
            std::string result;
            index++;

            while (index > 0)
            {
                index--;
                result.insert(result.begin(), char('a' + (index % 26)));
                index /= 26;
            }

            return result;
        };

        auto makeSdName = [&](int disk_index, int partition_num)
        {
            std::string name = "sd" + alphaSuffix(disk_index);

            if (partition_num == 0)
            {
                return std::string("Диск /dev/") + name;
            }

            return std::string("Раздел /dev/") + name + std::to_string(partition_num);
        };

        auto makeHdName = [&](int disk_index, int partition_num)
        {
            std::string name = "hd" + alphaSuffix(disk_index);

            if (partition_num == 0)
            {
                return std::string("Диск /dev/") + name;
            }

            return std::string("Раздел /dev/") + name + std::to_string(partition_num);
        };

        auto makeMmcName = [&](int minor_num)
        {
            // Для MMC обычно:
            // minor = device * 8 + partition
            // 0 -> mmcblk0
            // 1 -> mmcblk0p1
            // 8 -> mmcblk1
            int disk_num = minor_num / 8;
            int partition_num = minor_num % 8;

            std::string name = "mmcblk" + std::to_string(disk_num);

            if (partition_num == 0)
            {
                return std::string("Диск /dev/") + name;
            }

            return std::string("Раздел /dev/") + name + "p" + std::to_string(partition_num);
        };

        auto makeIdeName = [&](int first_disk_index)
        {
            // Для IDE major обычно содержит два диска.
            // minor 0..63   -> первый диск
            // minor 64..127 -> второй диск
            int disk_offset = minor_num / 64;
            int partition_num = minor_num % 64;
            int disk_index = first_disk_index + disk_offset;

            return makeHdName(disk_index, partition_num);
        };

        auto isScsiDiskMajor = [](int major_num)
        {
            return major_num == 8 ||
                   (major_num >= 65 && major_num <= 71) ||
                   (major_num >= 128 && major_num <= 135);
        };

        auto scsiDiskBaseIndex = [](int major_num)
        {
            if (major_num == 8)
            {
                return 0;
            }

            if (major_num >= 65 && major_num <= 71)
            {
                return 16 + (major_num - 65) * 16;
            }

            if (major_num >= 128 && major_num <= 135)
            {
                return 128 + (major_num - 128) * 16;
            }

            return 0;
        };

        if (isScsiDiskMajor(major_num))
        {
            major = "SCSI/SATA/SAS/USB disk";

            // Для sd-дисков:
            // minor = disk * 16 + partition
            int disk_index = scsiDiskBaseIndex(major_num) + minor_num / 16;
            int partition_num = minor_num % 16;

            minor = makeSdName(disk_index, partition_num);
        }
        else if (major_num == 1)
        {
            major = "RAM disk";
            minor = "/dev/ram" + std::to_string(minor_num);
        }
        else if (major_num == 2)
        {
            major = "Floppy disk";
            minor = "/dev/fd" + std::to_string(minor_num);
        }
        else if (major_num == 3)
        {
            major = "IDE disk";
            minor = makeIdeName(0); // hda, hdb
        }
        else if (major_num == 7)
        {
            major = "Loop device";
            minor = "/dev/loop" + std::to_string(minor_num);
        }
        else if (major_num == 9)
        {
            major = "MD RAID device";
            minor = "/dev/md" + std::to_string(minor_num);
        }
        else if (major_num == 11)
        {
            major = "SCSI CD/DVD-ROM";
            minor = "/dev/sr" + std::to_string(minor_num);
        }
        else if (major_num == 22)
        {
            major = "IDE disk";
            minor = makeIdeName(2); // hdc, hdd
        }
        else if (major_num == 33)
        {
            major = "IDE disk";
            minor = makeIdeName(4); // hde, hdf
        }
        else if (major_num == 34)
        {
            major = "IDE disk";
            minor = makeIdeName(6); // hdg, hdh
        }
        else if (major_num == 43)
        {
            major = "Network block device";
            minor = "/dev/nbd" + std::to_string(minor_num);
        }
        else if (major_num == 56)
        {
            major = "IDE disk";
            minor = makeIdeName(8); // hdi, hdj
        }
        else if (major_num == 57)
        {
            major = "IDE disk";
            minor = makeIdeName(10); // hdk, hdl
        }
        else if (major_num == 88)
        {
            major = "IDE disk";
            minor = makeIdeName(12); // hdm, hdn
        }
        else if (major_num == 89)
        {
            major = "IDE disk";
            minor = makeIdeName(14); // hdo, hdp
        }
        else if (major_num == 90)
        {
            major = "IDE disk";
            minor = makeIdeName(16); // hdq, hdr
        }
        else if (major_num == 91)
        {
            major = "IDE disk";
            minor = makeIdeName(18); // hds, hdt
        }
        else if (major_num == 179)
        {
            major = "MMC/SD card";
            minor = makeMmcName(minor_num);
        }
        else if (major_num == 202)
        {
            major = "Xen virtual block device";
            minor = "Xen block minor " + std::to_string(minor_num);
        }
        else if (major_num == 253)
        {
            major = "Device Mapper";
            minor = "/dev/dm-" + std::to_string(minor_num);
        }
        else if (major_num == 259)
        {
            major = "Extended block device";
            minor = "Невозможно надежно определить имя только по MAJOR/MINOR: " + major_digit + ":" + minor_digit;
        }
        else
        {
            major = "Неизвестный block major (" + major_digit + ")";
            minor = "minor " + minor_digit;
        }

        device_name = "[" + major + "] [" + minor + "]";
        return device_name;
    }
    // Заглушка: используем только devpath
    // В будущем можно добавить дополнительную информацию
    return device_name;
}

void DeviceTree::setupControlLevelColumn(QTreeWidgetItem *item, const DeviceInfo &device)
{
    if (item == nullptr)
    {
        return;
    }

    QString text;
    QString tooltip;
    QColor color;
    QStyle::StandardPixmap icon = QStyle::SP_MessageBoxInformation;
    bool emphasize = false;

    const std::string effectiveLevel = device.effective_control_level.empty()
        ? device.control_level
        : device.effective_control_level;

    if (effectiveLevel == "blocked")
    {
        text = "Блок";
        tooltip = "Устройство запрещено политикой";
        color = QColor(180, 44, 44);
        icon = QStyle::SP_DialogCancelButton;
        emphasize = true;
    }
    else if (effectiveLevel == "allowed")
    {
        text = "Разреш.";
        tooltip = "Устройство разрешено политикой";
        color = QColor(38, 128, 72);
        icon = QStyle::SP_DialogApplyButton;
    }
    else if (effectiveLevel == "permanent")
    {
        text = "Пост.";
        tooltip = "Устройство разрешено и должно быть подключено постоянно";
        color = QColor(36, 94, 166);
        icon = QStyle::SP_DialogSaveButton;
        emphasize = true;
    }
    else if (effectiveLevel == "ignored")
    {
        text = "Игнор";
        tooltip = "Устройство не контролируется";
        color = QColor(120, 120, 120);
        icon = QStyle::SP_DialogDiscardButton;
    }
    else
    {
        text = QString::fromStdString(effectiveLevel.empty() ? "unknown" : effectiveLevel);
        tooltip = "Неизвестный уровень контроля";
        color = QColor(120, 120, 120);
    }

    if (!device.control_explicit)
    {
        text += " ↴";
        tooltip += "\nПравило унаследовано";
    }
    else
    {
        tooltip += "\nПравило задано явно";
    }

    if (device.ignore_hierarchy)
    {
        tooltip += "\nДействует для этой идентичности во всей системе";
    }

    item->setText(1, text);
    item->setIcon(1, style()->standardIcon(icon));
    item->setForeground(1, QBrush(color));
    item->setBackground(1, QBrush(color.lighter(185)));
    item->setTextAlignment(1, Qt::AlignCenter);
    item->setToolTip(1,
                     tooltip +
                     "\nassigned control_level: " + QString::fromStdString(device.control_level) +
                     "\neffective control_level: " + QString::fromStdString(effectiveLevel) +
                     "\neffective source: " + QString::fromStdString(device.effective_source));

    QFont font = item->font(1);
    font.setBold(emphasize);
    item->setFont(1, font);
}

// Функция для установки стиля элемента дерева
void DeviceTree::setupTreeItemStyle(QTreeWidgetItem *item, const DeviceInfo &device)
{
    setupControlLevelColumn(item, device);

    // Проверяем, совпадает ли время старта устройства с временем старта ОС
    bool isValid = isDeviceBootIdValid(device);

    if (!isValid)
    {
        // Устанавливаем стиль с зачеркиванием текста
        item->setForeground(0, QBrush(QColor(128, 128, 128))); // Серый цвет

        // Создаем QFont с зачеркиванием
        QFont font = item->font(0);
        font.setStrikeOut(true);
        item->setFont(0, font);

        QString tooltip = item->text(0);
        if (!device.devpath.empty())
        {
            tooltip += "\n" + QString::fromStdString(device.devpath);
        }
        tooltip += "\n\nУстройство зарегистрировано при предыдущем запуске ОС\n";
        tooltip += "boot_id устройства: " + QString::fromStdString(device.boot_id) + "\n";
        tooltip += "Текущий boot_id ОС: " + QString::fromStdString(getSystemBootId());
        item->setToolTip(0, tooltip);
    }
    else
    {
        // Сбрасываем стиль для валидных устройств
        item->setForeground(0, QBrush()); // Сбрасываем цвет
        QFont font = item->font(0);
        font.setStrikeOut(false);
        item->setFont(0, font);
        QString tooltip = item->text(0);
        if (!device.devpath.empty())
        {
            tooltip += "\n" + QString::fromStdString(device.devpath);
        }
        item->setToolTip(0, tooltip);
    }
}

void DeviceTree::collectExpandedDeviceIds(QTreeWidgetItem *item, QSet<int> &expandedIds) const
{
    if (item == nullptr)
    {
        return;
    }

    if (item->data(0, Qt::UserRole).isValid() && item->isExpanded())
    {
        expandedIds.insert(item->data(0, Qt::UserRole).toInt());
    }

    for (int i = 0; i < item->childCount(); ++i)
    {
        collectExpandedDeviceIds(item->child(i), expandedIds);
    }
}

bool DeviceTree::restoreExpandedDeviceIds(QTreeWidgetItem *item, const QSet<int> &expandedIds, int selectedId)
{
    if (item == nullptr || !item->data(0, Qt::UserRole).isValid())
    {
        return false;
    }

    const int deviceId = item->data(0, Qt::UserRole).toInt();
    const bool mustExpand = expandedIds.contains(deviceId);
    bool containsSelection = deviceId == selectedId;

    if (mustExpand)
    {
        ensureChildrenLoaded(item);

        for (int i = 0; i < item->childCount(); ++i)
        {
            containsSelection |= restoreExpandedDeviceIds(item->child(i), expandedIds, selectedId);
        }

        item->setExpanded(true);
    }

    return containsSelection;
}

QTreeWidgetItem* DeviceTree::findItemByDeviceId(QTreeWidgetItem *item, int deviceId) const
{
    if (item == nullptr || deviceId <= 0)
    {
        return nullptr;
    }

    if (item->data(0, Qt::UserRole).isValid() &&
        item->data(0, Qt::UserRole).toInt() == deviceId)
    {
        return item;
    }

    for (int i = 0; i < item->childCount(); ++i)
    {
        QTreeWidgetItem *found = findItemByDeviceId(item->child(i), deviceId);
        if (found != nullptr)
        {
            return found;
        }
    }

    return nullptr;
}

void DeviceTree::refreshPreservingState()
{
    QSet<int> expandedIds;
    for (int i = 0; i < treeWidget->topLevelItemCount(); ++i)
    {
        collectExpandedDeviceIds(treeWidget->topLevelItem(i), expandedIds);
    }

    int selectedId = -1;
    if (treeWidget->currentItem() != nullptr &&
        treeWidget->currentItem()->data(0, Qt::UserRole).isValid())
    {
        selectedId = treeWidget->currentItem()->data(0, Qt::UserRole).toInt();
    }

    const int scrollValue = treeWidget->verticalScrollBar()->value();

    QTreeWidgetItem *selectedItem = nullptr;
    {
        QSignalBlocker blocker(treeWidget);
        Q_UNUSED(blocker);

        loadDeviceTree();

        for (int i = 0; i < treeWidget->topLevelItemCount(); ++i)
        {
            restoreExpandedDeviceIds(treeWidget->topLevelItem(i), expandedIds, selectedId);
        }

        for (int i = 0; i < treeWidget->topLevelItemCount(); ++i)
        {
            selectedItem = findItemByDeviceId(treeWidget->topLevelItem(i), selectedId);
            if (selectedItem != nullptr)
            {
                treeWidget->setCurrentItem(selectedItem);
                break;
            }
        }

        treeWidget->verticalScrollBar()->setValue(scrollValue);
    }

    applyDeviceFilter();

    if (selectedItem != nullptr)
    {
        onItemClicked(selectedItem, 0);
    }
}

void DeviceTree::loadDeviceTree()
{
    treeWidget->clear();
    DeviceInfo rootDevice{};
    rootDevice.id = -1;
    auto response = deviceClient().request({{"command", "device_root"}});
    if (response.value("ok", false) && response.contains("device") && response["device"].is_object())
    {
        fillDeviceFromJson(rootDevice, response["device"]);
    }

    if (rootDevice.id == -1)
    {
        qDebug() << "Root device not found!";
        return;
    }

    // Создаем корневой элемент
    QTreeWidgetItem *rootItem = new QTreeWidgetItem(treeWidget);
    rootItem->setText(0, QString::fromStdString(generateNodeName(rootDevice)));
    rootItem->setData(0, Qt::UserRole, rootDevice.id);
    setupTreeItemMetadata(rootItem, rootDevice);

    // Устанавливаем стиль для корневого элемента
    setupTreeItemStyle(rootItem, rootDevice);

    // Добавляем пустой дочерний элемент для отображения "+"
    QTreeWidgetItem *dummyItem = new QTreeWidgetItem(rootItem);
    dummyItem->setText(0, "Загрузка...");
    treeWidget->addTopLevelItem(rootItem);
    treeWidget->resizeColumnToContents(0);
    if (treeWidget->columnWidth(0) < 520)
    {
        treeWidget->setColumnWidth(0, 520);
    }
    applyDeviceFilter();
}

void DeviceTree::onItemExpanded(QTreeWidgetItem *item)
{
    // Удаляем заглушку "Загрузка..." если она есть
    if (item->childCount() == 1 && item->child(0)->text(0) == "Загрузка...")
    {
        delete item->child(0);

        int deviceId = item->data(0, Qt::UserRole).toInt();
        loadChildDevices(item, deviceId);
    }
}

void DeviceTree::loadChildDevices(QTreeWidgetItem *parentItem, int parentId)
{
    const bool includeDisconnected = chkShowHistory != nullptr && chkShowHistory->isChecked();
    std::vector<DeviceInfo> allChildren = fetchChildDevices(parentId, includeDisconnected);

    for (const auto &child : allChildren)
    {
        QTreeWidgetItem *childItem = new QTreeWidgetItem(parentItem);
        childItem->setText(0, QString::fromStdString(generateNodeName(child)));
        childItem->setData(0, Qt::UserRole, child.id);
        setupTreeItemMetadata(childItem, child);

        // Устанавливаем стиль в зависимости от времени старта устройства
        setupTreeItemStyle(childItem, child);

        // Добавляем заглушку для ленивой загрузки
        QTreeWidgetItem *dummy = new QTreeWidgetItem(childItem);
        dummy->setText(0, "Загрузка...");
    }

    treeWidget->resizeColumnToContents(0);
    if (treeWidget->columnWidth(0) < 520)
    {
        treeWidget->setColumnWidth(0, 520);
    }
    scheduleFilterUpdate();
}

void DeviceTree::ensureChildrenLoaded(QTreeWidgetItem *item)
{
    if (item == nullptr)
    {
        return;
    }

    if (item->childCount() != 1 || item->child(0)->data(0, Qt::UserRole).isValid())
    {
        return;
    }

    delete item->child(0);

    int deviceId = item->data(0, Qt::UserRole).toInt();
    loadChildDevices(item, deviceId);
}

void DeviceTree::expandNodeRecursively(QTreeWidgetItem *item)
{
    if (item == nullptr)
    {
        return;
    }

    ensureChildrenLoaded(item);

    for (int i = 0; i < item->childCount(); ++i)
    {
        expandNodeRecursively(item->child(i));
    }

    item->setExpanded(true);
}

void DeviceTree::expandAllNodes()
{
    treeWidget->setUpdatesEnabled(false);

    for (int i = 0; i < treeWidget->topLevelItemCount(); ++i)
    {
        expandNodeRecursively(treeWidget->topLevelItem(i));
    }

    treeWidget->setUpdatesEnabled(true);
}

void DeviceTree::collapseAllNodes()
{
    treeWidget->collapseAll();
}
