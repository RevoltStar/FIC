#include "features/devices/widgets/DeviceAttributeList.h"
#include <QDebug>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QVBoxLayout>
#include <fic/ipc/FicIpcClient.h>

DeviceAttributeList::DeviceAttributeList(QWidget *parent)
    : QWidget(parent)
{
    setupUI();
}

DeviceAttributeList::~DeviceAttributeList()
{

}

void DeviceAttributeList::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    QHBoxLayout *filterLayout = new QHBoxLayout();
    filterEdit = new QLineEdit(this);
    filterEdit->setPlaceholderText("Поиск в параметрах");
    countLabel = new QLabel(this);
    countLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    filterLayout->addWidget(filterEdit, 1);
    filterLayout->addWidget(countLabel);

    // Дерево атрибутов
    treeWidget = new QTreeWidget(this);
    treeWidget->setHeaderLabels({"Параметр", "Значение"});
    treeWidget->setColumnCount(2);
    treeWidget->setAlternatingRowColors(true);
    treeWidget->setRootIsDecorated(false);
    treeWidget->setSortingEnabled(true);
    treeWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    treeWidget->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    treeWidget->setTextElideMode(Qt::ElideNone);

    // Настройка размеров столбцов
    treeWidget->header()->setStretchLastSection(false);
    treeWidget->header()->setSectionResizeMode(0, QHeaderView::Interactive);
    treeWidget->header()->setSectionResizeMode(1, QHeaderView::Interactive);
    treeWidget->setColumnWidth(0, 180);
    treeWidget->setColumnWidth(1, 520);

    connect(filterEdit, &QLineEdit::textChanged,
            this, &DeviceAttributeList::applyFilter);

    mainLayout->addLayout(filterLayout);
    mainLayout->addWidget(treeWidget);

    setLayout(mainLayout);
}


void DeviceAttributeList::clear()
{
    currentAttributes.clear();
    treeWidget->clear();
    countLabel->clear();
}

void DeviceAttributeList::showDeviceAttributes(int deviceId)
{
    clear();

    std::map<std::string, std::string> attributes;
    auto response = fic::ipc::Client(fic::ipc::Endpoint::DeviceDaemon).request({
        {"command", "device_attributes"},
        {"device_id", deviceId}
    });
    if (!response.value("ok", false)) {
        qDebug() << "Failed to load device attributes:" << QString::fromStdString(response.value("message", "unknown daemon error"));
        populateTree(attributes);
        emit attributesUpdated(deviceId, 0);
        return;
    }

    if (response.contains("attributes") && response["attributes"].is_object()) {
        for (auto it = response["attributes"].begin(); it != response["attributes"].end(); ++it) {
            if (it.value().is_string()) {
                attributes[it.key()] = it.value().get<std::string>();
            }
        }
    }

    populateTree(attributes);

    emit attributesUpdated(deviceId, attributes.size());
}

void DeviceAttributeList::showAttributes(const std::map<std::string, std::string>& attributes)
{
    clear();
    populateTree(attributes);
    emit attributesUpdated(-1, attributes.size()); // -1 означает, что deviceId неизвестен
}

void DeviceAttributeList::populateTree(const std::map<std::string, std::string>& attributes)
{
    currentAttributes = attributes;
    if (attributes.empty()) {
        QTreeWidgetItem *emptyItem = new QTreeWidgetItem(treeWidget);
        emptyItem->setText(0, "Атрибуты отсутствуют");
        emptyItem->setText(1, "");
        emptyItem->setFlags(emptyItem->flags() & ~Qt::ItemIsSelectable);
        countLabel->setText("0");
        return;
    }

    // Сортировка ключей для более красивого отображения
    QMap<QString, QString> sortedAttributes;
    for (const auto& [key, value] : attributes) {
        sortedAttributes[QString::fromStdString(key)] = QString::fromStdString(value);
    }

    // Добавляем атрибуты в дерево
    for (auto it = sortedAttributes.begin(); it != sortedAttributes.end(); ++it) {
        QTreeWidgetItem *item = new QTreeWidgetItem(treeWidget);
        item->setText(0, it.key());
        item->setText(1, it.value());
        item->setToolTip(0, it.key());
        item->setToolTip(1, it.value());

        // Делаем значения редактируемыми (если нужно)
        // item->setFlags(item->flags() | Qt::ItemIsEditable);
    }

    // Сортируем по имени параметра
    treeWidget->sortItems(0, Qt::AscendingOrder);
    treeWidget->resizeColumnToContents(0);
    if (treeWidget->columnWidth(0) < 180) {
        treeWidget->setColumnWidth(0, 180);
    }
    treeWidget->resizeColumnToContents(1);
    if (treeWidget->columnWidth(1) < 520) {
        treeWidget->setColumnWidth(1, 520);
    }
    applyFilter();
}

void DeviceAttributeList::applyFilter()
{
    const QString query = filterEdit == nullptr ? QString() : filterEdit->text().trimmed();
    int visibleCount = 0;
    const int totalCount = treeWidget->topLevelItemCount();

    for (int i = 0; i < treeWidget->topLevelItemCount(); ++i) {
        QTreeWidgetItem *item = treeWidget->topLevelItem(i);
        const QString haystack = item->text(0) + "\n" + item->text(1);
        const bool visible = query.isEmpty() || haystack.contains(query, Qt::CaseInsensitive);
        item->setHidden(!visible);
        if (visible) {
            ++visibleCount;
        }
    }

    if (countLabel != nullptr) {
        countLabel->setText(QString("%1/%2").arg(visibleCount).arg(totalCount));
    }
}
