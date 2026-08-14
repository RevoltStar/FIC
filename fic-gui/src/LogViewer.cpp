// LogViewer.cpp
#include "LogViewer.h"

#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextOption>
#include <QVBoxLayout>

namespace {
QString levelLabel(logLevel level)
{
    return logLevelToString(level);
}
}

LogViewer::LogViewer(QWidget *parent)
    : QWidget(parent)
    , service_(new LogService(this))
    , model_(new LogModel(this))
    , proxyModel_(new LogFilterProxyModel(this))
{
    proxyModel_->setSourceModel(model_);
    setupUi();
    setupTableView();
    populateStaticControls();
    setupConnections();
    uiInitialized_ = true;
    loadLogs();
    service_->start();
}

LogViewer::~LogViewer()
{
    if (service_ != nullptr) {
        service_->stop();
    }
}

void LogViewer::setupUi()
{
    auto* mainLayout = new QVBoxLayout(this);
    auto* filters = new QHBoxLayout();
    comboLogLevel_ = new QComboBox(this);
    comboLogLevel_->addItems({QString::fromUtf8(u8"Все уровни"), "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"});
    comboLogType_ = new QComboBox(this);
    lineEditSearch_ = new QLineEdit(this);
    lineEditSearch_->setPlaceholderText(QString::fromUtf8(u8"Поиск"));
    filters->addWidget(new QLabel(QString::fromUtf8(u8"Уровень:"), this));
    filters->addWidget(comboLogLevel_);
    filters->addWidget(new QLabel(QString::fromUtf8(u8"Категория:"), this));
    filters->addWidget(comboLogType_);
    filters->addWidget(lineEditSearch_, 1);
    mainLayout->addLayout(filters);

    auto* actions = new QHBoxLayout();
    checkAutoScroll_ = new QCheckBox(QString::fromUtf8(u8"Автопрокрутка"), this);
    checkWordWrap_ = new QCheckBox(QString::fromUtf8(u8"Перенос строк"), this);
    checkPause_ = new QCheckBox(QString::fromUtf8(u8"Пауза"), this);
    btnRefresh_ = new QPushButton(QString::fromUtf8(u8"Обновить"), this);
    btnClear_ = new QPushButton(QString::fromUtf8(u8"Очистить вид"), this);
    btnExport_ = new QPushButton(QString::fromUtf8(u8"Экспорт"), this);
    actions->addWidget(checkAutoScroll_);
    actions->addWidget(checkWordWrap_);
    actions->addWidget(checkPause_);
    actions->addStretch();
    actions->addWidget(btnRefresh_);
    actions->addWidget(btnClear_);
    actions->addWidget(btnExport_);
    mainLayout->addLayout(actions);

    logSplitter_ = new QSplitter(Qt::Vertical, this);
    tableView_ = new QTableView(logSplitter_);
    detailsView_ = new QPlainTextEdit(logSplitter_);
    detailsView_->setReadOnly(true);
    detailsView_->setPlaceholderText(QString::fromUtf8(u8"Выберите запись, чтобы увидеть детали"));
    logSplitter_->addWidget(tableView_);
    logSplitter_->addWidget(detailsView_);
    logSplitter_->setStretchFactor(0, 4);
    logSplitter_->setStretchFactor(1, 1);
    mainLayout->addWidget(logSplitter_, 1);

    auto* status = new QHBoxLayout();
    labelLogCount_ = new QLabel(this);
    labelLogSize_ = new QLabel(this);
    labelLastUpdate_ = new QLabel(this);
    status->addWidget(labelLogCount_);
    status->addWidget(labelLogSize_);
    status->addStretch();
    status->addWidget(labelLastUpdate_);
    mainLayout->addLayout(status);
}

void LogViewer::loadLogs()
{
    if (!uiInitialized_) {
        return;
    }

    service_->reloadAll();
}

void LogViewer::clearLogs()
{
    if (!uiInitialized_) {
        return;
    }

    model_->clear();
    updateDetailsPane();
    updateStatusBar();
}

void LogViewer::exportLogs()
{
    if (!uiInitialized_) {
        return;
    }

    const QString defaultName = QStringLiteral("fic_logs_%1.txt")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd_hh-mm-ss")));

    const QString fileName = QFileDialog::getSaveFileName(
        this,
        QString::fromUtf8(u8"Экспорт логов"),
        defaultName,
        QStringLiteral("Text Files (*.txt);;All Files (*)"));

    if (fileName.isEmpty()) {
        return;
    }

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this,
                              QString::fromUtf8(u8"Ошибка"),
                              QString::fromUtf8(u8"Не удалось сохранить файл экспорта."));
        return;
    }

    QTextStream stream(&file);
    for (int row = 0; row < proxyModel_->rowCount(); ++row) {
        const QModelIndex sourceIndex = proxyModel_->mapToSource(proxyModel_->index(row, 0));
        const LogRecord &record = model_->recordAt(sourceIndex.row());
        stream << QStringLiteral("[%1] [%2] [%3] %4 (%5)\n")
                  .arg(record.timestampText,
                       levelLabel(record.level),
                       record.category,
                       record.message,
                       record.sourceFile);
    }

    file.close();
}

void LogViewer::refreshLogs()
{
    if (!uiInitialized_) {
        return;
    }

    service_->reloadAll();
}

void LogViewer::applyFilters()
{
    if (!uiInitialized_) {
        return;
    }

    proxyModel_->setMinimumLevel(currentMinimumLevel());
    proxyModel_->setCategoryFilter(categoryValueAt(comboLogType_->currentIndex()));
    proxyModel_->setSearchText(lineEditSearch_->text());

    if (tableView_ != nullptr) {
        tableView_->sortByColumn(LogModel::TimestampColumn, Qt::AscendingOrder);
    }

    applyWordWrapSetting();
    updateStatusBar();
    updateDetailsPane();
}

void LogViewer::onAutoRefresh()
{
    if (!uiInitialized_ || checkPause_->isChecked()) {
        return;
    }

    service_->refreshIncremental();
}

void LogViewer::onFilterChanged()
{
    applyFilters();
}

void LogViewer::onFullReloaded(const QVector<LogRecord> &records)
{
    model_->setRecords(records);
    if (tableView_ != nullptr) {
        tableView_->scrollToBottom();
    }
    applyFilters();
}

void LogViewer::onRecordsAppended(const QVector<LogRecord> &records)
{
    if (checkPause_->isChecked()) {
        return;
    }

    const bool shouldStickToBottom = tableView_ != nullptr && checkAutoScroll_->isChecked();
    model_->appendRecords(records);
    applyFilters();

    if (shouldStickToBottom && tableView_ != nullptr) {
        tableView_->scrollToBottom();
    }
}

void LogViewer::onCategoriesChanged(const QStringList &categories)
{
    if (!uiInitialized_) {
        return;
    }

    const QString previousCategory = categoryValueAt(comboLogType_->currentIndex());

    comboLogType_->blockSignals(true);
    comboLogType_->clear();
    comboLogType_->addItem(QString::fromUtf8(u8"Все категории"), QStringLiteral("all"));
    for (const QString &category : categories) {
        comboLogType_->addItem(categoryLabel(category), category);
    }

    int index = comboLogType_->findData(previousCategory);
    if (index < 0) {
        index = 0;
    }
    comboLogType_->setCurrentIndex(index);
    comboLogType_->blockSignals(false);

    applyFilters();
}

void LogViewer::onLastUpdateChanged(const QDateTime &timestamp)
{
    lastUpdate_ = timestamp;
    updateStatusBar();
}

void LogViewer::onSelectionChanged()
{
    updateDetailsPane();
}

void LogViewer::setupConnections()
{
    connect(comboLogLevel_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &LogViewer::onFilterChanged);
    connect(comboLogType_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &LogViewer::onFilterChanged);
    connect(lineEditSearch_, &QLineEdit::textChanged,
            this, &LogViewer::onFilterChanged);
    connect(checkWordWrap_, &QCheckBox::toggled, this, [this](bool) {
        applyWordWrapSetting();
    });
    connect(checkPause_, &QCheckBox::toggled, this, [this](bool paused) {
        if (paused) {
            service_->stop();
        } else {
            service_->start();
            service_->refreshIncremental();
        }
    });
    connect(btnRefresh_, &QPushButton::clicked, this, &LogViewer::refreshLogs);
    connect(btnClear_, &QPushButton::clicked, this, &LogViewer::clearLogs);
    connect(btnExport_, &QPushButton::clicked, this, &LogViewer::exportLogs);

    connect(service_, &LogService::fullReloaded,
            this, &LogViewer::onFullReloaded);
    connect(service_, &LogService::recordsAppended,
            this, &LogViewer::onRecordsAppended);
    connect(service_, &LogService::categoriesChanged,
            this, &LogViewer::onCategoriesChanged);
    connect(service_, &LogService::lastUpdateChanged,
            this, &LogViewer::onLastUpdateChanged);

    if (tableView_ != nullptr && tableView_->selectionModel() != nullptr) {
        connect(tableView_->selectionModel(), &QItemSelectionModel::selectionChanged,
                this, &LogViewer::onSelectionChanged);
    }
}

void LogViewer::setupTableView()
{
    if (tableView_ == nullptr) {
        return;
    }

    tableView_->setModel(proxyModel_);
    tableView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView_->setSelectionMode(QAbstractItemView::SingleSelection);
    tableView_->setAlternatingRowColors(true);
    tableView_->setSortingEnabled(true);
    tableView_->sortByColumn(LogModel::TimestampColumn, Qt::AscendingOrder);
    tableView_->verticalHeader()->setVisible(false);
    tableView_->horizontalHeader()->setStretchLastSection(false);
    tableView_->horizontalHeader()->setSectionResizeMode(LogModel::TimestampColumn, QHeaderView::ResizeToContents);
    tableView_->horizontalHeader()->setSectionResizeMode(LogModel::LevelColumn, QHeaderView::ResizeToContents);
    tableView_->horizontalHeader()->setSectionResizeMode(LogModel::CategoryColumn, QHeaderView::ResizeToContents);
    tableView_->horizontalHeader()->setSectionResizeMode(LogModel::MessageColumn, QHeaderView::Stretch);
    tableView_->horizontalHeader()->setSectionResizeMode(LogModel::SourceColumn, QHeaderView::ResizeToContents);
}

void LogViewer::populateStaticControls()
{
    comboLogLevel_->blockSignals(true);
    comboLogLevel_->setCurrentIndex(0);
    comboLogLevel_->blockSignals(false);

    comboLogType_->clear();
    comboLogType_->addItem(QString::fromUtf8(u8"Все категории"), QStringLiteral("all"));
    comboLogType_->setCurrentIndex(0);

    checkAutoScroll_->setChecked(true);
    checkWordWrap_->setChecked(false);
    checkPause_->setChecked(false);

    applyWordWrapSetting();
    updateStatusBar();
}

void LogViewer::updateStatusBar()
{
    if (!uiInitialized_) {
        return;
    }

    const int visibleCount = proxyModel_->rowCount();
    labelLogCount_->setText(QString::fromUtf8(u8"Сообщений: %1").arg(visibleCount));
    labelLogSize_->setText(QString::fromUtf8(u8"Размер: %1 KB").arg(filteredByteSize() / 1024.0, 0, 'f', 1));

    if (lastUpdate_.isValid()) {
        labelLastUpdate_->setText(
            QString::fromUtf8(u8"Обновлено: %1").arg(lastUpdate_.toString(QStringLiteral("hh:mm:ss"))));
    } else {
        labelLastUpdate_->setText(QString::fromUtf8(u8"Обновлено: никогда"));
    }
}

void LogViewer::updateDetailsPane()
{
    if (detailsView_ == nullptr) {
        return;
    }

    bool ok = false;
    const LogRecord record = selectedRecord(&ok);
    if (!ok) {
        detailsView_->clear();
        return;
    }

    const QString details = QString::fromUtf8(u8"Время: %1\nУровень: %2\nКатегория: %3\nИсточник: %4\n\n%5")
        .arg(record.timestampText,
             levelLabel(record.level),
             categoryLabel(record.category),
             record.sourceFile,
             record.message);
    detailsView_->setPlainText(details);
}

void LogViewer::applyWordWrapSetting()
{
    if (tableView_ == nullptr || detailsView_ == nullptr) {
        return;
    }

    const bool wrapEnabled = checkWordWrap_ != nullptr && checkWordWrap_->isChecked();
    tableView_->setWordWrap(wrapEnabled);
    detailsView_->setWordWrapMode(wrapEnabled ? QTextOption::WrapAtWordBoundaryOrAnywhere
                                              : QTextOption::NoWrap);

    if (wrapEnabled) {
        tableView_->resizeRowsToContents();
    } else {
        tableView_->verticalHeader()->setDefaultSectionSize(fontMetrics().height() + 10);
    }
}

QString LogViewer::categoryLabel(const QString &category) const
{
    if (category == QStringLiteral("db")) {
        return QString::fromUtf8(u8"База данных");
    }
    if (category == QStringLiteral("devices")) {
        return QString::fromUtf8(u8"Устройства");
    }
    if (category == QStringLiteral("daemon")) {
        return QString::fromUtf8(u8"Демон");
    }
    if (category == QStringLiteral("unclassified")) {
        return QString::fromUtf8(u8"Неклассифицированные");
    }
    if (category == QStringLiteral("all")) {
        return QString::fromUtf8(u8"Все категории");
    }

    return category;
}

QString LogViewer::categoryValueAt(int index) const
{
    if (comboLogType_ == nullptr || index < 0) {
        return QStringLiteral("all");
    }

    return comboLogType_->itemData(index).toString();
}

logLevel LogViewer::currentMinimumLevel() const
{
    if (comboLogLevel_ == nullptr) {
        return logLevel::TRACE;
    }

    switch (comboLogLevel_->currentIndex()) {
    case 0:
    case 1:
        return logLevel::TRACE;
    case 2:
        return logLevel::DEBUG;
    case 3:
        return logLevel::INFO;
    case 4:
        return logLevel::WARN;
    case 5:
        return logLevel::ERROR;
    case 6:
        return logLevel::FATAL;
    default:
        return logLevel::TRACE;
    }
}

qint64 LogViewer::filteredByteSize() const
{
    qint64 total = 0;
    for (int row = 0; row < proxyModel_->rowCount(); ++row) {
        total += proxyModel_->index(row, 0).data(LogModel::ByteSizeRole).toLongLong();
    }
    return total;
}

LogRecord LogViewer::selectedRecord(bool *ok) const
{
    if (ok != nullptr) {
        *ok = false;
    }

    if (tableView_ == nullptr || tableView_->selectionModel() == nullptr) {
        return {};
    }

    const QModelIndex proxyIndex = tableView_->selectionModel()->currentIndex();
    if (!proxyIndex.isValid()) {
        return {};
    }

    const QModelIndex sourceIndex = proxyModel_->mapToSource(proxyIndex);
    if (!sourceIndex.isValid()) {
        return {};
    }

    if (ok != nullptr) {
        *ok = true;
    }
    return model_->recordAt(sourceIndex.row());
}
