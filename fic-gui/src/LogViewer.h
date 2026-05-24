// LogViewer.h
#ifndef LOGVIEWER_H
#define LOGVIEWER_H

#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSplitter>
#include <QTableView>
#include <QTextBrowser>
#include <QWidget>
#include <QTextStream>

#include "LogFilterProxyModel.h"
#include "LogModel.h"
#include "LogService.h"

class LogViewer : public QWidget
{
    Q_OBJECT

public:
    explicit LogViewer(QWidget *parent = nullptr);
    ~LogViewer();

    void initializeUI(
        QComboBox *comboLogLevel,
        QComboBox *comboLogType,
        QLineEdit *lineEditSearch,
        QCheckBox *checkAutoScroll,
        QCheckBox *checkWordWrap,
        QCheckBox *checkPause,
        QPushButton *btnRefresh,
        QPushButton *btnClear,
        QPushButton *btnExport,
        QTextBrowser *textBrowserPlaceholder,
        QLabel *labelLogCount,
        QLabel *labelLogSize,
        QLabel *labelLastUpdate
    );

    void loadLogs();
    void clearLogs();
    void exportLogs();
    void refreshLogs();
    void applyFilters();

public slots:
    void onAutoRefresh();
    void onFilterChanged();

private slots:
    void onFullReloaded(const QVector<LogRecord> &records);
    void onRecordsAppended(const QVector<LogRecord> &records);
    void onCategoriesChanged(const QStringList &categories);
    void onLastUpdateChanged(const QDateTime &timestamp);
    void onSelectionChanged();

private:
    void setupConnections();
    void replacePlaceholderWidget(QTextBrowser *placeholder);
    void setupTableView();
    void populateStaticControls();
    void updateStatusBar();
    void updateDetailsPane();
    void applyWordWrapSetting();
    QString categoryLabel(const QString &category) const;
    QString categoryValueAt(int index) const;
    logLevel currentMinimumLevel() const;
    qint64 filteredByteSize() const;
    LogRecord selectedRecord(bool *ok = nullptr) const;

    QPointer<QTableView> tableView_;
    QPointer<QPlainTextEdit> detailsView_;
    QPointer<QSplitter> logSplitter_;

    QComboBox *comboLogLevel_ = nullptr;
    QComboBox *comboLogType_ = nullptr;
    QLineEdit *lineEditSearch_ = nullptr;
    QCheckBox *checkAutoScroll_ = nullptr;
    QCheckBox *checkWordWrap_ = nullptr;
    QCheckBox *checkPause_ = nullptr;
    QPushButton *btnRefresh_ = nullptr;
    QPushButton *btnClear_ = nullptr;
    QPushButton *btnExport_ = nullptr;
    QLabel *labelLogCount_ = nullptr;
    QLabel *labelLogSize_ = nullptr;
    QLabel *labelLastUpdate_ = nullptr;

    LogService *service_ = nullptr;
    LogModel *model_ = nullptr;
    LogFilterProxyModel *proxyModel_ = nullptr;

    bool uiInitialized_ = false;
    QDateTime lastUpdate_;
};

#endif // LOGVIEWER_H
