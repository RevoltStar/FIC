#include "IncidentHistoryView.h"
#include "shared/i18n/QLocalizationManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QComboBox>
#include <QLineEdit>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableView>
#include <QHeaderView>
namespace { QString trIR(const char* key) { return QLocalizationManager::getLang(QString("[incident:%1]").arg(key)); } }
IncidentHistoryView::IncidentHistoryView(QWidget* parent) : QWidget(parent) {
    setObjectName("incidentHistory");
    auto* layout = new QVBoxLayout(this);
    warning_ = new QLabel(this); warning_->setObjectName("incidentHistoryWarning");
    warning_->setTextFormat(Qt::PlainText); warning_->setWordWrap(true); layout->addWidget(warning_);
    auto* filters = new QHBoxLayout;
    auto* type = new QComboBox(this); type->setObjectName("incidentEventFilter");
    type->addItem(trIR("all_events"), QString());
    for (const auto token : {"incident_raise", "incident_clear", "incident_persistence_failed", "incident_action_failed",
         "incident_mode_preflight_failed", "incident_mode_registry_failed", "ssh_bridge_degraded"}) type->addItem(token, token);
    filters->addWidget(type);
    auto* severity = new QComboBox(this); severity->setObjectName("incidentSeverityFilter");
    severity->addItem(trIR("all_severities"), QString());
    for (const auto token : {"UNLOCKED", "SOFT", "STANDARD", "HARD", "ISOLATE"}) severity->addItem(token, token);
    filters->addWidget(severity);
    auto* source = new QLineEdit(this); source->setObjectName("incidentSourceFilter"); source->setPlaceholderText(trIR("source_filter"));
    filters->addWidget(source);
    auto* search = new QLineEdit(this); search->setObjectName("incidentSearch"); search->setPlaceholderText(trIR("search"));
    filters->addWidget(search); layout->addLayout(filters);
    model_ = new IncidentAuditModel(this); filter_ = new IncidentAuditFilter(this); filter_->setSourceModel(model_);
    auto* table = new QTableView(this); table->setObjectName("incidentHistoryTable"); table->setModel(filter_);
    table->setSelectionBehavior(QAbstractItemView::SelectRows); table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers); table->setSortingEnabled(true);
    table->horizontalHeader()->setStretchLastSection(true); layout->addWidget(table);
    auto apply = [=] { filter_->setFilters(type->currentData().toString(), severity->currentData().toString(), source->text(), search->text()); };
    connect(type, QOverload<int>::of(&QComboBox::currentIndexChanged), this, apply);
    connect(severity, QOverload<int>::of(&QComboBox::currentIndexChanged), this, apply);
    connect(source, &QLineEdit::textChanged, this, apply); connect(search, &QLineEdit::textChanged, this, apply);
    details_ = new QPlainTextEdit(this); details_->setObjectName("incidentAuditDetails"); details_->setReadOnly(true); layout->addWidget(details_);
    connect(table->selectionModel(), &QItemSelectionModel::currentRowChanged, this, [this](const QModelIndex& selected) {
        const auto* e = model_->eventAt(filter_->mapToSource(selected).row());
        details_->setPlainText(e ? (e->truncated ? trIR("audit_truncated") + "\n" : QString()) + QString::fromUtf8(e->raw) : QString());
    });
    connect(model_, &QAbstractItemModel::modelReset, details_, &QPlainTextEdit::clear);
    refresh_ = new QPushButton(trIR("history_refresh"), this); layout->addWidget(refresh_);
    connect(refresh_, &QPushButton::clicked, this, &IncidentHistoryView::refreshRequested);
    updateSnapshot({});
}
void IncidentHistoryView::setBusy(bool busy) { refresh_->setEnabled(!busy); }
void IncidentHistoryView::updateSnapshot(const IncidentHistorySnapshot& snapshot) {
    retranslate();
    model_->update(snapshot.events, snapshot.generation);
    QString message = trIR("history_scope").arg(snapshot.bootId.isEmpty() ? "UNKNOWN" : snapshot.bootId);
    if (snapshot.acquired.isValid()) message += "\n" + trIR("history_time").arg(snapshot.acquired.toLocalTime().toString(Qt::ISODate));
    else message += "\n" + trIR("history_unavailable");
    if (snapshot.stale) message += "\n" + trIR("history_stale") + "\n" + snapshot.error;
    if (snapshot.hasMore || snapshot.trimmed || snapshot.damaged || snapshot.reloaded) message += "\n" + trIR("history_partial");
    if (snapshot.hasMore) message += "\n" + trIR("history_more");
    if (snapshot.trimmed) message += "\n" + trIR("history_trimmed");
    if (snapshot.damaged) message += "\n" + trIR("history_damaged");
    if (snapshot.reloaded) message += "\n" + trIR("history_reloaded");
    warning_->setStyleSheet(snapshot.stale || snapshot.hasMore || snapshot.trimmed || snapshot.damaged || snapshot.reloaded
        ? "QLabel { color: #503400; background: #fff0bb; padding: 10px; font-weight: bold; }" : QString());
    warning_->setText(message);
}

void IncidentHistoryView::retranslate() {
    findChild<QComboBox*>("incidentEventFilter")->setItemText(0, trIR("all_events"));
    findChild<QComboBox*>("incidentSeverityFilter")->setItemText(0, trIR("all_severities"));
    findChild<QLineEdit*>("incidentSourceFilter")->setPlaceholderText(trIR("source_filter"));
    findChild<QLineEdit*>("incidentSearch")->setPlaceholderText(trIR("search"));
    refresh_->setText(trIR("history_refresh")); model_->retranslate();
}
