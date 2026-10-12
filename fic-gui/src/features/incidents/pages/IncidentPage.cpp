#include "IncidentPage.h"
#include "shared/i18n/QLocalizationManager.h"
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QComboBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QTimer>
namespace {
QString trIR(const char* key) { return QLocalizationManager::getLang(QString("[incident:%1]").arg(key)); }
QLabel* label(QWidget* parent, const char* name) {
    auto* l = new QLabel(parent); l->setObjectName(name); l->setTextFormat(Qt::PlainText);
    l->setWordWrap(true); l->setTextInteractionFlags(Qt::TextSelectableByMouse); return l;
}
}
IncidentPage::IncidentPage(QWidget* parent, IncidentService::RequestFunction transport) : QWidget(parent) {
    setObjectName("incidentPage");
    auto* layout = new QVBoxLayout(this);
    warning_ = label(this, "incidentWarning"); layout->addWidget(warning_);
    summary_ = label(this, "incidentSummary"); layout->addWidget(summary_);
    details_ = new QPlainTextEdit(this); details_->setObjectName("incidentDetails"); details_->setReadOnly(true);
    layout->addWidget(details_);
    auto* actions = new QHBoxLayout;
    refresh_ = new QPushButton(trIR("refresh"), this); actions->addWidget(refresh_);
    severity_ = new QComboBox(this); severity_->addItems({"SOFT", "STANDARD", "HARD", "ISOLATE"}); actions->addWidget(severity_);
    raise_ = new QPushButton(trIR("raise"), this); actions->addWidget(raise_);
    clear_ = new QPushButton(trIR("clear"), this); actions->addWidget(clear_);
    layout->addLayout(actions);
    operation_ = label(this, "incidentOperation"); layout->addWidget(operation_);
    connect(refresh_, &QPushButton::clicked, this, &IncidentPage::refresh);
    connect(raise_, &QPushButton::clicked, this, [this] {
        QMessageBox box(QMessageBox::Warning, trIR("title"), trIR("confirm_raise").arg(severity_->currentText()), QMessageBox::Yes | QMessageBox::Cancel, this);
        box.setTextFormat(Qt::PlainText); box.setDefaultButton(QMessageBox::Cancel);
        if (box.exec() == QMessageBox::Yes) executeConfirmedAction("incident_raise", severity_->currentText());
    });
    connect(clear_, &QPushButton::clicked, this, [this] {
        QMessageBox box(QMessageBox::Warning, trIR("title"), trIR("confirm_clear"), QMessageBox::Yes | QMessageBox::Cancel, this);
        box.setTextFormat(Qt::PlainText); box.setDefaultButton(QMessageBox::Cancel);
        if (box.exec() == QMessageBox::Yes) executeConfirmedAction("incident_clear");
    });
    qRegisterMetaType<IncidentService::Reply>();
    auto* worker = new IncidentWorker(std::move(transport)); worker->moveToThread(&thread_);
    connect(&thread_, &QThread::finished, worker, &QObject::deleteLater);
    connect(this, &IncidentPage::request, worker, &IncidentWorker::run, Qt::QueuedConnection);
    connect(worker, &IncidentWorker::actionFinished, this, [this](IncidentService::Reply r) {
        operation_->setText(trIR(r.failure == IncidentService::Failure::None ? "action_ok" : "action_failed") + "\n" + r.message);
    });
    connect(worker, &IncidentWorker::statusFinished, this, [this](quint64 seq, IncidentService::Reply r) {
        if (seq != sequence_) return;
        busy_ = false;
        snapshot_.accept(seq, r.status, r.status ? QString() : r.message, r.reachable);
        render(); emit updated();
    });
    thread_.start();
    auto* timer = new QTimer(this); timer->setInterval(5000);
    connect(timer, &QTimer::timeout, this, &IncidentPage::refresh); timer->start();
    render(); QTimer::singleShot(0, this, &IncidentPage::refresh);
}
IncidentPage::~IncidentPage() { thread_.quit(); thread_.wait(); }
void IncidentPage::refresh() { submit(); }
void IncidentPage::executeConfirmedAction(const QString& command, const QString& severity) { submit(command, severity); }
void IncidentPage::submit(const QString& command, const QString& severity) {
    if (busy_) return;
    busy_ = true; render(); emit request(++sequence_, command, severity);
}
void IncidentPage::render() {
    refresh_->setEnabled(!busy_);
    raise_->setEnabled(!busy_ && snapshot_.reachable); clear_->setEnabled(!busy_ && snapshot_.reachable);
    severity_->setEnabled(!busy_ && snapshot_.reachable);
    warning_->setStyleSheet("QLabel { background: #fff0bb; color: #503400; padding: 12px; font-weight: bold; }");
    if (!snapshot_.status) {
        warning_->setText(trIR("unavailable") + "\n" + snapshot_.error);
        summary_->setText(trIR("unknown")); details_->clear(); return;
    }
    const auto& s = *snapshot_.status;
    const QString time = snapshot_.acquired.toLocalTime().toString(Qt::ISODate);
    warning_->setVisible(snapshot_.stale);
    warning_->setText(trIR("stale").arg(time) + "\n" + snapshot_.error);
    const bool unproven = !s.stateProven || s.persistentBroken || !s.modeProven || s.runtime == "degraded";
    QString color = s.normal() ? "#d8f2df" : (s.severity == "HARD" || s.severity == "ISOLATE") ? "#ffd4d4" : unproven ? "#fff0bb" : "#e5e5e5";
    if (snapshot_.stale) color = "#fff0bb";
    summary_->setStyleSheet("QLabel { color: #202020; padding: 12px; background: " + color + "; }");
    summary_->setText(trIR("summary").arg(s.severity, s.mode, s.runtime,
        trIR(s.stateProven && !s.persistentBroken ? "proven" : "unproven"), s.provenance,
        trIR(s.modeProven ? "proven" : "unproven"), time) + "\n" + trIR(snapshot_.stale ? "connection_error" : "connected"));
    const auto flag = [&](bool value) { return trIR(value ? "reported_yes" : "reported_no"); };
    details_->setPlainText(trIR("mode_legend") + "\n\n" + trIR("persistent_broken") + ": " + trIR(s.persistentBroken ? "yes" : "no") + "\n\n" + trIR("containment") + "\n" + trIR("pam") + ": " + flag(s.pam) + "\n" +
        trIR("sessions") + ": " + flag(s.sessions) + "\n" + trIR("user_runtime") + ": " + flag(s.userRuntime) + "\n" +
        trIR("network") + ": " + flag(s.network) + "\n\n" + trIR("diagnostics") + "\n" + s.modeDiagnostic + "\n" + s.detail);
}
