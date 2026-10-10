#include "QtPreLoginView.h"
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QAbstractButton>
#include <QApplication>
#include <QShortcut>
#include <QScrollArea>
#include <map>
namespace fic::prelogin {
QtPreLoginView::QtPreLoginView(std::function<void(char)> action) : action_(std::move(action)) {
    setWindowTitle(QStringLiteral("FIC SECURITY"));
    setStyleSheet(QStringLiteral("QWidget{background:#111b2b;color:#e7edf5;font-size:22px} QPushButton{background:#244967;border:1px solid #537692;border-radius:8px;padding:18px} QPushButton:focus{border:3px solid #8fcfff} QLabel#brand{font-size:38px;font-weight:bold;color:#8fcfff}"));
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(48,32,48,32);
    layout->setSpacing(12);
    auto* summary = new QWidget;
    auto* summaryLayout = new QVBoxLayout(summary);
    summaryLayout->setContentsMargins(12,12,12,12);
    summaryLayout->addStretch();
    auto* brand = new QLabel(QStringLiteral("FIC SECURITY")); brand->setObjectName("brand");
    summaryLayout->addWidget(brand);
    summaryLayout->addWidget(new QLabel(QStringLiteral("Инициализация защиты ОС")));
    state_ = new QLabel(QStringLiteral("Ожидание демона FIC")); state_->setObjectName("state");
    startup_ = new QLabel; mode_ = new QLabel; detail_ = new QLabel;
    detail_->setObjectName("detail");
    for (auto* label : {state_,startup_,mode_,detail_}) {
        label->setTextFormat(Qt::PlainText); label->setWordWrap(true); summaryLayout->addWidget(label);
    }
    summaryLayout->addStretch();
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true); scroll->setWidget(summary);
    layout->addWidget(scroll, 1); // Long diagnostics scroll; actions stay visible.
    handoff_ = new QPushButton(QStringLiteral("Перейти к системному DM")); handoff_->setObjectName("handoff");
    handoff_->setFixedHeight(64);
    handoff_->setShortcut(QKeySequence(Qt::ALT | Qt::Key_D));
    connect(handoff_, &QPushButton::clicked, this, [this]{request('H');});
    layout->addWidget(handoff_);
    auto* enter = new QShortcut(QKeySequence(Qt::Key_Return), this);
    connect(enter, &QShortcut::activated, handoff_, &QPushButton::click);
    auto* power = new QHBoxLayout;
    reboot_ = new QPushButton(QStringLiteral("Перезагрузить")); reboot_->setObjectName("reboot");
    poweroff_ = new QPushButton(QStringLiteral("Выключить")); poweroff_->setObjectName("poweroff");
    reboot_->setFixedHeight(60); poweroff_->setFixedHeight(60);
    power->addWidget(reboot_); power->addWidget(poweroff_); layout->addLayout(power);
    connect(reboot_, &QPushButton::clicked, this, [this]{request('R');});
    connect(poweroff_, &QPushButton::clicked, this, [this]{request('P');});
    auto* note = new QLabel(QStringLiteral("Переход не разрешает вход: доступ независимо проверяет PAM. Recovery: Ctrl+Alt+F1."));
    note->setStyleSheet(QStringLiteral("font-size:16px"));
    note->setWordWrap(true); layout->addWidget(note);
    handoff_->setFocus();
}
bool QtPreLoginView::display(const nlohmann::json& value) {
    try {
        if (!value.is_object() || value.size()!=5) return false;
        for (const auto key : {"state","detail","mode","severity","startup"})
            if (!value.at(key).is_string() || value.at(key).get_ref<const std::string&>().size()>4096) return false;
        const auto state=value.at("state").get<std::string>();
        const std::map<std::string,QString> titles={
            {"WAITING_FOR_DAEMON",QStringLiteral("Ожидание демона FIC")},
            {"DAEMON_STARTING",QStringLiteral("Демон FIC запускается")},
            {"STARTUP_APPLYING",QStringLiteral("Первичное применение политик")},
            {"STARTUP_SUCCEEDED",QStringLiteral("Первичное применение завершено успешно")},
            {"STARTUP_FAILED",QStringLiteral("Ошибка первичного применения политик")},
            {"DAEMON_DEGRADED",QStringLiteral("Защита не подтверждена (DEGRADED)")},
            {"DAEMON_UNAVAILABLE",QStringLiteral("Не удалось получить состояние демона FIC")},
            {"HANDOFF",QStringLiteral("Передача управления системному DM")},
            {"POWER_ACTION",QStringLiteral("Завершение работы")}};
        const auto title=titles.find(state); if(title==titles.end()) return false;
        state_->setText(title->second);
        auto string=[&](const char* key){return QString::fromStdString(value.at(key).get<std::string>());};
        detail_->setText(string("detail"));
        startup_->setText(string("startup"));
        mode_->setText(QStringLiteral("Режим: %1    Incident severity: %2").arg(string("mode"),string("severity")));
        return true;
    } catch(const nlohmann::json::exception&) {return false;}
}
void QtPreLoginView::request(char action) {
    if(pending_) return;
    if(action!='H') {
        QMessageBox confirmation(QMessageBox::Question,QStringLiteral("Подтверждение"),
            action=='R'?QStringLiteral("Перезагрузить компьютер?"):QStringLiteral("Выключить компьютер?"),
            QMessageBox::Yes|QMessageBox::No,this);
        confirmation.button(QMessageBox::Yes)->setText(QStringLiteral("Да"));
        confirmation.button(QMessageBox::No)->setText(QStringLiteral("Нет"));
        confirmation.setDefaultButton(QMessageBox::No);
        if(confirmation.exec()!=QMessageBox::Yes) return;
    }
    pending_=true;
    for(auto* button:{handoff_,reboot_,poweroff_}) button->setEnabled(false);
    action_(action);
}
}
