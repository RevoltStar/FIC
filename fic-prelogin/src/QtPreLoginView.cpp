#include "QtPreLoginView.h"
#include "AnimatedButton.h"
#include "PreLoginStepsWidget.h"
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QAbstractButton>
#include <QApplication>
#include <QShortcut>
#include <QScrollArea>
#include <QFrame>
#include <QPainter>
#include <QPainterPath>
#include <QResizeEvent>
#include <map>
#include <iostream>
#include <cstdlib>
#include <string>
namespace fic::prelogin {
namespace {

// Синий щит FIC, отрисованный векторно (без внешних файлов и сети).
class ShieldWidget final : public QWidget {
public:
    explicit ShieldWidget(QWidget* parent = nullptr) : QWidget(parent) {
        setFixedSize(104, 100);
    }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        const QRectF area = QRectF(rect()).adjusted(6, 4, -6, -4);
        QPainterPath shield;
        shield.moveTo(area.left(), area.top());
        shield.cubicTo(area.left() + area.width() * 0.30, area.top() - 6,
                       area.right() - area.width() * 0.30, area.top() - 6,
                       area.right(), area.top());
        shield.lineTo(area.right(), area.top() + area.height() * 0.52);
        shield.cubicTo(area.right(), area.top() + area.height() * 0.78,
                       area.center().x() + area.width() * 0.30, area.bottom() - 4,
                       area.center().x(), area.bottom());
        shield.cubicTo(area.center().x() - area.width() * 0.30, area.bottom() - 4,
                       area.left(), area.top() + area.height() * 0.78,
                       area.left(), area.top() + area.height() * 0.52);
        shield.closeSubpath();
        QLinearGradient body(QPointF(0, area.top()), QPointF(0, area.bottom()));
        body.setColorAt(0, QColor("#2b7cd3"));
        body.setColorAt(1, QColor("#1256a8"));
        painter.setPen(Qt::NoPen);
        painter.setBrush(body);
        painter.drawPath(shield);
        painter.setPen(Qt::white);
        QFont font = this->font();
        font.setPixelSize(26);
        font.setBold(true);
        painter.setFont(font);
        painter.drawText(area.adjusted(0, 0, 0, -8),
                         Qt::AlignHCenter | Qt::AlignVCenter,
                         QStringLiteral("FIC"));
    }
};

// Центральная белая панель со скруглёнными углами и тонкой границей.
// Мягкую тень рисует родитель (QtPreLoginView), панель прозрачна по краям.
class CardWidget final : public QWidget {
public:
    explicit CardWidget(QWidget* parent = nullptr) : QWidget(parent) {
        setObjectName(QStringLiteral("card"));
        setAttribute(Qt::WA_StyledBackground, false);
        setAutoFillBackground(false);
    }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        const QRect r = rect().adjusted(1, 1, -1, -1);
        painter.setPen(QPen(QColor("#cfe0f0"), 1));
        painter.setBrush(QColor("#fdfeff"));
        painter.drawRoundedRect(r, 16, 16);
        painter.setPen(Qt::NoPen);
    }
};

} // namespace
// ============================== Основной вид ================================

QtPreLoginView::QtPreLoginView(std::function<void(char)> action) : action_(std::move(action)) {
    setWindowTitle(QStringLiteral("FIC SECURITY"));
    // Общие правила: сама вьюха рисует фон в paintEvent (кэшированный),
    // диагностические подписи оформлены статическим styleSheet.
    setStyleSheet(QStringLiteral(
        "QLabel{color:#22384c;font-size:16px}"
        "QLabel#title{font-size:29px;font-weight:bold;color:#16324f;}"
        "QLabel#subtitle{font-size:17px;color:#5d7893;}"
        "QLabel#diag{font-size:14px;color:#7d8fa1;}"
        "QLabel#banner{font-size:15px;font-weight:bold;border-radius:10px;padding:10px 14px;}"));

    auto* card = new CardWidget;
    card_ = card;
    // Адаптивные пропорции (приближены к эталону) выставляются в
    // resizeEvent(): ширина ~82% экрана с разумным потолком, высота —
    // не выше доступной. Здесь заданы стартовые значения до первого resize.
    card->setMaximumWidth(1260);
    card->setMaximumHeight(720);
    auto* cardLayout = new QVBoxLayout(card);
    cardLayout->setContentsMargins(34, 24, 34, 20);
    cardLayout->setSpacing(8);

    // Шапка: щит, заголовок, подзаголовок.
    auto* shield = new ShieldWidget;
    cardLayout->addWidget(shield, 0, Qt::AlignHCenter);

    title_ = new QLabel(QStringLiteral("Инициализация системы безопасности"));
    title_->setObjectName(QStringLiteral("title"));
    title_->setWordWrap(true);
    title_->setAlignment(Qt::AlignHCenter);
    cardLayout->addWidget(title_);
    auto* subtitle = new QLabel(QStringLiteral(
        "Пожалуйста, подождите. Выполняется запуск и применение политик FIC."));
    subtitle->setObjectName(QStringLiteral("subtitle"));
    subtitle->setWordWrap(true);
    subtitle->setAlignment(Qt::AlignHCenter);
    cardLayout->addWidget(subtitle);

    auto* separator = new QFrame;
    separator->setFrameShape(QFrame::HLine);
    separator->setStyleSheet(QStringLiteral("color:#e3edf7;"));
    cardLayout->addWidget(separator);

    // Три этапа инициализации (существующие состояния контроллера).
    // Блок этапов прижат к левому краю контента, как на макете.
    steps_ = new PreLoginStepsWidget;
    steps_->setContentsMargins(56, 4, 0, 4);
    cardLayout->addWidget(steps_, 0, Qt::AlignLeft);

    // Заметное предупреждение/ошибка состояния (скрыто по умолчанию).
    // Зазор после этапов поглощает свободную высоту панели (как на макете).
    cardLayout->addStretch(1);
    banner_ = new QLabel;
    banner_->setObjectName(QStringLiteral("banner"));
    banner_->setWordWrap(true);
    banner_->setTextFormat(Qt::PlainText);
    banner_->hide();
    cardLayout->addWidget(banner_);

    // Компактная диагностическая секция (данные IPC — PlainText).
    auto* diagnosticsHost = new QWidget;
    auto* diagnosticsLayout = new QVBoxLayout(diagnosticsHost);
    diagnosticsLayout->setContentsMargins(0, 2, 0, 2);
    diagnosticsLayout->setSpacing(3);
    // Текущее состояние контроллера — первая строка диагностики (крупный
    // заголовок панели остаётся постоянным, как на макете).
    state_ = new QLabel(QStringLiteral("Ожидание демона FIC"));
    state_->setObjectName(QStringLiteral("state"));
    state_->setStyleSheet(QStringLiteral("font-weight:bold;color:#2c4258;"));
    startup_ = new QLabel;
    mode_ = new QLabel;
    detail_ = new QLabel; detail_->setObjectName(QStringLiteral("detail"));
    for (auto* label : {state_, startup_, mode_, detail_}) {
        label->setTextFormat(Qt::PlainText);
        label->setWordWrap(true);
        diagnosticsLayout->addWidget(label);
    }
    // Компактный блок: строки прижаты кверху, свободное место — снизу.
    diagnosticsLayout->addStretch();
    diagnostics_ = new QScrollArea;
    diagnostics_->setWidgetResizable(true);
    diagnostics_->setFrameShape(QFrame::NoFrame);
    diagnostics_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    diagnostics_->setStyleSheet(QStringLiteral(
        "QScrollArea{background:transparent;}"
        "QScrollArea>QWidget>QWidget{background:transparent;}"
        "QScrollBar:vertical{background:transparent;width:8px;}"
        "QScrollBar::handle:vertical{background:#c4d5e6;border-radius:4px;}"
        "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}"));
    diagnostics_->setWidget(diagnosticsHost);
    // Длинная диагностика прокручивается и не выталкивает кнопки за экран:
    // секция сжимается первой (stretch в карточке).
    diagnostics_->setMinimumHeight(56);
    cardLayout->addWidget(diagnostics_, 1);

    auto* separator2 = new QFrame;
    separator2->setFrameShape(QFrame::HLine);
    separator2->setStyleSheet(QStringLiteral("color:#e3edf7;"));
    cardLayout->addWidget(separator2);

    // Кнопки: handoff слева, reboot/poweroff справа (существующие действия).
    auto* buttons = new QHBoxLayout;
    buttons->setSpacing(12);
    handoff_ = new AnimatedButton(QStringLiteral("Перейти к системному DM"));
    handoff_->setObjectName(QStringLiteral("handoff"));
    handoff_->setSymbol(AnimatedButton::Symbol::Monitor);
    handoff_->setFixedHeight(56);
    handoff_->setShortcut(QKeySequence(Qt::ALT | Qt::Key_D));
    connect(handoff_, &AnimatedButton::clicked, this, [this]{request('H');});
    buttons->addWidget(handoff_);
    buttons->addStretch();
    reboot_ = new AnimatedButton(QStringLiteral("Перезагрузить"));
    reboot_->setObjectName(QStringLiteral("reboot"));
    reboot_->setSymbol(AnimatedButton::Symbol::Restart);
    reboot_->setFixedHeight(56);
    poweroff_ = new AnimatedButton(QStringLiteral("Выключить"));
    poweroff_->setObjectName(QStringLiteral("poweroff"));
    poweroff_->setSymbol(AnimatedButton::Symbol::Power);
    poweroff_->setFixedHeight(56);
    buttons->addWidget(reboot_);
    buttons->addWidget(poweroff_);
    cardLayout->addLayout(buttons);
    connect(reboot_, &AnimatedButton::clicked, this, [this]{request('R');});
    connect(poweroff_, &AnimatedButton::clicked, this, [this]{request('P');});

    auto* note = new QLabel(QStringLiteral(
        "Переход не разрешает вход: доступ независимо проверяет PAM. Recovery: Ctrl+Alt+F1."));
    note->setObjectName(QStringLiteral("diag"));
    note->setWordWrap(true);
    note->setAlignment(Qt::AlignHCenter);
    cardLayout->addWidget(note);

    auto* enter = new QShortcut(QKeySequence(Qt::Key_Return), this);
    connect(enter, &QShortcut::activated, handoff_, &AnimatedButton::click);

    // Центрирование панели: по горизонтали и по возможности по вертикали.
    // Stretch-факторы растягивают панель до адаптивного максимума из
    // resizeEvent(), оставляя поля по краям.
    auto* row = new QHBoxLayout;
    row->addStretch();
    row->addWidget(card, 1);
    row->addStretch();
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(20, 16, 20, 16);
    root->addStretch();
    root->addLayout(row, 1);
    root->addStretch();
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
        // Крупный заголовок панели остаётся постоянным; текущее состояние
        // контроллера показывается первой строкой диагностической секции.
        state_->setText(title->second);

        // Визуальная последовательность трёх этапов по существующим
        // состояниям контроллера. Индикатор отражает доставленные факты и
        // не является отдельным security attestation.
        using S = StepState;
        StepState steps[PreLoginStepsWidget::kStepCount] = {
            S::Waiting, S::Waiting, S::Waiting};
        QString bannerText;
        enum class Banner { None, Warning, Error, Info } bannerKind = Banner::None;

        if (state == "WAITING_FOR_DAEMON") {
            // Первый этап ожидает запуска, остальные неактивны.
        } else if (state == "DAEMON_STARTING") {
            steps[0] = S::Active;
        } else if (state == "STARTUP_APPLYING") {
            steps[0] = S::Done;
            steps[1] = S::Active;
        } else if (state == "STARTUP_SUCCEEDED") {
            steps[0] = S::Done;
            steps[1] = S::Done;
            // Третий этап ожидает передачи управления системному DM.
        } else if (state == "STARTUP_FAILED") {
            steps[0] = S::Done;
            steps[1] = S::Failed;
            bannerText = QStringLiteral(
                "Обнаружена ошибка первичного применения политик. Подробности — в диагностике ниже.");
            bannerKind = Banner::Error;
        } else if (state == "DAEMON_DEGRADED") {
            // Состояние защиты не подтверждено: недостоверные зелёные
            // галочки не показываются.
            steps[1] = S::Warning;
            bannerText = QStringLiteral(
                "Состояние защиты не подтверждено. Рекомендуется проверить состояние системы (Recovery: Ctrl+Alt+F1).");
            bannerKind = Banner::Warning;
        } else if (state == "DAEMON_UNAVAILABLE") {
            steps[0] = S::Failed;
            bannerText = QStringLiteral(
                "Не удалось связаться с демоном FIC. Проверьте систему (Recovery: Ctrl+Alt+F1).");
            bannerKind = Banner::Error;
        } else if (state == "HANDOFF") {
            steps[0] = S::Done;
            steps[1] = S::Done;
            // Передача управления в процессе; окончательное завершение
            // не помечается до фактического успешного handoff.
            steps[2] = S::Active;
        } else if (state == "POWER_ACTION") {
            // Завершение работы не выдаётся за успешную инициализацию:
            // этапы не помечаются выполненными.
            bannerText = QStringLiteral("Выполняется завершение работы…");
            bannerKind = Banner::Info;
        }
        steps_->setStates(steps);

        switch (bannerKind) {
            case Banner::Warning:
                banner_->setStyleSheet(QStringLiteral(
                    "QLabel#banner{background:#fff4dd;color:#7c5200;border:1px solid #f0d9a8;}"));
                banner_->show();
                break;
            case Banner::Error:
                banner_->setStyleSheet(QStringLiteral(
                    "QLabel#banner{background:#fdecec;color:#8f1f24;border:1px solid #f2c4c6;}"));
                banner_->show();
                break;
            case Banner::Info:
                banner_->setStyleSheet(QStringLiteral(
                    "QLabel#banner{background:#e8f2fd;color:#1c4a7c;border:1px solid #c6ddf3;}"));
                banner_->show();
                break;
            case Banner::None:
                banner_->hide();
                break;
        }
        banner_->setText(bannerText);

        auto string=[&](const char* key){return QString::fromStdString(value.at(key).get<std::string>());};
        detail_->setText(string("detail"));
        startup_->setText(string("startup"));
        mode_->setText(QStringLiteral("Режим: %1    Incident severity: %2").arg(string("mode"),string("severity")));
        return true;
    } catch(const nlohmann::json::exception&) {return false;}
}

void QtPreLoginView::rebuildBackground() {
    // Кэшированный статичный фон: светлый голубой градиент и несколько
    // плавных волн. Перерисовывается только при изменении размера окна.
    const QSize current = size();
    if (current.isEmpty()) return;
    background_ = QPixmap(current);
    QPainter painter(&background_);
    painter.setRenderHint(QPainter::Antialiasing, true);
    QLinearGradient wash(QPoint(0, 0), QPoint(current.width(), current.height()));
    wash.setColorAt(0, QColor("#f2f8fd"));
    wash.setColorAt(1, QColor("#dbe9f7"));
    painter.fillRect(rect(), wash);

    const qreal w = current.width();
    const qreal h = current.height();
    auto wave = [&](qreal topRatio, qreal thickness, QColor color) {
        QPainterPath path;
        const qreal top = h * topRatio;
        path.moveTo(0, top + thickness);
        path.cubicTo(w * 0.28, top - thickness * 1.6,
                     w * 0.62, top + thickness * 2.2,
                     w, top - thickness * 0.4);
        path.lineTo(w, h + 40);
        path.lineTo(0, h + 40);
        path.closeSubpath();
        painter.setPen(Qt::NoPen);
        painter.setBrush(color);
        painter.drawPath(path);
    };
    wave(0.18, h * 0.10, QColor(255, 255, 255, 110));
    wave(0.38, h * 0.14, QColor(190, 216, 240, 90));
    wave(0.62, h * 0.18, QColor(167, 200, 231, 80));
    wave(0.84, h * 0.22, QColor(140, 181, 220, 70));
}

void QtPreLoginView::paintEvent(QPaintEvent* /*event*/) {
    // Фон закэширован в QPixmap: постоянной полной перерисовки волн нет.
    if (!background_.isNull()) {
        QPainter painter(this);
        painter.drawPixmap(0, 0, background_);
    }
    // Мягкая голубовато-серая тень вокруг панели: расширяющиеся
    // полупрозрачные контуры с растущей плотностью к панели и смещением
    // вниз (заметна по краям и снизу). Внутренняя часть скрывается
    // дочерней панелью, содержимое не перекрывается.
    if (auto* card = findChild<QWidget*>(QStringLiteral("card"))) {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        const QRectF base(card->geometry());
        for (int layer = 12; layer >= 1; --layer) {
            const qreal pad = layer * 1.7;
            const qreal drop = layer * 2.2;
            painter.setPen(Qt::NoPen);
            painter.setBrush(QColor(96, 130, 165, 15 - layer));
            painter.drawRoundedRect(
                QRectF(base).adjusted(-pad, -pad * 0.55, pad, drop),
                16 + pad, 16 + pad);
        }
    }
}

void QtPreLoginView::resizeEvent(QResizeEvent* event) {
    QWidget::resizeEvent(event);
    if (card_) {
        // Пропорции центральной панели приближены к эталону: на 1536×1024
        // панель занимает ~82% ширины; на 1920×1080 остаётся широкой
        // центральной панелью (потолок), на малых разрешениях не опускается
        // ниже минимума, при котором кнопки остаются читаемыми, и никогда
        // не выходит за видимую область.
        const int width = event->size().width();
        const int height = event->size().height();
        int desiredWidth = qMax(qRound(width * 0.82), 744);
        desiredWidth = qMin(desiredWidth, width - 40);
        desiredWidth = qMin(desiredWidth, 1400);
        card_->setMaximumWidth(qMax(320, desiredWidth));
        card_->setMaximumHeight(qMin(780, qMax(560, height - 36)));
    }
    rebuildBackground();
}

int QtPreLoginView::stepState(int index) const {
    return static_cast<int>(steps_->state(index));
}

bool QtPreLoginView::warningBannerVisible() const {
    return banner_->isVisible();
}

QString QtPreLoginView::warningBannerText() const {
    return banner_->text();
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
