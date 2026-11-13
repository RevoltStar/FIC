#include "PreLoginStepsWidget.h"

#include <QPainter>
#include <QPainterPath>
#include <QtMath>
#include <algorithm>

namespace fic::prelogin {
namespace {

constexpr int kIndicatorSize = 26;
constexpr int kRowSpacing = 14;
constexpr int kTitlePixelSize = 19;
constexpr int kCaptionPixelSize = 15;

// Цветовая палитра светлой темы (согласована с центральной панелью).
const QColor kDoneGreen("#2eb872");
const QColor kActiveBlue("#3b82f6");
const QColor kFailedRed("#e5484d");
const QColor kWarnAmber("#f5a623");
const QColor kWaitingGray("#b8c4d0");
const QColor kTitleInk("#22384c");
const QColor kCaptionInk("#8296ab");

QString activeCaption(int index) {
    switch (index) {
        case 0: return QStringLiteral("Установка связи с демоном FIC…");
        case 1: return QStringLiteral("Проверка и применение настроек безопасности…");
        case 2: return QStringLiteral("Передача управления системному DM…");
    }
    return {};
}

} // namespace

PreLoginStepsWidget::PreLoginStepsWidget(QWidget* parent) : QWidget(parent) {
    animationTimer_.setInterval(70);
    connect(&animationTimer_, &QTimer::timeout, this, [this] {
        ++spinnerPhase_;
        // Лёгкая перерисовка только этого виджета, не всего экрана.
        update();
    });
}

QString PreLoginStepsWidget::stepTitle(int index) {
    switch (index) {
        case 0: return QStringLiteral("Запуск демона FIC");
        case 1: return QStringLiteral("Первичное применение политик");
        case 2: return QStringLiteral("Передача управления системному DM");
    }
    return {};
}

void PreLoginStepsWidget::setStates(const StepState (&states)[kStepCount]) {
    bool changed = false;
    for (int i = 0; i < kStepCount; ++i) {
        if (states_[static_cast<std::size_t>(i)] != states[i]) {
            states_[static_cast<std::size_t>(i)] = states[i];
            changed = true;
        }
    }
    if (!changed) return;
    updateAnimation();
    update();
}

bool PreLoginStepsWidget::anyActive() const {
    return std::any_of(states_.begin(), states_.end(),
                       [](StepState s) { return s == StepState::Active; });
}

void PreLoginStepsWidget::updateAnimation() {
    if (anyActive()) {
        if (!animationTimer_.isActive()) animationTimer_.start();
    } else if (animationTimer_.isActive()) {
        animationTimer_.stop();
    }
}

QSize PreLoginStepsWidget::minimumSizeHint() const {
    return {380, kStepCount * (kIndicatorSize + kRowSpacing) + kRowSpacing};
}

QSize PreLoginStepsWidget::sizeHint() const {
    return {520, kStepCount * (kIndicatorSize + kRowSpacing) + kRowSpacing};
}

void PreLoginStepsWidget::paintEvent(QPaintEvent* /*event*/) {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    QFont title = font();
    title.setPixelSize(kTitlePixelSize);
    title.setBold(true);
    QFont caption = font();
    caption.setPixelSize(kCaptionPixelSize);

    QFontMetrics titleMetrics(title);
    QFontMetrics captionMetrics(caption);

    int y = 0;
    for (int i = 0; i < kStepCount; ++i) {
        const StepState state = states_.at(static_cast<std::size_t>(i));
        const QRectF indicator(0, y, kIndicatorSize, kIndicatorSize);
        drawIndicator(painter, indicator, state);

        const qreal textLeft = kIndicatorSize + 16;
        const QRectF titleRect(textLeft, y - 2, width() - textLeft,
                               titleMetrics.height());
        painter.setFont(title);
        painter.setPen(kTitleInk);
        painter.drawText(titleRect, Qt::AlignLeft | Qt::AlignVCenter,
                         stepTitle(i));

        if (state == StepState::Active) {
            const QRectF captionRect(textLeft, titleRect.bottom() + 2,
                                     width() - textLeft,
                                     captionMetrics.height());
            painter.setFont(caption);
            painter.setPen(kCaptionInk);
            painter.drawText(captionRect, Qt::AlignLeft | Qt::AlignVCenter,
                             activeCaption(i));
            y += captionMetrics.height();
        }
        y += kIndicatorSize + kRowSpacing;
    }
}

void PreLoginStepsWidget::drawIndicator(QPainter& painter, const QRectF& area,
                                        StepState state) const {
    switch (state) {
        case StepState::Done: {
            // Зелёный круг с белой галочкой.
            painter.setPen(Qt::NoPen);
            painter.setBrush(kDoneGreen);
            painter.drawEllipse(area);
            QPen check(Qt::white, 2.6);
            check.setCapStyle(Qt::RoundCap);
            check.setJoinStyle(Qt::RoundJoin);
            painter.setPen(check);
            const QPointF c = area.center();
            QPainterPath path;
            path.moveTo(c.x() - 6, c.y());
            path.lineTo(c.x() - 1.5, c.y() + 4.5);
            path.lineTo(c.x() + 6, c.y() - 4.5);
            painter.drawPath(path);
            break;
        }
        case StepState::Failed: {
            // Красный круг с белым крестом.
            painter.setPen(Qt::NoPen);
            painter.setBrush(kFailedRed);
            painter.drawEllipse(area);
            QPen cross(Qt::white, 2.6);
            cross.setCapStyle(Qt::RoundCap);
            painter.setPen(cross);
            const QPointF c = area.center();
            const qreal d = 5;
            painter.drawLine(QPointF(c.x() - d, c.y() - d),
                             QPointF(c.x() + d, c.y() + d));
            painter.drawLine(QPointF(c.x() + d, c.y() - d),
                             QPointF(c.x() - d, c.y() + d));
            break;
        }
        case StepState::Warning: {
            // Оранжевый круг с «!» — состояние не подтверждено.
            painter.setPen(Qt::NoPen);
            painter.setBrush(kWarnAmber);
            painter.drawEllipse(area);
            painter.setPen(QPen(Qt::white, 2.2));
            QFont warn = font();
            warn.setPixelSize(17);
            warn.setBold(true);
            painter.setFont(warn);
            painter.drawText(area, Qt::AlignCenter, QStringLiteral("!"));
            break;
        }
        case StepState::Active: {
            // Синий вращающийся сегментный индикатор (8 сегментов).
            constexpr int kSegments = 8;
            const QPointF c = area.center();
            const qreal radius = area.width() / 2 - 2;
            for (int segment = 0; segment < kSegments; ++segment) {
                const qreal alpha = 60 + 195 * segment / (kSegments - 1);
                QColor color = kActiveBlue;
                color.setAlpha(static_cast<int>(alpha));
                QPen pen(color, 3.2);
                pen.setCapStyle(Qt::RoundCap);
                painter.setPen(pen);
                painter.setBrush(Qt::NoBrush);
                const qreal startAngle =
                    (spinnerPhase_ * 45 + segment * 45) * 16;
                const QRectF circle(c.x() - radius, c.y() - radius,
                                    radius * 2, radius * 2);
                painter.drawArc(circle, static_cast<int>(-startAngle),
                                14 * 16);
            }
            break;
        }
        case StepState::Waiting: {
            // Серый контурный круг.
            QPen pen(kWaitingGray, 2);
            painter.setPen(pen);
            painter.setBrush(Qt::NoBrush);
            painter.drawEllipse(area.adjusted(2, 2, -2, -2));
            break;
        }
    }
}

} // namespace fic::prelogin