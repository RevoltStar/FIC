#include "AnimatedButton.h"

#include <QPainter>
#include <QEvent>
#include <QEasingCurve>

namespace {

QColor lerpColor(const QColor& a, const QColor& b, qreal t) {
    return QColor(
        a.red() + (b.red() - a.red()) * t,
        a.green() + (b.green() - a.green()) * t,
        a.blue() + (b.blue() - a.blue()) * t,
        a.alpha() + (b.alpha() - a.alpha()) * t
    );
}

} // namespace

AnimatedButton::AnimatedButton(const QString& text, QWidget* parent)
    : QPushButton(text, parent)
    , currentBackground_(normalBackground_)
    , currentBorder_(normalBorder_)
{
    setCursor(Qt::PointingHandCursor);
    setFont(QFont(font().family(), 22));

    animation_.setDuration(160);
    animation_.setEasingCurve(QEasingCurve::OutCubic);

    connect(&animation_, &QVariantAnimation::valueChanged,
        this, [this](const QVariant& value) {
            qreal progress = value.toReal();
            currentBackground_ = lerpColor(startBackground_, targetBackground_, progress);
            currentBorder_ = lerpColor(startBorder_, targetBorder_, progress);
            update();
        });

    connect(&animation_, &QVariantAnimation::finished,
        this, [this]() {
            currentBackground_ = targetBackground_;
            currentBorder_ = targetBorder_;
            update();
        });
}

void AnimatedButton::enterEvent(QEnterEvent* /*event*/) {
    if (!isEnabled()) return;
    startAnimation(hoverBackground_, hoverBorder_);
}

void AnimatedButton::leaveEvent(QEvent* /*event*/) {
    if (!isEnabled()) return;
    startAnimation(normalBackground_, normalBorder_);
}

void AnimatedButton::startAnimation(const QColor& targetBg, const QColor& targetBorder) {
    startBackground_ = currentBackground_;
    startBorder_ = currentBorder_;
    targetBackground_ = targetBg;
    targetBorder_ = targetBorder;
    animation_.stop();
    animation_.setStartValue(0.0);
    animation_.setEndValue(1.0);
    animation_.start();
}

void AnimatedButton::paintEvent(QPaintEvent* /*event*/) {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QRect r = rect();
    const int radius = 8;

    QColor bg = currentBackground_;
    QColor border = currentBorder_;
    QColor textColor = QColor("#e7edf5");

    if (!isEnabled()) {
        bg = QColor("#555555");
        border = QColor("#777777");
        textColor = QColor("#aaaaaa");
    } else if (isDown()) {
        bg = bg.darker(125);
    }

    // Фон кнопки.
    painter.setBrush(bg);
    painter.setPen(Qt::NoPen);
    painter.drawRoundedRect(r, radius, radius);

    // Граница кнопки (рисуем внутри, чтобы не наезжать на фон).
    QRect borderRect = r.adjusted(0, 0, -1, -1);
    painter.setPen(QPen(border, 1));
    painter.setBrush(Qt::NoBrush);
    painter.drawRoundedRect(borderRect, radius, radius);

    // Текст с отступами, как в исходном стиле (padding: 18px).
    painter.setPen(textColor);
    QRect textRect = r.adjusted(18, 12, -18, -12);
    painter.drawText(textRect, Qt::AlignCenter, text());

    // Индикатор фокуса клавиатуры.
    if (hasFocus()) {
        QPen focusPen(QColor("#8fcfff"), 3);
        painter.setPen(focusPen);
        painter.setBrush(Qt::NoBrush);
        QRect focusRect = r.adjusted(2, 2, -2, -2);
        painter.drawRoundedRect(focusRect, radius, radius);
    }
}