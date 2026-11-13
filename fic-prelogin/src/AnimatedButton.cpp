#include "AnimatedButton.h"

#include <QPainter>
#include <QPainterPath>
#include <QEvent>
#include <QEasingCurve>
#include <QtMath>
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
    QFont f = font();
    f.setPixelSize(18);
    setFont(f);

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

void AnimatedButton::setSymbol(Symbol symbol) {
    if (symbol_ == symbol) return;
    symbol_ = symbol;
    update();
}

QSize AnimatedButton::sizeHint() const {
    QSize hint = QPushButton::sizeHint();
    if (symbol_ != Symbol::None) {
        // Иконка + зазор слева от текста.
        hint.rwidth() += 20 + 8;
    }
    hint.rwidth() += 10;
    hint.rheight() = qMax(hint.rheight(), 50);
    return hint;
}

QSize AnimatedButton::minimumSizeHint() const {
    return sizeHint();
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

void AnimatedButton::drawSymbol(QPainter& painter, const QRect& area) const {
    painter.save();
    // Тёмный символ согласован с текстом светлой кнопки.
    QPen pen(QColor("#2c4258"), 1.8);
    pen.setCapStyle(Qt::RoundCap);
    painter.setPen(pen);
    painter.setBrush(Qt::NoBrush);
    const QRectF r(area);
    switch (symbol_) {
        case Symbol::Monitor: {
            // Экран с подставкой.
            painter.drawRoundedRect(r.adjusted(1, 2, -1, -6), 2.5, 2.5);
            painter.drawLine(QPointF(r.center().x(), r.bottom() - 6),
                             QPointF(r.center().x(), r.bottom() - 3));
            painter.drawLine(QPointF(r.center().x() - 5, r.bottom() - 2.5),
                             QPointF(r.center().x() + 5, r.bottom() - 2.5));
            break;
        }
        case Symbol::Restart: {
            // Круговая стрелка: почти полный круг + наконечник.
            const QRectF circle = r.adjusted(2, 2, -2, -2);
            painter.drawArc(circle, 40 * 16, 290 * 16);
            const qreal angle = qDegreesToRadians(40.0 + 290.0);
            const QPointF tip(circle.center().x() + circle.width() / 2 * std::cos(angle),
                              circle.center().y() - circle.height() / 2 * std::sin(angle));
            QPainterPath arrow;
            arrow.moveTo(tip.x() - 4, tip.y() - 3);
            arrow.lineTo(tip.x() + 2, tip.y() - 1);
            arrow.lineTo(tip.x() - 1, tip.y() + 5);
            arrow.closeSubpath();
            painter.setBrush(QColor("#2c4258"));
            painter.drawPath(arrow);
            break;
        }
        case Symbol::Power: {
            // Стандартный символ питания: разомкнутый круг + вертикальная линия.
            const QRectF circle = r.adjusted(2, 3, -2, -2);
            painter.drawArc(circle, -35 * 16, 250 * 16);
            painter.drawLine(QPointF(r.center().x(), r.top() + 1),
                             QPointF(r.center().x(), r.center().y() + 1));
            break;
        }
        case Symbol::None:
            break;
    }
    painter.restore();
}

void AnimatedButton::paintEvent(QPaintEvent* /*event*/) {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QRect r = rect();
    const int radius = 10;

    QColor bg = currentBackground_;
    QColor border = currentBorder_;
    QColor textColor = QColor("#22384c");

    if (!isEnabled()) {
        bg = QColor("#f2f4f7");
        border = QColor("#d4dbe3");
        textColor = QColor("#9aa7b3");
    } else if (isDown()) {
        bg = bg.darker(105);
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

    // Иконка слева от текста (только когда она задана).
    constexpr int symbolSize = 20;
    constexpr int symbolGap = 8;
    QRect textRect = r.adjusted(14, 6, -14, -6);
    if (symbol_ != Symbol::None) {
        const QRect symbolRect(r.left() + 14,
                               r.center().y() - symbolSize / 2,
                               symbolSize, symbolSize);
        drawSymbol(painter, symbolRect);
        textRect.setLeft(symbolRect.right() + symbolGap);
    }

    // Текст.
    painter.setPen(textColor);
    painter.drawText(textRect, Qt::AlignCenter, text());

    // Индикатор фокуса клавиатуры.
    if (hasFocus()) {
        QPen focusPen(QColor("#4d9ae8"), 2);
        painter.setPen(focusPen);
        painter.setBrush(Qt::NoBrush);
        QRect focusRect = r.adjusted(2, 2, -2, -2);
        painter.drawRoundedRect(focusRect, radius, radius);
    }
}