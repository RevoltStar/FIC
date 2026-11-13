#pragma once

#include <QPushButton>
#include <QVariantAnimation>
#include <QColor>
#include <QEvent>
#include <QEnterEvent>
#include <QPaintEvent>

// Кнопка с плавной сменой цвета фона и границы при наведении указателя.
// Не меняет геометрию, не вызывает setStyleSheet на каждом кадре,
// анимирует ограниченное число цветовых параметров с локальной перерисовкой.
// Работает исключительно в GUI-потоке Qt через QVariantAnimation.
//
// Светлая тема инициализации: белый фон, тонкая голубовато-серая рамка,
// тёмный текст, опциональная векторная иконка слева от текста (рисуется тем
// же paintEvent, без внешних файлов и без сетевых ресурсов).
class AnimatedButton : public QPushButton {
    Q_OBJECT
public:
    // Небольшой векторный символ слева от текста.
    enum class Symbol { None, Monitor, Restart, Power };

    explicit AnimatedButton(const QString& text, QWidget* parent = nullptr);

    void setSymbol(Symbol symbol);

    // Доступ к текущим анимированным цветам (для тестирования).
    QColor currentBackgroundColor() const { return currentBackground_; }
    QColor currentBorderColor() const { return currentBorder_; }

    // Размер учитывает векторную иконку и не сжимается ниже читаемого
    // минимума: текст кнопки никогда не обрезается layout'ом.
    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

protected:
    void enterEvent(QEnterEvent* event) override;
    void leaveEvent(QEvent* event) override;
    void paintEvent(QPaintEvent* event) override;

private:
    QVariantAnimation animation_;
    QColor normalBackground_ = QColor("#ffffff");
    QColor hoverBackground_ = QColor("#eef6ff");
    QColor normalBorder_ = QColor("#c7d6e6");
    QColor hoverBorder_ = QColor("#79b0e8");
    QColor currentBackground_;
    QColor currentBorder_;
    QColor startBackground_;
    QColor startBorder_;
    QColor targetBackground_;
    QColor targetBorder_;
    Symbol symbol_ = Symbol::None;

    void startAnimation(const QColor& targetBg, const QColor& targetBorder);
    void drawSymbol(QPainter& painter, const QRectF& area,
                    const QColor& symbolColor) const;
};