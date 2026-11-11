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
class AnimatedButton : public QPushButton {
    Q_OBJECT
public:
    explicit AnimatedButton(const QString& text, QWidget* parent = nullptr);

    // Доступ к текущим анимированным цветам (для тестирования).
    QColor currentBackgroundColor() const { return currentBackground_; }
    QColor currentBorderColor() const { return currentBorder_; }

protected:
    void enterEvent(QEnterEvent* event) override;
    void leaveEvent(QEvent* event) override;
    void paintEvent(QPaintEvent* event) override;

private:
    QVariantAnimation animation_;
    QColor normalBackground_ = QColor("#244967");
    QColor hoverBackground_ = QColor("#32688e");
    QColor normalBorder_ = QColor("#537692");
    QColor hoverBorder_ = QColor("#8fcfff");
    QColor currentBackground_;
    QColor currentBorder_;
    QColor startBackground_;
    QColor startBorder_;
    QColor targetBackground_;
    QColor targetBorder_;

    void startAnimation(const QColor& targetBg, const QColor& targetBorder);
};