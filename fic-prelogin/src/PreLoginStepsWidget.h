#pragma once

#include <QWidget>
#include <QTimer>
#include <vector>

namespace fic::prelogin {

// Состояние одного этапа инициализации. Отображает ФАКТЫ, доставленные
// существующим контроллером; не создаёт новых подтверждений безопасности.
enum class StepState {
    Waiting,   // Серый контурный круг — этап ещё не начат.
    Active,    // Синий вращающийся индикатор — этап выполняется.
    Done,      // Зелёный круг с белой галочкой — этап завершён.
    Failed,    // Красный индикатор — этап завершился ошибкой.
    Warning    // Оранжевый «!» — состояние не подтверждено (без ложного успеха).
};

// Три этапа инициализации FIC (Model: состояние → этапы маппятся в
// QtPreLoginView::display). Перерисовка ограничена этим виджетом; анимация —
// лёгкий QTimer в основном GUI-потоке, останавливается, когда активных
// этапов нет (никакой постоянной полной перерисовки экрана).
class PreLoginStepsWidget final : public QWidget {
    Q_OBJECT
public:
    static constexpr int kStepCount = 3;
    explicit PreLoginStepsWidget(QWidget* parent = nullptr);

    void setStates(const StepState (&states)[kStepCount]);
    StepState state(int index) const { return states_.at(static_cast<std::size_t>(index)); }
    bool anyActive() const;

    // Подписи этапов. Индексы фиксированы: 0 — демон, 1 — политики,
    // 2 — передача DM.
    static QString stepTitle(int index);

    QSize minimumSizeHint() const override;
    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    void updateAnimation();
    void drawIndicator(QPainter& painter, const QRectF& area,
                       StepState state) const;

    std::vector<StepState> states_{StepState::Waiting, StepState::Waiting,
                                   StepState::Waiting};
    QTimer animationTimer_;
    int spinnerPhase_ = 0;
};

} // namespace fic::prelogin