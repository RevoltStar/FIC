#pragma once
#include <QWidget>
#include <QPixmap>
#include <functional>
#include <nlohmann/json.hpp>
class QLabel;
class QScrollArea;
class AnimatedButton;
namespace fic::prelogin { class PreLoginStepsWidget; }
namespace fic::prelogin {
// Local broker-to-view rendering data. No policy or authentication authority.
class QtPreLoginView final : public QWidget {
public:
    explicit QtPreLoginView(std::function<void(char)> action);
    bool display(const nlohmann::json& value);

    // Доступ к этапам для тестов (без экспорта внутренних виджетов).
    // Индексы: 0 — демон, 1 — политики, 2 — передача DM.
    int stepState(int index) const;
    bool warningBannerVisible() const;
    QString warningBannerText() const;

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;

private:
    void request(char action);
    void rebuildBackground();

    std::function<void(char)> action_;
    QLabel *title_, *state_, *detail_, *mode_, *startup_, *banner_;
    QScrollArea* diagnostics_;
    PreLoginStepsWidget* steps_;
    AnimatedButton *handoff_, *reboot_, *poweroff_;
    QWidget* card_ = nullptr;
    QPixmap background_;
    bool pending_ = false;
};
}
