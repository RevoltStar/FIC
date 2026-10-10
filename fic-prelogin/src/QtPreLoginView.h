#pragma once
#include <QWidget>
#include <functional>
#include <nlohmann/json.hpp>
class QLabel;
class QPushButton;
namespace fic::prelogin {
// Local broker-to-view rendering data. No policy or authentication authority.
class QtPreLoginView final : public QWidget {
public:
    explicit QtPreLoginView(std::function<void(char)> action);
    bool display(const nlohmann::json& value);
private:
    void request(char action);
    std::function<void(char)> action_;
    QLabel *state_, *detail_, *mode_, *startup_;
    QPushButton *handoff_, *reboot_, *poweroff_;
    bool pending_ = false;
};
}
