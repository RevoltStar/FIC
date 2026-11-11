#include "QtPreLoginView.h"
#include "AnimatedButton.h"
#include <QApplication>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QAbstractButton>
#include <QTimer>
#include <QTime>
#include <QEvent>
#include <stdexcept>
#include <iostream>
using namespace fic::prelogin;

static void waitMs(int ms) {
    QTime die = QTime::currentTime().addMSecs(ms);
    while (QTime::currentTime() < die) QApplication::processEvents();
}

void require(bool ok, const char* detail) { if (!ok) throw std::runtime_error(detail); }
int main(int argc,char** argv){
 QApplication app(argc,argv);
 for(const auto state:{"WAITING_FOR_DAEMON","DAEMON_STARTING","STARTUP_APPLYING","STARTUP_SUCCEEDED","STARTUP_FAILED","DAEMON_DEGRADED","DAEMON_UNAVAILABLE"}){
  int actions=0;QtPreLoginView view([&](char action){require(action=='H',"wrong handoff action");++actions;});
  auto status=nlohmann::json{{"state",state},{"detail","<img src='file:///etc/shadow'>"},{"mode","ACTIVE"},{"severity","ISOLATE"},{"startup","first apply failed"}};
  require(view.display(status),"valid status rejected");
  view.resize(800,600);view.show();app.processEvents();
  status["detail"]=std::string(4096,'x');require(view.display(status),"bounded long diagnostic rejected");
  app.processEvents();
  auto* button=view.findChild<QPushButton*>("handoff");
  require(view.rect().contains(button->geometry()),"long diagnostic hid handoff button");
  require(view.findChild<QLabel*>("detail")->textFormat()==Qt::PlainText,"rich text injected");
  auto* handoff=view.findChild<QPushButton*>("handoff");require(handoff->isEnabled(),"manual handoff unavailable");
  handoff->click();handoff->click();require(actions==1,"duplicate handoff action");
  status["extra"]=true;require(!view.display(status),"unbounded schema accepted");
 }
 for(const bool confirm:{false,true}){
  int actions=0;QtPreLoginView view([&](char action){require(action=='R',"wrong power action");++actions;});
  view.show();QTimer::singleShot(0,[&]{auto* box=qobject_cast<QMessageBox*>(QApplication::activeModalWidget());require(box,"missing power confirmation");box->button(confirm?QMessageBox::Yes:QMessageBox::No)->click();});
  view.findChild<QPushButton*>("reboot")->click();require(actions==(confirm?1:0),"power confirmation bypassed");
 }
// --- Новые проверки анимации наведения ---
    {
        QtPreLoginView view([](char) {});
        view.show();
        app.processEvents();

        auto* handoff = view.findChild<AnimatedButton*>("handoff");
        auto* reboot = view.findChild<AnimatedButton*>("reboot");
        auto* poweroff = view.findChild<AnimatedButton*>("poweroff");
        require(handoff, "handoff AnimatedButton missing");
        require(reboot, "reboot AnimatedButton missing");
        require(poweroff, "poweroff AnimatedButton missing");

        require(handoff->currentBackgroundColor() == QColor("#244967"), "wrong initial bg");
        require(handoff->currentBorderColor() == QColor("#537692"), "wrong initial border");

        QEvent enter(QEvent::Enter);
        QApplication::sendEvent(handoff, &enter);
        waitMs(60);
        require(handoff->currentBackgroundColor() != QColor("#244967"), "hover did not change bg color");
        require(handoff->currentBorderColor() != QColor("#537692"), "hover did not change border color");

        QEvent leave(QEvent::Leave);
        QApplication::sendEvent(handoff, &leave);
        waitMs(200);
        require(handoff->currentBackgroundColor() == QColor("#244967"), "leave did not restore bg color");
        require(handoff->currentBorderColor() == QColor("#537692"), "leave did not restore border color");

        QApplication::sendEvent(handoff, &enter);
        QApplication::sendEvent(handoff, &leave);
        QApplication::sendEvent(handoff, &enter);
        waitMs(60);
        require(handoff->currentBackgroundColor() != QColor("#244967"), "fast re-hover did not change color");
        QApplication::sendEvent(handoff, &leave);
        waitMs(200);
        require(handoff->currentBackgroundColor() == QColor("#244967"), "fast leave did not restore color");

        handoff->setEnabled(false);
        QApplication::sendEvent(handoff, &enter);
        waitMs(60);
        require(handoff->currentBackgroundColor() == QColor("#244967"), "disabled button reacted to hover");
        require(handoff->currentBorderColor() == QColor("#537692"), "disabled button changed border on hover");

        handoff->setEnabled(true);
        int actions = 0;
        QtPreLoginView view2([&](char action) { require(action == 'H', "wrong action"); ++actions; });
        view2.show();
        app.processEvents();
        auto* h2 = view2.findChild<AnimatedButton*>("handoff");
        QApplication::sendEvent(h2, &enter);
        waitMs(60);
        h2->click();
        require(actions == 1, "click during animation did not trigger handler");

        h2->click();
        h2->click();
        require(actions == 1, "duplicate click bypassed pending_");

        h2->setFocus(Qt::TabFocusReason);
        app.processEvents();
        // В offscreen нет нативного окна, hasFocus() может быть false,
        // но фокус-политика должна допускать фокус (визуальный индикатор в paintEvent).
        require(h2->focusPolicy() != Qt::NoFocus, "button cannot receive focus");
    }
 std::cout<<"Qt states/manual/idempotence/plain text/power confirmation/hover animation PASS\n";
}
