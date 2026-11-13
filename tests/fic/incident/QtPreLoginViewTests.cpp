#include "QtPreLoginView.h"
#include "AnimatedButton.h"
#include <QApplication>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QAbstractButton>
#include <QTimer>
#include <QTest>
#include <QEnterEvent>
#include <stdexcept>
#include <filesystem>
#include <iostream>
using namespace fic::prelogin;

void require(bool ok, const char* detail) { if (!ok) throw std::runtime_error(detail); }
int main(int argc,char** argv){
 QApplication app(argc,argv);
 // Каталог для визуальных снимков реальных виджетов (проверка дизайна).
 const char* shotsDir=::getenv("FIC_PRELOGIN_SHOTS");
 const auto shot=[&](QWidget& widget,const QString& name){
   if(!shotsDir) return;
   const auto path=std::filesystem::path(shotsDir)/(name.toStdString()+".png");
   widget.grab().save(QString::fromStdString(path.string()));
 };
 // Три этапа: точное соответствие существующим состояниям контроллера.
 // Состояния шагов: 0=waiting, 1=active(spinner), 2=done, 3=failed,
 // 4=warning(не подтверждено). Banner: 0=нет, 1=warning, 2=error, 3=info.
 const struct{const char* state;int steps[3];int banner;const char* shot;} stepMatrix[]={{
   "WAITING_FOR_DAEMON",{0,0,0},0,"daemon_waiting"},{
   "DAEMON_STARTING",{1,0,0},0,"daemon_starting"},{
   "STARTUP_APPLYING",{2,1,0},0,"startup_applying"},{
   "STARTUP_SUCCEEDED",{2,2,0},0,"startup_succeeded"},{
   "STARTUP_FAILED",{2,3,0},2,"startup_failed"},{
   "DAEMON_DEGRADED",{0,4,0},1,"daemon_degraded"},{
   "DAEMON_UNAVAILABLE",{3,0,0},2,"daemon_unavailable"},{
   "HANDOFF",{2,2,1},0,"handoff"},{
   "POWER_ACTION",{0,0,0},3,"power_action"}};
 for(const auto& expected:stepMatrix){
  int actions=0;QtPreLoginView view([&](char action){require(action=='H',"wrong handoff action");++actions;});
  auto status=nlohmann::json{{"state",expected.state},{"detail","<img src='file:///etc/shadow'>"},{"mode","ACTIVE"},{"severity","ISOLATE"},{"startup","startup diagnostics"}};
  require(view.display(status),"valid status rejected");
  view.resize(800,600);view.show();app.processEvents();
  for(int i=0;i<3;++i) require(view.stepState(i)==expected.steps[i],(std::string("wrong step state for ")+expected.state+" step "+std::to_string(i)).c_str());
  const bool bannerVisible=view.warningBannerVisible();
  if(expected.banner==0) require(!bannerVisible,"unexpected banner shown");
  else require(bannerVisible,"required banner missing");
  if(expected.banner==1) require(view.warningBannerText().contains("не подтверждено"),"degraded banner must deny proven protection");
  shot(view,expected.shot);
  status["detail"]=std::string(4096,'x');require(view.display(status),"bounded long diagnostic rejected");
  app.processEvents();
  auto* button=view.findChild<QPushButton*>("handoff");
  require(view.rect().contains(button->geometry()),"long diagnostic hid handoff button");
  require(view.findChild<QLabel*>("detail")->textFormat()==Qt::PlainText,"rich text injected");
  auto* handoff=view.findChild<QPushButton*>("handoff");require(handoff->isEnabled(),"manual handoff unavailable");
  handoff->click();handoff->click();require(actions==1,"duplicate handoff action");
  status["extra"]=true;require(!view.display(status),"unbounded schema accepted");
 }
 // POWER_ACTION не должен помечать этапы выполненными (без ложного успеха).
 {
  QtPreLoginView view([](char){});
  auto status=nlohmann::json{{"state","DAEMON_DEGRADED"},{"detail","d"},{"mode","ACTIVE"},{"severity","HARD"},{"startup","s"}};
  require(view.display(status),"degraded status rejected");
  // Ни один шаг не помечен зелёным (Done=2): защита не подтверждена.
  require(view.stepState(0)!=2&&view.stepState(1)!=2&&view.stepState(2)!=2,"degraded state must not show false success");
 }
 // Разрешения: кнопки остаются доступны на малых экранах, панель не
 // растягивается на всю ширину на больших.
 for(const QSize resolution:{QSize(800,600),QSize(1024,768),QSize(1280,720),QSize(1920,1080)}){
  QtPreLoginView view([](char){});
  auto status=nlohmann::json{{"state","DAEMON_DEGRADED"},{"detail",std::string(3000,'z')},{"mode","ACTIVE"},{"severity","HARD"},{"startup","applying"}};
  require(view.display(status),"resolution status rejected");
  view.resize(resolution);view.show();app.processEvents();
  auto* handoff=view.findChild<QPushButton*>("handoff");
  auto* reboot=view.findChild<QPushButton*>("reboot");
  auto* poweroff=view.findChild<QPushButton*>("poweroff");
  require(view.rect().contains(handoff->geometry()),(std::string("handoff offscreen at ")+std::to_string(resolution.width())).c_str());
  require(view.rect().contains(reboot->geometry()),(std::string("reboot offscreen at ")+std::to_string(resolution.width())).c_str());
  require(view.rect().contains(poweroff->geometry()),(std::string("poweroff offscreen at ")+std::to_string(resolution.width())).c_str());
  require(handoff->isEnabled()&&reboot->isEnabled()&&poweroff->isEnabled(),"actions must remain available");
  if(resolution.width()>=1280) require(handoff->width()<resolution.width()/2,"panel must not stretch over the whole width");
  if(resolution==QSize(1920,1080)) shot(view,"resolution_1920x1080");
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

        require(handoff->currentBackgroundColor() == QColor("#ffffff"), "wrong initial bg");
        require(handoff->currentBorderColor() == QColor("#c7d6e6"), "wrong initial border");

        QEnterEvent enter(QPointF(10, 10), QPointF(10, 10), QPointF(10, 10));
        QApplication::sendEvent(handoff, &enter);
        QTest::qWait(60);
        require(handoff->currentBackgroundColor() != QColor("#ffffff"), "hover did not change bg color");
        require(handoff->currentBorderColor() != QColor("#c7d6e6"), "hover did not change border color");

        QEvent leave(QEvent::Leave);
        QApplication::sendEvent(handoff, &leave);
        QTest::qWait(200);
        require(handoff->currentBackgroundColor() == QColor("#ffffff"), "leave did not restore bg color");
        require(handoff->currentBorderColor() == QColor("#c7d6e6"), "leave did not restore border color");

        QApplication::sendEvent(handoff, &enter);
        QApplication::sendEvent(handoff, &leave);
        QApplication::sendEvent(handoff, &enter);
        QTest::qWait(60);
        require(handoff->currentBackgroundColor() != QColor("#ffffff"), "fast re-hover did not change color");
        QApplication::sendEvent(handoff, &leave);
        QTest::qWait(200);
        require(handoff->currentBackgroundColor() == QColor("#ffffff"), "fast leave did not restore color");

        handoff->setEnabled(false);
        QApplication::sendEvent(handoff, &enter);
        QTest::qWait(60);
        require(handoff->currentBackgroundColor() == QColor("#ffffff"), "disabled button reacted to hover");
        require(handoff->currentBorderColor() == QColor("#c7d6e6"), "disabled button changed border on hover");

        handoff->setEnabled(true);
        int actions = 0;
        QtPreLoginView view2([&](char action) { require(action == 'H', "wrong action"); ++actions; });
        view2.show();
        app.processEvents();
        auto* h2 = view2.findChild<AnimatedButton*>("handoff");
        QApplication::sendEvent(h2, &enter);
        QTest::qWait(60);
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
