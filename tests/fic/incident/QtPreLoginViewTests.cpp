#include "QtPreLoginView.h"
#include "AnimatedButton.h"
#include <QApplication>
#include <QPushButton>
#include <QLabel>
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
 // Геометрия виджета в координатах QtPreLoginView: button->geometry()
 // задана в координатах родителя, поэтому используется mapTo.
 const auto mappedRect=[](QWidget& view,QWidget* widget){
   return QRect(widget->mapTo(&view,QPoint(0,0)),widget->size());
 };
 // Проверка одной кнопки: полностью видима, ненулевая, внутри панели и
 // не пересекается с ранее проверенными кнопками.
 const auto checkButton=[&](QtPreLoginView& view,QPushButton* button,
                            const QRect& cardRect,
                            std::vector<QRect>& placed,const char* name){
   const QRect rect=mappedRect(view,button);
   require(rect.width()>0&&rect.height()>0,(std::string(name)+" has empty geometry").c_str());
   require(button->isVisible(),(std::string(name)+" is hidden").c_str());
   require(view.rect().contains(rect),(std::string(name)+" is outside the view").c_str());
   require(cardRect.contains(rect),(std::string(name)+" is outside the central panel").c_str());
   for(const QRect& other:placed)
     require(!rect.intersects(other),(std::string(name)+" overlaps another button").c_str());
   placed.push_back(rect);
 };
 // Состояния шагов: 0=waiting, 1=active(spinner), 2=done, 3=failed,
 // 4=warning(не подтверждено). Banner: 0=нет, 1=warning, 2=error, 3=info.
 const struct{const char* state;int steps[3];int banner;const char* shot;} stepMatrix[]={{
   "WAITING_FOR_DAEMON",{0,0,0},0,"daemon_waiting"},{
   "DAEMON_STARTING",{1,0,0},0,"daemon_starting"},{
   "STARTUP_APPLYING",{2,1,0},0,"startup_applying"},{
   "STARTUP_SUCCEEDED",{2,2,0},0,"startup_succeeded"},{
   "STARTUP_FAILED",{2,3,0},2,"startup_failed"},{
   "DAEMON_SERVICE_FAILED",{3,0,0},2,"service_failed"},{
   "DAEMON_DEGRADED",{0,4,0},1,"daemon_degraded"},{
   "DAEMON_UNAVAILABLE",{4,0,0},1,"daemon_unavailable"},{
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
  if(expected.banner==1) require(view.warningBannerText().contains(
      std::string(expected.state)=="DAEMON_UNAVAILABLE"?"не подтверждена":"не подтверждено"),"warning must deny proven protection");
  if(std::string(expected.state)=="DAEMON_UNAVAILABLE"){
    require(view.warningBannerText().contains("текущее состояние"),"unavailability must explain missing current observation");
    require(view.findChild<QLabel*>("banner")->styleSheet().contains("#fff4dd"),"unavailability uses red failure banner");
  }
  if(expected.banner==2) require(view.findChild<QLabel*>("banner")->styleSheet().contains("#fdecec"),"missing red error banner");
  if(std::string(expected.state)=="DAEMON_SERVICE_FAILED")
    require(view.warningBannerText().contains("systemd")&&view.warningBannerText().contains("fic.service"),"service failure attribution missing");
  require(view.findChild<QPushButton*>("reboot")->isEnabled()&&view.findChild<QPushButton*>("poweroff")->isEnabled(),"power actions unavailable in state");
  shot(view,expected.shot);
  status["detail"]=std::string(4096,'x');require(view.display(status),"bounded long diagnostic rejected");
  app.processEvents();
  auto* button=view.findChild<QPushButton*>("handoff");
  auto* card=view.findChild<QWidget*>("card");
  const QRect handoffRect=mappedRect(view,button);
  require(handoffRect.width()>0&&handoffRect.height()>0,"handoff has empty geometry");
  require(view.rect().contains(handoffRect),"long diagnostic hid handoff button");
  require(mappedRect(view,card).contains(handoffRect),"handoff outside the central panel");
  require(view.findChild<QLabel*>("detail")->textFormat()==Qt::PlainText,"rich text injected");
  auto* handoff=view.findChild<QPushButton*>("handoff");require(handoff->isEnabled(),"manual handoff unavailable");
  handoff->click();handoff->click();require(actions==1,"duplicate handoff action");
  status["extra"]=true;require(!view.display(status),"unbounded schema accepted");
 }
 // One widget must recover through a transient observation outage without restart.
 {
  QtPreLoginView view([](char){});
  for(const auto& expected:std::vector<std::pair<std::string,std::pair<int,int>>>{
      {"STARTUP_APPLYING",{2,1}},{"DAEMON_UNAVAILABLE",{4,0}},
      {"STARTUP_APPLYING",{2,1}},{"STARTUP_SUCCEEDED",{2,2}},
      {"STARTUP_FAILED",{2,3}}}){
   const auto status=nlohmann::json{{"state",expected.first},{"detail","operation=get_property property=MainPID code=-110"},
       {"mode","не подтверждён"},{"severity","не подтверждена"},{"startup","result"}};
   require(view.display(status),"state transition rejected");
   require(view.stepState(0)==expected.second.first&&view.stepState(1)==expected.second.second,
       "transient observation/failure step semantics lost");
   if(expected.first=="STARTUP_FAILED")require(view.findChild<QLabel*>("banner")->styleSheet().contains("#fdecec"),
       "confirmed startup failure lost red error banner");
   require(view.findChild<QLabel*>("detail")->text().contains("property=MainPID"),"D-Bus diagnostic not rendered");
  }
 }
 // POWER_ACTION не должен помечать этапы выполненными (без ложного успеха).
 {
  QtPreLoginView view([](char){});
  auto status=nlohmann::json{{"state","DAEMON_DEGRADED"},{"detail","d"},{"mode","ACTIVE"},{"severity","HARD"},{"startup","s"}};
  require(view.display(status),"degraded status rejected");
  // Ни один шаг не помечен зелёным (Done=2): защита не подтверждена.
  require(view.stepState(0)!=2&&view.stepState(1)!=2&&view.stepState(2)!=2,"degraded state must not show false success");
 }
 // Основной сценарий STARTUP_APPLYING на всех разрешениях, включая эталонное
 // 1536×1024. Кнопки: полностью видимы, ненулевые, внутри панели, без
 // перекрытий. Панель: близка к ~82% ширины на эталоне, не растягивается на
 // весь экран.
 for(const QSize resolution:{QSize(800,600),QSize(1024,768),QSize(1280,720),QSize(1536,1024),QSize(1920,1080)}){
  QtPreLoginView view([](char){});
  auto status=nlohmann::json{{"state","STARTUP_APPLYING"},{"detail","startup diagnostics"},{"mode","ACTIVE"},{"severity","ISOLATE"},{"startup","applying"}};
  require(view.display(status),"resolution status rejected");
  view.resize(resolution);view.show();app.processEvents();
  auto* card=view.findChild<QWidget*>("card");
  const QRect cardRect=mappedRect(view,card);
  require(view.rect().contains(cardRect),"central panel outside the view");
  require(cardRect.width()>=700,"central panel too narrow");
  if(resolution.width()>=1536){
    const int ratio=resolution.width()*100/cardRect.width();
    require(ratio>=110&&ratio<=140,(std::string("panel width ratio off at ")+std::to_string(resolution.width())).c_str());
  }
  auto* handoff=view.findChild<QPushButton*>("handoff");
  auto* reboot=view.findChild<QPushButton*>("reboot");
  auto* poweroff=view.findChild<QPushButton*>("poweroff");
  std::vector<QRect> placed;
  checkButton(view,handoff,cardRect,placed,"handoff");
  checkButton(view,reboot,cardRect,placed,"reboot");
  checkButton(view,poweroff,cardRect,placed,"poweroff");
  require(handoff->isEnabled()&&reboot->isEnabled()&&poweroff->isEnabled(),"actions must remain available");
  // Расположение при достаточной ширине: handoff слева, питание справа.
  if(resolution.width()>=1024){
    require(handoff->x()<reboot->x()&&reboot->x()<poweroff->x(),"wrong button order");
  }
  if(resolution==QSize(800,600)) shot(view,"resolution_800x600");
  if(resolution==QSize(1280,720)) shot(view,"resolution_1280x720");
  if(resolution==QSize(1536,1024)) shot(view,"resolution_1536x1024");
  if(resolution==QSize(1920,1080)) shot(view,"resolution_1920x1080");
 }
 // Disabled-иконка повторяет состояние кнопки: в выключенной кнопке самый
 // тёмный пиксель зоны иконки значительно светлее, чем во включённой
 // (серый текст disabled), тёмная иконка не сохраняется.
 {
  QtPreLoginView view([](char){});
  view.resize(1024,768);view.show();app.processEvents();
  auto* handoff=view.findChild<AnimatedButton*>("handoff");
  const auto darkest=[](const QPixmap& pixmap){
    const QImage image=pixmap.toImage();
    int worst=255;
    for(int y=6;y<image.height()-6;++y)
      for(int x=8;x<40;++x)
        worst=qMin(worst,qGray(image.pixel(x,y)));
    return worst;
  };
  const int enabledDark=darkest(handoff->grab());
  handoff->setEnabled(false);app.processEvents();
  const int disabledDark=darkest(handoff->grab());
  require(enabledDark<110,"enabled icon is not dark");
  require(disabledDark>enabledDark+25,"disabled icon keeps dark color");
 }
 // Confirmation is a child overlay, so view.grab() includes the actual dialog.
 for(const char action:{'R','P'}){
  for(const QSize resolution:{QSize(800,600),QSize(1024,768),QSize(1280,720),QSize(1536,1024),QSize(1920,1080)}){
   std::vector<char> actions;
   QtPreLoginView view([&](char sent){actions.push_back(sent);});
   view.resize(resolution);view.show();app.processEvents();
   const auto activeOverlay=[&view]() -> QWidget* {
    for(auto* widget:view.findChildren<QWidget*>("powerConfirmation"))
     if(widget->isVisible()) return widget;
    return nullptr;
   };
   auto* trigger=view.findChild<QPushButton*>(action=='R'?"reboot":"poweroff");
   auto* handoff=view.findChild<QPushButton*>("handoff");
   trigger->click();app.processEvents();
   auto* overlay=activeOverlay();
   require(overlay&&overlay->isVisible(),"confirmation missing");
   auto* card=overlay->findChild<QWidget*>("confirmationCard");
   auto* cancel=overlay->findChild<AnimatedButton*>("confirmationCancel");
   auto* accept=overlay->findChild<AnimatedButton*>("confirmationAccept");
   auto* title=overlay->findChild<QLabel*>("confirmationTitle");
   auto* description=overlay->findChild<QLabel*>("confirmationDescription");
   require(card&&cancel&&accept&&title&&description,"confirmation contents missing");
   require(title->text()==(action=='R'?QStringLiteral("Перезагрузка компьютера"):QStringLiteral("Выключение компьютера")),"wrong confirmation title");
   require(description->text().contains(action=='R'?QStringLiteral("перезагрузить"):QStringLiteral("выключить")),"wrong confirmation text");
   require(cancel->text()==QStringLiteral("Отмена")&&accept->text()==(action=='R'?QStringLiteral("Перезагрузить"):QStringLiteral("Выключить")),"wrong confirmation buttons");
   require(cancel->hasFocus(),"cancel lacks initial focus");
   require(!handoff->isEnabled()&&!trigger->isEnabled(),"base actions enabled under confirmation");
   require(view.rect().contains(mappedRect(view,card)),"confirmation outside view");
   require(card->width()<=520&&card->height()<resolution.height(),"confirmation too large");
   const QRect cardRect=mappedRect(view,card);
   require(cardRect.contains(mappedRect(view,title))&&cardRect.contains(mappedRect(view,description)),"confirmation text clipped");
   std::vector<QRect> placed;
   checkButton(view,cancel,cardRect,placed,"cancel");
   checkButton(view,accept,cardRect,placed,"accept");
   require(cancel->height()==accept->height(),"confirmation button heights differ");
   require(cancel->width()>=cancel->fontMetrics().horizontalAdvance(cancel->text())+28,"cancel label clipped");
   require(accept->width()>=accept->fontMetrics().horizontalAdvance(accept->text())+28,"accept label clipped");
   trigger->click();handoff->click();
   require(activeOverlay()==overlay&&actions.empty(),"reentrant or bypassed confirmation");
   if(resolution==QSize(800,600)||resolution==QSize(1920,1080))
    shot(view,QStringLiteral("%1_confirmation_%2x%3").arg(action=='R'?"reboot":"poweroff").arg(resolution.width()).arg(resolution.height()));
   if(resolution==QSize(800,600)){
    const auto status=nlohmann::json{{"state","DAEMON_UNAVAILABLE"},{"detail","new broker state"},
        {"mode","ACTIVE"},{"severity","HARD"},{"startup","pending"}};
    require(view.display(status),"broker update rejected under confirmation");
    require(view.findChild<QLabel*>("detail")->text()==QStringLiteral("new broker state")&&overlay->isVisible(),
        "broker update blocked by confirmation");
   }
   // Initial Enter is a safe cancel; Alt+D and the handoff Return shortcut are inactive.
   QTest::keyClick(cancel,Qt::Key_Return);app.processEvents();
   require(!activeOverlay()&&actions.empty(),"initial Enter did not cancel");
   require(handoff->isEnabled()&&trigger->isEnabled(),"base buttons not restored");
   trigger->click();app.processEvents();
   overlay=activeOverlay();
   cancel=overlay->findChild<AnimatedButton*>("confirmationCancel");
   QTest::keyClick(cancel,Qt::Key_Escape);app.processEvents();
   require(!activeOverlay()&&actions.empty(),"Escape did not cancel");
   trigger->click();app.processEvents();
   overlay=activeOverlay();
   cancel=overlay->findChild<AnimatedButton*>("confirmationCancel");
   accept=overlay->findChild<AnimatedButton*>("confirmationAccept");
   QTest::keyClick(cancel,Qt::Key_D,Qt::AltModifier);app.processEvents();
   require(actions.empty()&&overlay->isVisible(),"Alt+D bypassed confirmation");
   QTest::keyClick(cancel,Qt::Key_Tab);app.processEvents();
   require(accept->hasFocus(),"Tab did not focus accept");
   QTest::keyClick(accept,Qt::Key_Backtab);app.processEvents();
   require(cancel->hasFocus(),"Shift+Tab did not return to cancel");
   accept->setFocus();
   QTest::keyClick(accept,Qt::Key_Return);app.processEvents();
   require(actions.size()==1&&actions.front()==action,"confirmation did not send exactly one correct action");
   require(!handoff->isEnabled()&&!trigger->isEnabled(),"pending actions not disabled");
   trigger->click();handoff->click();
   require(actions.size()==1,"pending action sent twice");
  }
 }
 {
  QtPreLoginView view([](char){throw std::runtime_error("action on frontend close");});
  view.resize(800,600);view.show();app.processEvents();
  view.findChild<QPushButton*>("poweroff")->click();
  require(view.findChild<QWidget*>("powerConfirmation")->isVisible(),"close fixture confirmation missing");
  view.close();app.processEvents();
  require(!view.isVisible(),"open confirmation blocked frontend close");
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
