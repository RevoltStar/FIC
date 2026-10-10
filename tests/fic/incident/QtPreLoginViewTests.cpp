#include "QtPreLoginView.h"
#include <QApplication>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QAbstractButton>
#include <QTimer>
#include <stdexcept>
#include <iostream>
using namespace fic::prelogin;
void require(bool ok,const char* detail){if(!ok)throw std::runtime_error(detail);}
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
 std::cout<<"Qt states/manual/idempotence/plain text/power confirmation PASS\n";
}
