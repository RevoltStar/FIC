#include "FrontendProcess.h"
#include <chrono>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <iostream>
#include <stdexcept>
using namespace fic::prelogin;
void require(bool ok,const char* detail){if(!ok)throw std::runtime_error(detail);}
int main(){
 for(const auto kind:{"clean","failure","hung","malformed"}){
  int pair[2];require(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair)==0,"socketpair");
  pid_t child=fork();require(child>=0,"fork");
  if(child==0){
   close(pair[0]);
   if(std::string(kind)=="malformed"){char invalid[]="incident_clear";send(pair[1],invalid,sizeof(invalid),0);}
   char action;recv(pair[1],&action,1,0);
   if(std::string(kind)=="hung")for(;;)pause();
   usleep(100000);
   _exit(std::string(kind)=="failure"?1:0);
  }
  close(pair[1]);FrontendProcess graphics(child,pair[0]);
  if(std::string(kind)=="malformed"){usleep(30000);require(!graphics.action(),"accepted arbitrary action");}
  std::string error;const auto before=std::chrono::steady_clock::now();
  require(graphics.cleanup(error)==(std::string(kind)=="clean"),"false successful renderer cleanup");
  if(std::string(kind)=="clean")require(std::chrono::steady_clock::now()-before>=std::chrono::milliseconds(90),"didn't wait for exit");
  int status;require(waitpid(child,&status,WNOHANG)==-1 && errno==ECHILD,"renderer not reaped");
 }
 int pair[2];require(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair)==0,"socketpair");
 const pid_t child=fork();require(child>=0,"fork");if(child==0)for(;;)pause();
 close(pair[1]);{FrontendProcess graphics(child,pair[0]);}
 int status;require(waitpid(child,&status,WNOHANG)==-1 && errno==ECHILD,"exception/destructor didn't reap");
 // A denied signal must not turn cleanup/destruction into an infinite wait.
 // Run UID changes in an isolated worker; the root supervisor reaps its fixture.
 if(geteuid()==0){
  require(prctl(PR_SET_CHILD_SUBREAPER,1)==0,"subreaper");
  int report[2];require(pipe(report)==0,"report pipe");
  const pid_t worker=fork();require(worker>=0,"worker fork");
  if(worker==0){
   close(report[0]);
   int channel[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET,0,channel)!=0)_exit(2);
   const pid_t renderer=fork();if(renderer<0)_exit(3);
   if(renderer==0){if(setuid(65534)!=0)_exit(4);for(;;)pause();}
   if(write(report[1],&renderer,sizeof(renderer))!=sizeof(renderer))_exit(5);
   usleep(100000); // Renderer drops UID before worker.
   if(setuid(65533)!=0)_exit(6);
   close(channel[1]);
   const auto before=std::chrono::steady_clock::now();
   {
    FrontendProcess graphics(renderer,channel[0]);std::string error;
    if(graphics.cleanup(error))_exit(7);
   }
   _exit(std::chrono::steady_clock::now()-before<std::chrono::seconds(5)?0:8);
  }
  close(report[1]);pid_t renderer=-1;
  require(read(report[0],&renderer,sizeof(renderer))==sizeof(renderer),"renderer identity");close(report[0]);
  int workerStatus=0;bool finished=false;
  for(int attempt=0;attempt<700;++attempt){
   if(waitpid(worker,&workerStatus,WNOHANG)==worker){finished=true;break;}
   usleep(10000);
  }
  if(!finished){kill(worker,SIGKILL);waitpid(worker,&workerStatus,0);}
  kill(renderer,SIGKILL);waitpid(renderer,nullptr,0);
  require(finished && WIFEXITED(workerStatus) && WEXITSTATUS(workerStatus)==0,"denied signal blocked cleanup");
 }
 std::cout<<"frontend graceful/nonzero/hung/protocol/exception cleanup and reap PASS\n";
}
