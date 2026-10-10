#include "FrontendProcess.h"
#include <chrono>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
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
 std::cout<<"frontend graceful/nonzero/hung/protocol/exception cleanup and reap PASS\n";
}
