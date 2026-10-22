// Research only: bounded kernel exit notification, no polling loop or signals.
#include <fcntl.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <iostream>
int main() {
    int barrier[2]; if(pipe2(barrier,O_CLOEXEC))return 1;
    const auto child=fork();if(child<0)return 2;
    if(!child){close(barrier[1]);char c;const auto n=read(barrier[0],&c,1);_exit(n==1?0:1);}
    close(barrier[0]);
    const int fd=static_cast<int>(syscall(SYS_pidfd_open,child,0));
    if(fd<0){close(barrier[1]);waitpid(child,nullptr,0);return 77;}
    pollfd event{fd,POLLIN,0};if(poll(&event,1,0)!=0)return 3;
    if(write(barrier[1],"Q",1)!=1)return 4;
    close(barrier[1]);
    if(poll(&event,1,5000)!=1 || !(event.revents&POLLIN))return 5;
    int status=0;if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status))return 6;
    close(fd);std::cout<<"PASS: bounded pidfd exit delivery without polling or PID reuse inference\n";
}
