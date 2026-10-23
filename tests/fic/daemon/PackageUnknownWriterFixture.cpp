// A distinct, long-lived executable with deterministic readiness. Do not depend
// on distribution coreutils dispatch (Ubuntu 26.04 uses a multi-call binary).
#include <cstdlib>
#include <unistd.h>
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    const int fd=std::atoi(argv[1]);const char ready='R';
    if(::write(fd,&ready,1)!=1)return 3;
    ::close(fd);
    for(;;)::pause();
}
