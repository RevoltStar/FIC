// Test executable only. Kill the REAL writer halfway through its first staged
// config write; never linked into fic or fic-core. No alternative writer engine.
#include <atomic>
#include <fcntl.h>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
std::atomic<bool> sssdI4CrashDuringWrite{false};
extern "C" ssize_t write(int fd,const void* bytes,size_t count) {
    if(sssdI4CrashDuringWrite.load()&&count>1) {
        char path[4096];const auto name="/proc/self/fd/"+std::to_string(fd);
        auto n=::syscall(SYS_readlinkat,AT_FDCWD,name.c_str(),path,sizeof(path));
        if(n>0&&std::string(path,n).rfind("/etc/sssd/conf.d/.zzzz-fic.conf.tmp.",0)==0) {
            ::syscall(SYS_write,fd,bytes,count/2);
            const char checkpoint[]="partial-staged-write";
            int out=::syscall(SYS_openat,AT_FDCWD,"/run/sssd-research-out/last-checkpoint",O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,0600);
            if(out>=0){::syscall(SYS_write,out,checkpoint,sizeof(checkpoint)-1);::syscall(SYS_close,out);}
            ::syscall(SYS_exit_group,74);
        }
    }
    return ::syscall(SYS_write,fd,bytes,count);
}
