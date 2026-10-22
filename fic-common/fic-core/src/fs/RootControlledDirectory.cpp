#include <fic/core/fs/RootControlledDirectory.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
namespace fic::core {
int openRootControlledDirectory(const std::filesystem::path& path,std::string& error) {
    if(!path.is_absolute() || path.lexically_normal()!=path || path.native().size()>PATH_MAX) {
        error="directory path must be bounded, absolute and normalized";return -1;
    }
    int fd=::open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    const auto trusted=[](int descriptor) {
        struct stat info{};
        return descriptor>=0 && ::fstat(descriptor,&info)==0 && S_ISDIR(info.st_mode) &&
            info.st_uid==0 && (info.st_mode&0022)==0;
    };
    if(!trusted(fd)) {if(fd>=0)::close(fd);error="untrusted filesystem root";return -1;}
    for(const auto& component:path.relative_path()) {
        if(component=="..") {::close(fd);error="parent traversal forbidden";return -1;}
        int next=::openat(fd,component.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        ::close(fd);fd=next;
        if(!trusted(fd)) {if(fd>=0)::close(fd);error="missing, symlink or untrusted directory ancestor";return -1;}
    }
    error.clear();return fd;
}
}
