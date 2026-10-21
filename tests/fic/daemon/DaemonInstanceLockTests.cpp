#include "daemon/DaemonInstanceLock.h"
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
using fic::daemon::DaemonInstanceLock;
void require(bool yes, const std::string& message) { if (!yes) throw std::runtime_error(message); }
struct Fixture {
    std::filesystem::path root;
    Fixture() {
        std::string pattern = "/run/fic-singleton-tests-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        require(created != nullptr, "mkdtemp"); root = created;
    }
    ~Fixture() { std::error_code ec; std::filesystem::remove_all(root, ec); }
    std::filesystem::path directory() const { return root / "runtime"; }
    std::filesystem::path file() const { return directory() / "daemon.lock"; }
};
struct Pipe {
    int fds[2];
    Pipe() { require(::pipe2(fds, O_CLOEXEC) == 0, "pipe2"); }
    ~Pipe() { for (int fd : fds) if (fd >= 0) ::close(fd); }
};
void send(int fd, char value) { require(::write(fd, &value, 1) == 1, "pipe write"); }
char receive(int fd) { char value = 0; require(::read(fd, &value, 1) == 1, "pipe read"); return value; }
void wait(pid_t pid, int expected = 0) {
    int status = 0; require(::waitpid(pid, &status, 0) == pid, "waitpid");
    require(WIFEXITED(status) && WEXITSTATUS(status) == expected, "child failed");
}
void testLifetimeAndMetadata() {
    Fixture tree;
    std::string error;
    {
        DaemonInstanceLock first, second;
        require(first.tryAcquire(tree.directory(), error), error);
        require(!second.tryAcquire(tree.directory(), error) && error.find("holds the lock") != std::string::npos,
                "second independent FD must fail closed even within same process");
        require(!first.tryAcquire(tree.directory(), error), "no recursive acquisition");
        struct stat st{}; require(::lstat(tree.file().c_str(), &st) == 0, "stat lock");
        require(st.st_uid == 0 && (st.st_mode & 07777) == 0600 && st.st_nlink == 1, "lock metadata");
    }
    require(std::filesystem::exists(tree.file()), "release must not unlink lockfile");
    DaemonInstanceLock restarted;
    require(restarted.tryAcquire(tree.directory(), error), error);
}
void testConcurrentAndCrash(bool crash) {
    Fixture tree;
    Pipe ready, release;
    const pid_t child = ::fork(); require(child >= 0, "fork");
    if (!child) {
        ::close(ready.fds[0]); ::close(release.fds[1]);
        int code = 0;
        try {
            DaemonInstanceLock owner; std::string error;
            require(owner.tryAcquire(tree.directory(), error), error);
            send(ready.fds[1], 'L');
            char ignored; (void)::read(release.fds[0], &ignored, 1);
        } catch (...) { code = 1; }
        ::_exit(code);
    }
    require(receive(ready.fds[0]) == 'L', "owner readiness barrier");
    DaemonInstanceLock contender; std::string error;
    require(!contender.tryAcquire(tree.directory(), error), "concurrent writer admitted");
    require(error.find("holds the lock") != std::string::npos, error);
    if (crash) {
        require(::kill(child, SIGKILL) == 0, "kill owner");
        int status = 0; require(::waitpid(child, &status, 0) == child && WIFSIGNALED(status), "crash wait");
    } else { send(release.fds[1], 'Q'); wait(child); }
    require(contender.tryAcquire(tree.directory(), error), "restart after owner exit/crash: " + error);
}
void testSimultaneousStart() {
    Fixture tree; Pipe start, answers, release;
    pid_t children[2];
    for (pid_t& child : children) {
        child = ::fork(); require(child >= 0, "fork concurrent starters");
        if (!child) {
            ::close(start.fds[1]); ::close(release.fds[1]);
            int code = 0;
            try {
                (void)receive(start.fds[0]);
                DaemonInstanceLock lock; std::string error;
                const bool acquired = lock.tryAcquire(tree.directory(), error);
                send(answers.fds[1], acquired ? 'L' : 'D');
                if (acquired) { char ignored; (void)::read(release.fds[0], &ignored, 1); }
            } catch (...) { code = 1; }
            ::_exit(code);
        }
    }
    send(start.fds[1], 'S'); send(start.fds[1], 'S');
    const char a = receive(answers.fds[0]), b = receive(answers.fds[0]);
    require((a == 'L' && b == 'D') || (a == 'D' && b == 'L'), "exactly one concurrent startup must win");
    send(release.fds[1], 'Q');
    for (pid_t child : children) wait(child);
}
void testUntrustedObjects() {
    Fixture tree;
    std::filesystem::create_directory(tree.directory());
    auto refused = [&] { DaemonInstanceLock lock; std::string error;
        require(!lock.tryAcquire(tree.directory(), error) && !error.empty(), "untrusted file admitted"); };
    std::filesystem::create_symlink(tree.root / "target", tree.file()); refused();
    require(!std::filesystem::exists(tree.root / "target"), "followed dangling symlink");
    std::filesystem::remove(tree.file());
    require(::mkfifo(tree.file().c_str(), 0600) == 0, "mkfifo"); refused();
    std::filesystem::remove(tree.file());
    std::filesystem::create_directory(tree.file()); refused();
    std::filesystem::remove(tree.file());
    { std::ofstream file(tree.file()); file << "external bytes"; }
    ::chmod(tree.file().c_str(), 0644); refused();
    struct stat st{}; ::stat(tree.file().c_str(), &st);
    require((st.st_mode & 0777) == 0644, "must not repair foreign mode");
    ::chmod(tree.file().c_str(), 0600);
    std::filesystem::create_hard_link(tree.file(), tree.root / "alias"); refused();
    std::filesystem::remove(tree.root / "alias");
    require(::chown(tree.file().c_str(), 65534, 65534) == 0, "chown fixture"); refused();
    require(::chown(tree.file().c_str(), 0, 0) == 0, "restore fixture owner");
    ::chmod(tree.directory().c_str(), 0777); refused();
    ::chmod(tree.directory().c_str(), 0755);
    std::filesystem::create_directory_symlink(tree.directory(), tree.root / "aliasdir");
    DaemonInstanceLock lock; std::string error;
    require(!lock.tryAcquire(tree.root / "aliasdir", error), "directory symlink admitted");
    require(!lock.tryAcquire(tree.directory() / ".." / "runtime", error), "traversal admitted");
    require(!lock.tryAcquire("relative", error), "relative lock path admitted");
}
void testExceptionRelease() {
    Fixture tree; std::string error;
    try { DaemonInstanceLock lock; require(lock.tryAcquire(tree.directory(), error), error); throw 7; }
    catch (int) {}
    DaemonInstanceLock next; require(next.tryAcquire(tree.directory(), error), error);
}
} // namespace
int main(int argc, char** argv) {
    // Disposable native startup probe: hold the real production guard while
    // another executable starts. No host mode or policy code is invoked here.
    if (argc == 3 && std::string(argv[1]) == "--hold") {
        DaemonInstanceLock lock; std::string error;
        if (!lock.tryAcquire(argv[2], error)) { std::cerr << error << '\n'; return 1; }
        std::cout << "LOCKED" << std::endl;
        char ignored; (void)::read(STDIN_FILENO, &ignored, 1);
        return 0;
    }
    if (::geteuid() != 0) {
        DaemonInstanceLock lock; std::string error;
        if (lock.tryAcquire("/run/fic", error)) return 1;
        std::cout << "SKIP: trusted root-owned process tests require disposable root environment\n";
        return 77;
    }
    ::alarm(25); // bounded watchdog; synchronization uses pipes, never sleeps.
    try {
        testLifetimeAndMetadata(); testConcurrentAndCrash(false); testConcurrentAndCrash(true);
        testSimultaneousStart(); testUntrustedObjects(); testExceptionRelease();
        std::cout << "PASS: lifetime, contention, crash/restart, simultaneous start, trust, exception\n";
    } catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
