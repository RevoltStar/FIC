#include "service/sssd/SssdRuntimeProof.h"
#include "platform/PlatformExecutableResolver.h"
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/process/VerifiedProcessExecutor.h>
#include <fstream>
#include <linux/memfd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <pwd.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <thread>
#include <unistd.h>
namespace fic::service::sssd::detail_i3 {
namespace {
namespace d = fic::service::detail;
using J = nlohmann::json;
struct DirCloser {
  void operator()(DIR *directory) const { ::closedir(directory); }
};
[[noreturn]] void fail(ActivationStatus status, const std::string &message) {
  throw d::Failure(status, "SSSD runtime: " + message);
}
void remaining(Deadline deadline) {
  if (std::chrono::steady_clock::now() >= deadline)
    fail(ActivationStatus::TimedOut, "proof deadline exceeded");
}
std::string read(const std::string &path, std::size_t limit = 1024 * 1024) {
  d::Fd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
  if (!fd)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "cannot read runtime observation");
  std::string out;
  char b[8192];
  ssize_t n;
  while ((n = ::read(fd.get(), b, sizeof b)) != 0) {
    if (n < 0) {
      if (errno == EINTR)
        continue;
      fail(ActivationStatus::ReadinessUnconfirmed, "runtime read failed");
    }
    if (out.size() + n > limit)
      fail(ActivationStatus::UnsupportedConfiguration,
           "runtime observation limit");
    out.append(b, n);
  }
  return out;
}
J typed(const d::LaunchContract &c, const std::string &key) {
  return J::parse(c.at("launch." + key)).at("value");
}
ProcessResult execute(const std::string &exe,
                      const std::vector<std::string> &args, Deadline deadline) {
  remaining(deadline);
  ProcessOptions options;
  options.timeout = std::chrono::duration_cast<std::chrono::milliseconds>(
      deadline - std::chrono::steady_clock::now());
  if (options.timeout.count() <= 0)
    fail(ActivationStatus::TimedOut, "query deadline exhausted");
  options.maxOutputBytes = 1024 * 1024;
  options.clearEnvironment = true;
  options.environment = {{"LANG", "C"},
                         {"LC_ALL", "C"},
                         {"PATH", "/usr/sbin:/usr/bin:/sbin:/bin"}};
  auto result = VerifiedProcessExecutor::execute(exe, args, options);
  if (!result.success())
    fail(result.timedOut ? ActivationStatus::TimedOut
                         : ActivationStatus::UnsupportedConfiguration,
         "verified native query failed: " + exe + ": " + result.error);
  return result;
}
struct Process {
  SssdProcessEvidence evidence;
  d::Fd pidfd;
  std::set<unsigned> sockets;
  std::vector<std::string> args;
};
Process process(pid_t pid, const std::string &exe, const d::Identity &db,
                const NativeRuntimeContract &contract) {
  Process out;
  out.evidence.pid = pid;
  out.evidence.executable = exe;
  const auto path = "/proc/" + std::to_string(pid);
  out.pidfd = d::Fd(::syscall(SYS_pidfd_open, pid, 0));
  if (!out.pidfd)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "cannot pin process generation");
  const auto stat = read(path + "/stat", 8192);
  const auto end = stat.rfind(')');
  if (end == stat.npos)
    fail(ActivationStatus::ReadinessUnconfirmed, "process stat malformed");
  std::istringstream fields(stat.substr(end + 1));
  std::string field, state;
  for (int i = 3; i <= 22; ++i) {
    if (!(fields >> field))
      fail(ActivationStatus::ReadinessUnconfirmed, "process stat incomplete");
    if (i == 3)
      state = field;
    if (i == 4)
      out.evidence.parent = std::stoi(field);
  }
  if (state == "T" || state == "t" || state == "Z" || state == "X")
    fail(ActivationStatus::ReadinessUnconfirmed, "consumer suspended/exited");
  out.evidence.startToken = std::to_string(pid) + ":" + field;
  struct stat actual {
  }, expected{}, root{}, self{};
  auto canonical = d::openAbsolute(exe, O_RDONLY);
  if (::stat((path + "/exe").c_str(), &actual) ||
      ::fstat(canonical.get(), &expected) || actual.st_dev != expected.st_dev ||
      actual.st_ino != expected.st_ino)
    fail(ActivationStatus::InterferenceDetected,
         "consumer executable object differs");
  out.evidence.executableIdentity = d::identity(canonical.get());
  if (::stat((path + "/root").c_str(), &root) || ::stat("/", &self) ||
      root.st_dev != self.st_dev || root.st_ino != self.st_ino)
    fail(ActivationStatus::UnsupportedConfiguration, "consumer root differs");
  out.evidence.mountNamespace = d::namespaceIdentity(pid);
  if (out.evidence.mountNamespace != d::namespaceIdentity(::getpid()))
    fail(ActivationStatus::UnsupportedConfiguration,
         "consumer mount namespace differs");
  out.evidence.cgroup = read(path + "/cgroup", 4096);
  if (out.evidence.cgroup != "0::/system.slice/sssd.service\n")
    fail(ActivationStatus::UnsupportedConfiguration,
         "consumer outside canonical monitor cgroup");
  std::istringstream status(read(path + "/status", 16384));
  std::string line;
  bool uid = false, gid = false;
  while (std::getline(status, line))
    if (line.rfind("Uid:", 0) == 0 || line.rfind("Gid:", 0) == 0) {
      std::istringstream values(line.substr(4));
      unsigned a, b, c, e;
      if (!(values >> a >> b >> c >> e) || a != b || a != c || a != e)
        fail(ActivationStatus::UnsupportedConfiguration,
             "consumer credential set ambiguous");
      if (line[0] == 'U') {
        out.evidence.uid = a;
        uid = true;
      } else {
        out.evidence.gid = a;
        gid = true;
      }
    }
  if (!uid || !gid ||
      (out.evidence.uid != 0 && out.evidence.uid != contract.uid) ||
      (out.evidence.gid != 0 && out.evidence.gid != contract.gid))
    fail(ActivationStatus::UnsupportedConfiguration,
         "consumer credentials outside native identity");
  const auto cmd = read(path + "/cmdline", 16384);
  std::size_t at = 0;
  while (at < cmd.size()) {
    auto n = cmd.find('\0', at);
    if (n == cmd.npos)
      fail(ActivationStatus::UnsupportedConfiguration, "incomplete argv");
    out.args.push_back(cmd.substr(at, n - at));
    at = n + 1;
  }
  if (out.args.empty() || out.args[0] != exe)
    fail(ActivationStatus::UnsupportedConfiguration,
         "non-native consumer argv0");
  bool config = false;
  const auto fdpath = path + "/fd";
  DIR *raw = ::opendir(fdpath.c_str());
  if (!raw)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "consumer descriptors unavailable");
  std::unique_ptr<DIR, DirCloser> directory(raw);
  unsigned count = 0;
  while (auto *item = ::readdir(raw)) {
    if (item->d_name[0] == '.')
      continue;
    if (++count > 4096)
      fail(ActivationStatus::UnsupportedConfiguration,
           "consumer descriptor limit");
    const auto name = fdpath + "/" + item->d_name;
    struct stat st {};
    char link[4096];
    const auto n = ::readlink(name.c_str(), link, sizeof link);
    if (n <= 0 || n == sizeof link)
      fail(ActivationStatus::ReadinessUnconfirmed,
           "consumer descriptor changed");
    const std::string target(link, n);
    if (target.rfind("socket:[", 0) == 0 && target.back() == ']')
      out.sockets.insert(std::stoul(target.substr(8, target.size() - 9)));
    if (target == "/var/lib/sss/db/config.ldb" &&
        ::stat(name.c_str(), &st) == 0 && st.st_dev == db.device &&
        st.st_ino == db.inode)
      config = true;
  }
  if (!config)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "consumer has no descriptor to selected ConfigDB generation");
  bool mapped = false;
  std::istringstream maps(read(path + "/maps", 1024 * 1024));
  while (std::getline(maps, line)) {
    std::istringstream parts(line);
    std::string range, mode, offset, device, name;
    unsigned long inode;
    if (!(parts >> range >> mode >> offset >> device >> inode))
      continue;
    std::getline(parts, name);
    struct stat mapping {};
    // maps reports the backing filesystem device on OverlayFS. Resolve the
    // kernel mapping object instead of equating that number with stat(2).
    if (name.find("/var/lib/sss/db/config.ldb") != name.npos &&
        mode.size() == 4 && mode[3] == 's' &&
        ::stat((path + "/map_files/" + range).c_str(), &mapping) == 0 &&
        mapping.st_dev == db.device && mapping.st_ino == db.inode)
      mapped = true;
  }
  if (!mapped)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "consumer ConfigDB mapping unproven");
  out.evidence.configDbIdentity = db;
  pollfd p{out.pidfd.get(), POLLIN, 0};
  if (::poll(&p, 1, 0) != 0)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "consumer exited during observation");
  return out;
}
std::map<unsigned, unsigned> unixPeers(Deadline deadline) {
  d::Fd fd(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG));
  if (!fd)
    fail(ActivationStatus::UnsupportedConfiguration,
         "UNIX diagnostic interface unavailable");
  timeval timeout{0, 200000};
  ::setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
  struct {
    nlmsghdr header;
    unix_diag_req request;
  } query{};
  query.header.nlmsg_len = sizeof query;
  query.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
  query.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  query.header.nlmsg_seq = 1;
  query.request.sdiag_family = AF_UNIX;
  query.request.udiag_states = ~0u;
  query.request.udiag_show = UDIAG_SHOW_PEER;
  if (::send(fd.get(), &query, sizeof query, 0) != sizeof query)
    fail(ActivationStatus::UnsupportedConfiguration,
         "UNIX diagnostics send failed");
  std::map<unsigned, unsigned> peers;
  std::size_t total = 0;
  for (;;) {
    remaining(deadline);
    pollfd readable{fd.get(), POLLIN, 0};
    const auto wait = std::min<std::int64_t>(
        20, std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now())
                .count());
    if (::poll(&readable, 1, std::max<std::int64_t>(0, wait)) <= 0)
      continue;
    alignas(nlmsghdr) char buffer[65536];
    sockaddr_nl sender{};
    socklen_t sl = sizeof sender;
    const auto n = ::recvfrom(fd.get(), buffer, sizeof buffer, MSG_DONTWAIT,
                              reinterpret_cast<sockaddr *>(&sender), &sl);
    if (n < 0) {
      if (errno == EINTR || errno == EAGAIN)
        continue;
      fail(ActivationStatus::UnsupportedConfiguration,
           "UNIX diagnostics failed");
    }
    if (sender.nl_pid || !n || (total += n) > 4 * 1024 * 1024)
      fail(ActivationStatus::UnsupportedConfiguration,
           "UNIX diagnostic bounds/peer");
    int bytes = n;
    for (auto *h = reinterpret_cast<nlmsghdr *>(buffer); NLMSG_OK(h, bytes);
         h = NLMSG_NEXT(h, bytes)) {
      if (h->nlmsg_seq != 1)
        fail(ActivationStatus::InterferenceDetected,
             "UNIX diagnostic sequence");
      if (h->nlmsg_type == NLMSG_DONE) {
        if (h->nlmsg_flags & NLM_F_DUMP_INTR)
          fail(ActivationStatus::ReadinessUnconfirmed,
               "UNIX diagnostic dump interrupted");
        return peers;
      }
      if (h->nlmsg_type == NLMSG_ERROR ||
          h->nlmsg_len < NLMSG_LENGTH(sizeof(unix_diag_msg)))
        fail(ActivationStatus::UnsupportedConfiguration,
             "UNIX diagnostic response");
      auto *msg = reinterpret_cast<unix_diag_msg *>(NLMSG_DATA(h));
      int attrs = h->nlmsg_len - NLMSG_LENGTH(sizeof(*msg));
      for (auto *a = reinterpret_cast<rtattr *>(reinterpret_cast<char *>(msg) +
                                                NLMSG_ALIGN(sizeof(*msg)));
           RTA_OK(a, attrs); a = RTA_NEXT(a, attrs))
        if (a->rta_type == UNIX_DIAG_PEER &&
            RTA_PAYLOAD(a) == sizeof(unsigned)) {
          unsigned peer;
          std::memcpy(&peer, RTA_DATA(a), sizeof peer);
          peers[msg->udiag_ino] = peer;
        }
    }
  }
}
void probeResponder(const Process &pam, Deadline deadline) {
  remaining(deadline);
  d::Fd fd(::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
  if (!fd)
    fail(ActivationStatus::ReadinessUnconfirmed, "PAM protocol socket");
  int yes = 1;
  if (::setsockopt(fd.get(), SOL_SOCKET, SO_PASSCRED, &yes, sizeof yes))
    fail(ActivationStatus::UnsupportedConfiguration,
         "PAM credential proof unavailable");
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  std::strcpy(address.sun_path, pam.evidence.role == "pam"
                                    ? "/var/lib/sss/pipes/pam"
                                    : "/var/lib/sss/pipes/nss");
  if (::connect(fd.get(), reinterpret_cast<sockaddr *>(&address),
                sizeof address) &&
      errno != EINPROGRESS)
    fail(ActivationStatus::ReadinessUnconfirmed, "PAM responder not listening");
  std::uint32_t query[]{16, 1, 0, 0};
  std::size_t sent = 0;
  unsigned char response[20];
  std::size_t received = 0;
  while (received < sizeof response) {
    remaining(deadline);
    pollfd p{fd.get(),
             static_cast<short>(sent < sizeof query ? POLLOUT : POLLIN), 0};
    const auto wait = std::min<std::int64_t>(
        20, std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now())
                .count());
    if (::poll(&p, 1, std::max<std::int64_t>(0, wait)) <= 0)
      continue;
    if (p.revents & (POLLERR | POLLHUP | POLLNVAL))
      fail(ActivationStatus::ReadinessUnconfirmed, "PAM protocol disconnected");
    if (sent < sizeof query) {
      const auto n = ::send(fd.get(), reinterpret_cast<char *>(query) + sent,
                            sizeof query - sent, MSG_NOSIGNAL);
      if (n < 0) {
        if (errno == EAGAIN || errno == EINTR)
          continue;
        fail(ActivationStatus::ReadinessUnconfirmed, "PAM version send");
      }
      sent += n;
      continue;
    }
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(ucred))];
    iovec io{response + received, sizeof response - received};
    msghdr message{};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    const auto n = ::recvmsg(fd.get(), &message, 0);
    if (n < 0 && (errno == EAGAIN || errno == EINTR))
      continue;
    if (n <= 0 || message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
      fail(ActivationStatus::ReadinessUnconfirmed, "PAM version reply bounds");
    bool credentials = false;
    for (auto *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c))
      if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS &&
          c->cmsg_len == CMSG_LEN(sizeof(ucred))) {
        ucred peer{};
        std::memcpy(&peer, CMSG_DATA(c), sizeof peer);
        credentials = peer.pid == pam.evidence.pid &&
                      peer.uid == pam.evidence.uid &&
                      peer.gid == pam.evidence.gid;
      }
    if (!credentials)
      fail(ActivationStatus::ReadinessUnconfirmed,
           "PAM response not from proven consumer generation");
    received += n;
  }
  std::uint32_t fields[5];
  std::memcpy(fields, response, sizeof fields);
  if (fields[0] != 20 || fields[1] != 1 || fields[2] || fields[3] ||
      fields[4] != (pam.evidence.role == "pam" ? 3u : 1u))
    fail(ActivationStatus::UnsupportedConfiguration,
         "unsupported PAM GET_VERSION response");
}
std::string trim(std::string s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == s.npos)
    return {};
  return s.substr(first, s.find_last_not_of(" \t\r\n") - first + 1);
}
std::string busQuery(const std::string &destination, const std::string &path,
                     const std::string &method, const std::string &argument,
                     Deadline deadline) {
  auto result =
      execute("/usr/bin/dbus-send",
              {"--bus=unix:path=/var/lib/sss/pipes/private/sbus-master",
               "--print-reply=literal",
               "--reply-timeout=" +
                   std::to_string(std::max<std::int64_t>(
                       1, std::chrono::duration_cast<std::chrono::milliseconds>(
                              deadline - std::chrono::steady_clock::now())
                              .count())),
               "--dest=" + destination, path, method, "string:" + argument},
              deadline);
  return trim(result.standardOutput);
}
d::Fd trustedNativeDirectory(std::initializer_list<const char *> components,
                             uid_t nativeUid, gid_t nativeGid) {
  auto directory = d::openAbsolute("/var/lib", O_PATH | O_DIRECTORY);
  const auto validate = [&] {
    const auto id = d::identity(directory.get());
    if (!S_ISDIR(id.mode) || (id.uid != 0 && id.uid != nativeUid) ||
        (id.mode & 0002) ||
        ((id.mode & 0020) && (nativeUid == 0 || id.gid != nativeGid)))
      fail(ActivationStatus::UnsupportedConfiguration,
           "untrusted native state directory");
    d::Fd readable(::openat(directory.get(), ".",
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!readable)
      fail(ActivationStatus::UnsupportedConfiguration,
           "native state directory inaccessible");
    // A service-group writable directory is trusted only for that principal;
    // named ACL entries must not silently grant another principal write access.
    for (const auto *name :
         {"system.posix_acl_access", "system.posix_acl_default"}) {
      char value;
      errno = 0;
      const auto n = ::fgetxattr(readable.get(), name, &value, 1);
      if (n >= 0 || errno == ERANGE)
        fail(ActivationStatus::UnsupportedConfiguration,
             "native state directory ACL unsupported");
      if (errno != ENODATA && errno != EOPNOTSUPP)
        fail(ActivationStatus::UnsupportedConfiguration,
             "native state directory ACL visibility unproven");
    }
    if (!d::sameObject(id, d::identity(readable.get())))
      fail(ActivationStatus::InterferenceDetected,
           "native state directory changed");
  };
  validate();
  for (const auto *component : components) {
    d::Fd child(::openat(directory.get(), component,
                         O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!child)
      fail(ActivationStatus::UnsupportedConfiguration,
           "native state directory unavailable");
    directory = std::move(child);
    validate();
  }
  return directory;
}
void probeBackend(Process &backend, const Process &monitor, Deadline deadline) {
  const std::string path = "/var/lib/sss/pipes/private/sbus-master";
  auto parent = trustedNativeDirectory(
      {"sss", "pipes", "private"}, monitor.evidence.uid, monitor.evidence.gid);
  auto socketObject = d::Fd(
      ::openat(parent.get(), "sbus-master", O_PATH | O_NOFOLLOW | O_CLOEXEC));
  if (!socketObject)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "central bus socket unavailable");
  const auto identity = d::identity(socketObject.get());
  if (!S_ISSOCK(identity.mode) ||
      (identity.uid != 0 && identity.uid != monitor.evidence.uid) ||
      (identity.mode & 0002))
    fail(ActivationStatus::UnsupportedConfiguration,
         "central bus socket object untrusted");
  d::Fd socket(
      ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  std::strcpy(address.sun_path, path.c_str());
  if (!socket || ::connect(socket.get(), reinterpret_cast<sockaddr *>(&address),
                           sizeof address))
    fail(ActivationStatus::ReadinessUnconfirmed,
         "central bus connection unavailable");
  ucred peer{};
  socklen_t size = sizeof peer;
  if (::getsockopt(socket.get(), SOL_SOCKET, SO_PEERCRED, &peer, &size) ||
      size != sizeof peer || peer.pid != monitor.evidence.pid ||
      peer.uid != monitor.evidence.uid || peer.gid != monitor.evidence.gid)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "central bus is not the proven monitor generation");
  const auto owner =
      busQuery("org.freedesktop.DBus", "/org/freedesktop/DBus",
               "org.freedesktop.DBus.GetNameOwner",
               backendBusName(backend.evidence.domain), deadline);
  if (!validBusOwner(owner))
    fail(ActivationStatus::ReadinessUnconfirmed,
         "backend unique bus owner unproven");
  const auto expected = "uint32 " + std::to_string(backend.evidence.pid);
  auto pid = [&] {
    return busQuery("org.freedesktop.DBus", "/org/freedesktop/DBus",
                    "org.freedesktop.DBus.GetConnectionUnixProcessID", owner,
                    deadline);
  };
  if (pid() != expected)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "backend bus owner differs from pinned consumer");
  const auto online =
      busQuery(owner, "/sssd", "sssd.DataProvider.Backend.IsOnline",
               backend.evidence.domain, deadline);
  // IsOnline reads in-memory offline state; either value proves post-target
  // interface initialization. It does not prove LDAP reachability or auth.
  if ((online != "boolean true" && online != "boolean false") ||
      pid() != expected)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "backend post-initialization protocol not proven");
  auto after = d::openAbsolute(path, O_PATH, false);
  if (!d::sameObject(identity, d::identity(after.get())))
    fail(ActivationStatus::InterferenceDetected,
         "central bus socket changed during proof");
  trustedNativeDirectory({"sss", "pipes", "private"}, monitor.evidence.uid,
                         monitor.evidence.gid);
  backend.evidence.backendBusOwner = owner;
}
d::Fd openConfigDb(uid_t nativeUid, gid_t nativeGid) {
  auto parent = trustedNativeDirectory({"sss", "db"}, nativeUid, nativeGid);
  d::Fd file(::openat(parent.get(), "config.ldb",
                      O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
  if (!file)
    fail(ActivationStatus::ReadinessUnconfirmed, "ConfigDB unavailable");
  return file;
}
void verifyPidFile(const SssdLaunchReference &launch,
                   const std::string &mainPid) {
  if (launch.profile.pidFile.empty())
    return;
  auto file = d::openAbsolute(launch.profile.pidFile, O_RDONLY);
  struct stat st {};
  char bytes[33];
  const auto n = ::read(file.get(), bytes, sizeof bytes);
  if (::fstat(file.get(), &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
      st.st_nlink != 1 || (st.st_mode & 0022) || n <= 0 || n == sizeof bytes)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "native PIDFile object unproven");
  const std::string text(bytes, n);
  if (text != mainPid && text != mainPid + "\n")
    fail(ActivationStatus::ReadinessUnconfirmed,
         "native PIDFile differs from confirmed monitor");
}
std::string dbGeneration(const d::Identity &id, uid_t nativeUid,
                         gid_t nativeGid) {
  auto fd = openConfigDb(nativeUid, nativeGid);
  struct stat st {};
  if (::fstat(fd.get(), &st) || !d::sameObject(id, d::identity(fd.get())) ||
      st.st_nlink != 1 || !S_ISREG(st.st_mode) || (st.st_mode & 0077))
    fail(ActivationStatus::InterferenceDetected,
         "ConfigDB object/metadata changed");
  const auto bytes =
      read("/proc/self/fd/" + std::to_string(fd.get()), 64 * 1024 * 1024);
  return J::array({id.device, id.inode, id.mount, st.st_uid, st.st_gid,
                   st.st_mode, st.st_size, st.st_mtim.tv_sec,
                   st.st_mtim.tv_nsec, st.st_ctim.tv_sec, st.st_ctim.tv_nsec,
                   fic::core::ContentDigest::sha256Hex(bytes)})
      .dump();
}
} // namespace
std::string backendBusName(const std::string &domain) {
  std::string out = "sssd.domain_";
  const char *hex = "0123456789abcdef";
  for (unsigned char c : domain) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9'))
      out += c;
    else {
      out += '_';
      out += hex[c >> 4];
      out += hex[c & 15];
    }
  }
  return out;
}
bool validBusOwner(const std::string &owner) {
  const auto dot = owner.find('.');
  return owner.size() >= 4 && owner.size() <= 64 && owner[0] == ':' &&
         dot > 1 && dot != owner.npos && dot == owner.rfind('.') &&
         dot + 1 < owner.size() &&
         owner.find_first_not_of("0123456789.", 1) == owner.npos;
}
DbRecords parseConfigDb(const std::string &text) {
  if (text.size() > 1024 * 1024)
    fail(ActivationStatus::UnsupportedConfiguration, "ConfigDB query limit");
  DbRecords out;
  std::istringstream in(text);
  std::string line, dn;
  std::string *last = nullptr;
  while (std::getline(in, line)) {
    if (line.empty()) {
      dn.clear();
      last = nullptr;
      continue;
    }
    if (line[0] == '#')
      continue;
    if (line[0] == ' ') {
      if (!last)
        fail(ActivationStatus::UnsupportedConfiguration,
             "invalid LDIF continuation");
      *last += line.substr(1);
      continue;
    }
    const auto colon = line.find(": ");
    if (colon == line.npos || line.find("::") != line.npos)
      fail(ActivationStatus::UnsupportedConfiguration,
           "unsupported ConfigDB LDIF");
    auto key = line.substr(0, colon), value = line.substr(colon + 2);
    for (auto &c : key)
      if (c >= 'A' && c <= 'Z')
        c += 32;
    if (key == "dn") {
      dn = value;
      if (out.count(dn))
        fail(ActivationStatus::UnsupportedConfiguration,
             "duplicate ConfigDB entry");
      out[dn];
      last = nullptr;
    } else {
      if (dn.empty() || out[dn].count(key))
        fail(ActivationStatus::UnsupportedConfiguration,
             "ambiguous ConfigDB value");
      last = &out[dn].emplace(key, value).first->second;
    }
  }
  return out;
}
std::string domainDn(const std::string &name) {
  if (name.empty() ||
      name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW"
                             "XYZ0123456789._-") != name.npos)
    fail(ActivationStatus::UnsupportedConfiguration,
         "unsupported native domain DN");
  return "cn=" + name + ",cn=domain,cn=config";
}
NativeRuntimeContract
nativePreflight(const SssdVerifiedActivationRequest &request,
                const EffectiveConfiguration &cfg, Deadline deadline) {
  NativeRuntimeContract out;
  out.launch = request.input.launch;
  const auto platform = request.input.launch.profile.platform;
  const std::map<std::string, std::string> versions{{"debian-12", "2.8.2"},
                                                    {"debian-13", "2.10.1"},
                                                    {"ubuntu-24.04", "2.9.4"},
                                                    {"ubuntu-26.04", "2.12.0"},
                                                    {"alt-p11", "2.9.8"}};
  if (!versions.count(platform))
    fail(ActivationStatus::UnsupportedConfiguration,
         "unreviewed native source version");
  auto version =
      execute("/usr/sbin/sssd", {"--version"}, deadline).standardOutput;
  while (!version.empty() && (version.back() == '\n' || version.back() == '\r'))
    version.pop_back();
  if (version != versions.at(platform))
    fail(ActivationStatus::UnsupportedConfiguration,
         "native source version mismatch");
  out.sourceContract =
      "SSSD/" + platform + "/" + version + "/I3-source-causal-v1";
  const std::map<std::string, std::string> releases{
      {"debian-12", "2.8.2-4+deb12u1"},
      {"debian-13", "2.10.1-2+b1"},
      {"ubuntu-24.04", "2.9.4-1.1ubuntu6.8"},
      {"ubuntu-26.04", "2.12.0-1ubuntu5.5"},
      {"alt-p11", "2.9.8-alt3"}};
  fic::platform::PlatformExecutableResolver resolver(
      fic::platform::makeBuildPlatformProfile().executables);
  std::filesystem::path packageTool;
  std::string packageError;
  if (!resolver.resolve(fic::platform::ExecutableId::PackageQuery, packageTool,
                        packageError))
    fail(ActivationStatus::UnsupportedConfiguration,
         "native package query unavailable");
  const bool alt = platform == "alt-p11";
  const auto packageEvidence =
      execute(
          packageTool.string(),
          alt ? std::vector<std::string>{"-q", "--qf",
                                         "%{NAME} %{VERSION}-%{RELEASE}\n",
                                         "sssd", "sssd-ldap"}
              : std::vector<std::string>{"-W",
                                         "-f=${binary:Package} ${Version}\n",
                                         "sssd-common", "sssd-ldap"},
          deadline)
          .standardOutput;
  const auto expectedPackages = std::string(alt ? "sssd " : "sssd-common ") +
                                releases.at(platform) + "\nsssd-ldap " +
                                releases.at(platform) + "\n";
  if (packageEvidence != expectedPackages)
    fail(ActivationStatus::UnsupportedConfiguration,
         "unreviewed native SSSD package revision");
  out.sourceContract += "/" + releases.at(platform);
  if (platform == "ubuntu-26.04" || platform == "alt-p11") {
    passwd entry{}, *user = nullptr;
    char buffer[16384];
    if (::getpwnam_r(platform == "alt-p11" ? "_sssd" : "sssd", &entry, buffer,
                     sizeof buffer, &user) ||
        !user || user->pw_uid == 0)
      fail(ActivationStatus::UnsupportedConfiguration,
           "native service identity unavailable");
    out.uid = user->pw_uid;
    out.gid = user->pw_gid;
  }
  verifyPidFile(
      request.input.launch,
      std::to_string(
          typed(request.input.launch.contract, "MainPID").get<unsigned>()));
  for (const auto &expectation : request.expectations)
    if (expectation.key.key != "account_cache_expiration")
      out.needsPam = true;
  if (out.needsPam) {
    const auto section = request.input.ini.find("sssd");
    if (section == request.input.ini.end() ||
        !section->second.count("services"))
      fail(ActivationStatus::UnsupportedConfiguration,
           "required dormant/lazy PAM responder has no proven initialization "
           "profile");
    std::istringstream services(section->second.at("services").value);
    std::string name;
    bool found = false;
    while (std::getline(services, name, ',')) {
      name.erase(0, name.find_first_not_of(" \t"));
      name.erase(name.find_last_not_of(" \t") + 1);
      if (name == "pam")
        found = true;
    }
    if (!found)
      fail(ActivationStatus::UnsupportedConfiguration,
           "selected semantics require configured PAM consumer; lazy-only "
           "profile unproven");
  }
  out.needsBackendProtocol =
      platform == "debian-13" || platform == "ubuntu-26.04";
  if (out.needsBackendProtocol)
    trustedNativeDirectory({"sss", "pipes", "private"}, out.uid, out.gid);
  for (const auto &[name, st] :
       request.input.sources.at("/etc/sssd").tree.attributes) {
    if (platform == "ubuntu-26.04" &&
        (st.st_uid != 0 || st.st_gid != out.gid || !(st.st_mode & 0040) ||
         (S_ISDIR(st.st_mode) && !(st.st_mode & 0010))))
      fail(ActivationStatus::UnsupportedConfiguration,
           "native nonroot metadata must be prepared before RO publication");
    if (platform == "debian-13" && (st.st_gid != 0 || !(st.st_mode & 0040)))
      fail(ActivationStatus::UnsupportedConfiguration,
           "native root precommand metadata not prepared");
  }
  std::string error;
  if (!CommandHashStore::verifyHash("/usr/bin/ldbsearch", error))
    fail(ActivationStatus::UnsupportedConfiguration,
         "read-only native ConfigDB tool trust missing: " + error);
  auto root = d::openAbsolute("/", O_PATH | O_DIRECTORY);
  std::uint64_t budget = 128 * 1024 * 1024;
  for (const auto &[path, fingerprint] : request.input.launch.executables)
    out.code[path] = fingerprint;
  out.code["/usr/bin/ldbsearch"] =
      d::fingerprintUnitSource(root.get(), "/usr/bin/ldbsearch", budget);
  const std::string libs = platform == "alt-p11"
                               ? "/usr/lib64/sssd/"
                               : "/usr/lib/x86_64-linux-gnu/sssd/";
  for (const auto &name : {"libsss_ldap.so", "libsss_ldap_common.so"})
    out.code[libs + name] =
        d::fingerprintUnitSource(root.get(), libs + name, budget);
  if (out.needsBackendProtocol) {
    if (!CommandHashStore::verifyHash("/usr/bin/dbus-send", error))
      fail(ActivationStatus::UnsupportedConfiguration,
           "native backend protocol query tool trust missing: " + error);
    out.code["/usr/bin/dbus-send"] =
        d::fingerprintUnitSource(root.get(), "/usr/bin/dbus-send", budget);
  }
  if (cfg.scope.data().enabled.size() > 64)
    fail(ActivationStatus::UnsupportedConfiguration,
         "native domain proof limit");
  return out;
}
void verifyNativeCode(const NativeRuntimeContract &contract) {
  detail_i1::verifyExecutables(contract.launch);
  auto root = d::openAbsolute("/", O_PATH | O_DIRECTORY);
  std::uint64_t budget = 128 * 1024 * 1024;
  for (const auto &[path, expected] : contract.code) {
    if (path.rfind("/bin/", 0) == 0)
      continue; // I1 pins closed native aliases via fresh admission.
    if (d::fingerprintUnitSource(root.get(), path, budget) != expected)
      fail(ActivationStatus::InterferenceDetected,
           "native code source changed");
  }
}
void proveRuntime(const SssdVerifiedActivationRequest &request,
                  const EffectiveConfiguration &cfg,
                  const NativeRuntimeContract &contract,
                  const d::ServiceState &ready, Deadline deadline,
                  SssdVerifiedActivationResult &result) {
  remaining(deadline);
  const auto launch = admit(deadline);
  const auto old = typed(request.input.launch.contract, "InvocationID");
  const auto current = typed(launch.contract, "InvocationID");
  std::string hexInvocation;
  const char *hex = "0123456789abcdef";
  for (const auto &value : current) {
    auto b = value.get<unsigned>();
    if (b > 255)
      fail(ActivationStatus::ReadinessUnconfirmed, "invocation byte invalid");
    hexInvocation += hex[b >> 4];
    hexInvocation += hex[b & 15];
  }
  if (hexInvocation != ready.at("InvocationID") || current == old ||
      typed(launch.contract, "MainPID").get<unsigned>() !=
          std::stoul(ready.at("MainPID")))
    fail(ActivationStatus::ReadinessUnconfirmed,
         "monitor generation does not match restart result");
  if (configurationOnly(launch.contract) !=
      configurationOnly(request.input.launch.contract))
    fail(ActivationStatus::InterferenceDetected,
         "native launch configuration changed");
  auto db = openConfigDb(contract.uid, contract.gid);
  const auto dbId = d::identity(db.get());
  if (dbId.uid != 0 && dbId.uid != contract.uid)
    fail(ActivationStatus::UnsupportedConfiguration,
         "ConfigDB owner outside native identity");
  verifyPidFile(launch, ready.at("MainPID"));
  const auto generation = dbGeneration(dbId, contract.uid, contract.gid);
  auto monitor = process(std::stoul(ready.at("MainPID")), "/usr/sbin/sssd",
                         dbId, contract);
  monitor.evidence.role = "monitor";
  const auto separator = request.input.launch.processIdentity.find(
      ':', request.input.launch.processIdentity.find(':') + 1);
  if (separator == std::string::npos ||
      monitor.evidence.startToken ==
          request.input.launch.processIdentity.substr(0, separator))
    fail(ActivationStatus::ReadinessUnconfirmed,
         "monitor start token did not change");
  const auto expectedMonitorUid =
      request.input.launch.profile.platform == "ubuntu-26.04" ? contract.uid
                                                              : 0;
  const auto expectedMonitorGid =
      request.input.launch.profile.platform == "ubuntu-26.04" ? contract.gid
                                                              : 0;
  if (monitor.evidence.parent != 1 ||
      monitor.evidence.uid != expectedMonitorUid ||
      monitor.evidence.gid != expectedMonitorGid)
    fail(ActivationStatus::UnsupportedConfiguration,
         "monitor identity differs from native unit");
  result.activation = SssdProofState::Proven;
  result.newInvocation = ready.at("InvocationID");
  result.processes.push_back(monitor.evidence);
  std::vector<Process> children;
  std::map<std::string, std::size_t> backends;
  std::optional<std::size_t> pam;
  DIR *raw = ::opendir("/proc");
  if (!raw)
    fail(ActivationStatus::ReadinessUnconfirmed, "proc enumeration");
  std::unique_ptr<DIR, DirCloser> listing(raw);
  unsigned total = 0;
  while (auto *e = ::readdir(raw)) {
    remaining(deadline);
    if (e->d_name[0] < '0' || e->d_name[0] > '9')
      continue;
    if (++total > 32768)
      fail(ActivationStatus::UnsupportedConfiguration,
           "process enumeration bound");
    const auto pid = std::stoi(e->d_name);
    if (pid == monitor.evidence.pid)
      continue;
    try {
      const auto stat = read("/proc/" + std::to_string(pid) + "/stat", 8192);
      const auto end = stat.rfind(')');
      std::istringstream fields(stat.substr(end + 1));
      std::string state;
      int parent;
      fields >> state >> parent;
      if (parent != monitor.evidence.pid)
        continue;
      char link[4096];
      const auto n = ::readlink(
          ("/proc/" + std::to_string(pid) + "/exe").c_str(), link, sizeof link);
      if (n <= 0 || n == sizeof link)
        continue;
      const std::string exe(link, n);
      if (exe != "/usr/libexec/sssd/sssd_be" &&
          !(contract.needsPam && exe == "/usr/libexec/sssd/sssd_pam"))
        continue;
      auto child = process(pid, exe, dbId, contract);
      if (child.evidence.uid != contract.uid ||
          child.evidence.gid != contract.gid)
        fail(ActivationStatus::UnsupportedConfiguration,
             "consumer differs from native configuration identity");
      if (std::stoull(child.evidence.startToken.substr(
              child.evidence.startToken.find(':') + 1)) <
          std::stoull(monitor.evidence.startToken.substr(
              monitor.evidence.startToken.find(':') + 1)))
        fail(ActivationStatus::InterferenceDetected,
             "consumer predates monitor generation");
      if (exe == "/usr/libexec/sssd/sssd_be") {
        std::string domain;
        for (std::size_t i = 1; i + 1 < child.args.size(); ++i)
          if (child.args[i] == "--domain") {
            if (!domain.empty())
              fail(ActivationStatus::UnsupportedConfiguration,
                   "ambiguous backend domain");
            domain = child.args[i + 1];
          }
        if (!cfg.scope.data().domains.count(domain) ||
            !cfg.scope.data().domains.at(domain).enabled)
          fail(ActivationStatus::InterferenceDetected,
               "unexpected backend scope");
        if (backends.count(domain))
          fail(ActivationStatus::InterferenceDetected,
               "duplicate backend generation");
        child.evidence.domain = domain;
        child.evidence.role = "backend";
        backends[domain] = children.size();
        const auto maps = read("/proc/" + std::to_string(pid) + "/maps");
        for (const auto &[path, pin] : contract.code)
          if (path.find("libsss_ldap") != path.npos) {
            auto code = d::openAbsolute(path, O_RDONLY);
            const auto id = d::identity(code.get());
            bool mapped = false;
            std::istringstream lines(maps);
            std::string line;
            while (std::getline(lines, line)) {
              std::istringstream fields(line);
              std::string a, b, c, dev;
              unsigned long ino;
              if (fields >> a >> b >> c >> dev >> ino) {
                struct stat mapping {};
                if (line.find(path) != line.npos &&
                    ::stat(("/proc/" + std::to_string(pid) + "/map_files/" + a)
                               .c_str(),
                           &mapping) == 0 &&
                    mapping.st_ino == id.inode && mapping.st_dev == id.device)
                  mapped = true;
              }
            }
            if (!mapped)
              fail(ActivationStatus::ReadinessUnconfirmed,
                   "LDAP constructor code mapping absent");
          }
      } else if (exe == "/usr/libexec/sssd/sssd_pam") {
        if (pam)
          fail(ActivationStatus::InterferenceDetected,
               "duplicate PAM generation");
        pam = children.size();
        child.evidence.role = "pam";
      }
      children.push_back(std::move(child));
    } catch (const d::Failure &e) {
      if (e.status == ActivationStatus::InterferenceDetected ||
          e.status == ActivationStatus::UnsupportedConfiguration)
        throw;
    }
  }
  if (backends.size() != cfg.scope.data().enabled.size() ||
      (contract.needsPam && !pam))
    fail(ActivationStatus::ReadinessUnconfirmed,
         "required initialized consumers missing");
  const auto peers = unixPeers(deadline);
  for (auto &child : children) {
    bool connected = false;
    for (auto socket : child.sockets) {
      auto peer = peers.find(socket);
      if (peer != peers.end() && monitor.sockets.count(peer->second) &&
          peers.count(peer->second) && peers.at(peer->second) == socket) {
        connected = true;
        child.evidence.consumerSocket = socket;
        child.evidence.monitorSocket = peer->second;
      }
    }
    if (!connected)
      fail(ActivationStatus::ReadinessUnconfirmed,
           "consumer has no verified post-initialization monitor connection");
    child.evidence.initializationConfirmed = true;
  }
  if (pam)
    probeResponder(children.at(*pam), deadline);
  if (contract.needsBackendProtocol)
    for (auto &child : children)
      if (child.evidence.role == "backend")
        probeBackend(child, monitor, deadline);
  // ldbsearch opens TDB read-write even for a search (and TDB recovery can
  // write). Never grant it the live ConfigDB pathname. Query a bounded private
  // memory copy and reject any native recovery/modification of that copy.
  const auto dbBytes =
      read("/proc/self/fd/" + std::to_string(db.get()), 64 * 1024 * 1024);
  if (dbGeneration(dbId, contract.uid, contract.gid) != generation)
    fail(ActivationStatus::InterferenceDetected,
         "ConfigDB changed before read-only query copy");
  d::Fd queryCopy(::syscall(SYS_memfd_create, "fic-sssd-configdb-query",
                            MFD_CLOEXEC | MFD_ALLOW_SEALING));
  if (!queryCopy)
    fail(ActivationStatus::UnsupportedConfiguration,
         "bounded ConfigDB query copy unavailable");
  std::size_t written = 0;
  while (written < dbBytes.size()) {
    remaining(deadline);
    const auto n = ::write(queryCopy.get(), dbBytes.data() + written,
                           dbBytes.size() - written);
    if (n <= 0) {
      if (n < 0 && errno == EINTR)
        continue;
      fail(ActivationStatus::ReadinessUnconfirmed, "query copy write failed");
    }
    written += n;
  }
  if (::fcntl(queryCopy.get(), F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK))
    fail(ActivationStatus::UnsupportedConfiguration,
         "query copy size seal unavailable");
  const auto copyPath = "/proc/" + std::to_string(::getpid()) + "/fd/" +
                        std::to_string(queryCopy.get());
  const auto query =
      execute("/usr/bin/ldbsearch",
              {"-H", copyPath, "-b", "cn=config", "-s", "sub", "(cn=*)", "cn",
               "domains", "enabled", "id_provider", "auth_provider",
               "offline_credentials_expiration", "cache_credentials",
               "account_cache_expiration", "cached_auth_timeout"},
              deadline);
  if (read(copyPath, 64 * 1024 * 1024) != dbBytes)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "native query modified private ConfigDB copy; no live ConfigDB write "
         "allowed");
  const auto records = parseConfigDb(query.standardOutput);
  // Project only queried non-secret structural/semantic attributes, preserving
  // native defaults.
  IniProjection observed;
  for (const auto &[dn, attrs] : records) {
    std::string section;
    if (dn == "cn=sssd,cn=config")
      section = "sssd";
    else if (dn == "cn=pam,cn=config")
      section = "pam";
    else if (dn.rfind("cn=", 0) == 0 && dn.size() > 23 &&
             dn.substr(dn.size() - 20) == ",cn=domain,cn=config") {
      const auto name = dn.substr(3, dn.size() - 23);
      if (domainDn(name) != dn)
        fail(ActivationStatus::ReadinessUnconfirmed,
             "noncanonical ConfigDB domain DN");
      section = "domain/" + name;
    }
    if (section.empty())
      continue;
    for (const auto &[key, value] : attrs)
      if (key != "cn")
        observed[section][key] = {value, "ConfigDB:" + dn};
  }
  const auto values =
      detail_i2::effectiveProjection(request.input, observed, nullptr);
  if (values.scope.data().configured != cfg.scope.data().configured ||
      values.scope.data().selected != cfg.scope.data().selected ||
      values.scope.data().enabled != cfg.scope.data().enabled ||
      !validateRelations(values).semanticProjectionValidated())
    fail(ActivationStatus::ReadinessUnconfirmed,
         "ConfigDB selected semantic scope differs");
  if (!sameValue(values.offlineDays.value, cfg.offlineDays.value))
    fail(ActivationStatus::ReadinessUnconfirmed,
         "global ConfigDB dependency differs");
  for (const auto &name : cfg.scope.data().enabled) {
    const auto &a = values.domains.at(name);
    const auto &b = cfg.domains.at(name);
    const auto &ad = values.scope.data().domains.at(name);
    const auto &bd = cfg.scope.data().domains.at(name);
    if (ad.idProvider != bd.idProvider || ad.authProvider != bd.authProvider ||
        ad.enabledSetting != bd.enabledSetting ||
        !sameValue(a.cacheCredentials.value, b.cacheCredentials.value) ||
        !sameValue(a.accountDays.value, b.accountDays.value) ||
        !sameValue(a.cachedAuthSeconds.value, b.cachedAuthSeconds.value))
      fail(ActivationStatus::ReadinessUnconfirmed,
           "ConfigDB domain dependency generation differs");
  }
  for (const auto &expectation : request.expectations) {
    const EffectiveValue *actual = nullptr;
    const EffectiveValue *expected = nullptr;
    if (expectation.key.section == "pam") {
      actual = &values.offlineDays;
      expected = &cfg.offlineDays;
    } else {
      const auto name = expectation.key.section.substr(7);
      const auto &a = values.domains.at(name);
      const auto &b = cfg.domains.at(name);
      if (expectation.key.key == "cache_credentials") {
        actual = &a.cacheCredentials;
        expected = &b.cacheCredentials;
      } else if (expectation.key.key == "account_cache_expiration") {
        actual = &a.accountDays;
        expected = &b.accountDays;
      } else {
        actual = &a.cachedAuthSeconds;
        expected = &b.cachedAuthSeconds;
      }
    }
    if (!sameValue(actual->value, expected->value))
      fail(ActivationStatus::ReadinessUnconfirmed,
           "selected ConfigDB value differs from protected graph");
    auto add = [&](const Process &p, const std::string &moment,
                   const std::string &scope, SemanticValue consumer) {
      result.parameters.push_back({expectation.key, expected->value,
                                   std::move(consumer), p.evidence.role,
                                   p.evidence.startToken, generation,
                                   contract.sourceContract, moment, scope});
    };
    for (const auto &[domain, index] : backends)
      if (expectation.key.section == "pam" ||
          expectation.key.section == "domain/" + domain)
        add(children[index], "initialization",
            (expectation.key.key == "account_cache_expiration"
                 ? "sdap_get_options -> ldap_id_cleanup (options initialized; "
                   "cleanup execution not claimed)"
             : expectation.key.key == "offline_credentials_expiration"
                 ? "sdap_get_options (LDAP relation validation only)"
                 : "sssd_domain_init -> confdb_get_domain_internal (domain "
                   "options initialized)"),
            expected->value);
    if (pam && expectation.key.key != "account_cache_expiration") {
      SemanticValue consumer = expected->value;
      if (expectation.key.key == "cached_auth_timeout")
        consumer = *cfg.domains.at(expectation.key.section.substr(7))
                        .expectedCachedAuthSeconds;
      add(children.at(*pam),
          expectation.key.key == "offline_credentials_expiration"
              ? "request-time"
              : "initialization then request-time",
          (expectation.key.key == "offline_credentials_expiration"
               ? "pamsrv_cmd -> sysdb_cache_auth -> CONFDB_PAM_CRED_TIMEOUT "
                 "(future request; no authentication executed)"
               : "sss_process_init -> confdb_get_domains -> pamsrv_cmd "
                 "cached-auth checks (future request; no authentication "
                 "executed)"),
          consumer);
    }
  }
  if (dbGeneration(dbId, contract.uid, contract.gid) != generation)
    fail(ActivationStatus::InterferenceDetected,
         "ConfigDB changed during consumer proof");
  for (auto &child : children) {
    auto again =
        process(child.evidence.pid, child.evidence.executable, dbId, contract);
    if (again.evidence.startToken != child.evidence.startToken ||
        again.evidence.parent != monitor.evidence.pid ||
        !again.sockets.count(child.evidence.consumerSocket))
      fail(ActivationStatus::ReadinessUnconfirmed,
           "consumer generation/connection changed");
  }
  auto confirmedMonitor =
      process(monitor.evidence.pid, "/usr/sbin/sssd", dbId, contract);
  const auto confirmedPeers = unixPeers(deadline);
  for (const auto &child : children)
    if (!confirmedMonitor.sockets.count(child.evidence.monitorSocket) ||
        !confirmedPeers.count(child.evidence.consumerSocket) ||
        confirmedPeers.at(child.evidence.consumerSocket) !=
            child.evidence.monitorSocket)
      fail(ActivationStatus::ReadinessUnconfirmed,
           "monitor connection changed during proof");
  auto again = admit(deadline);
  if (again.processIdentity != launch.processIdentity)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "monitor changed during semantic proof");
  verifyNativeCode(contract);
  monitor.evidence.initializationConfirmed = true;
  result.processes.at(0) = monitor.evidence;
  for (const auto &child : children)
    result.processes.push_back(child.evidence);
  result.newInvocation = ready.at("InvocationID");
  result.configDbGeneration = generation;
  result.nativeCode = contract.code;
}
void confirmRuntime(const NativeRuntimeContract &contract,
                    const SssdVerifiedActivationResult &result,
                    Deadline deadline) {
  remaining(deadline);
  auto db = openConfigDb(contract.uid, contract.gid);
  const auto id = d::identity(db.get());
  if (dbGeneration(id, contract.uid, contract.gid) != result.configDbGeneration)
    fail(ActivationStatus::ReadinessUnconfirmed,
         "ConfigDB generation changed after cleanup");
  const auto peers = unixPeers(deadline);
  std::set<unsigned> monitorSockets;
  for (const auto &expected : result.processes) {
    remaining(deadline);
    auto current = process(expected.pid, expected.executable, id, contract);
    if (current.evidence.startToken != expected.startToken ||
        current.evidence.parent != expected.parent ||
        current.evidence.uid != expected.uid ||
        current.evidence.gid != expected.gid)
      fail(ActivationStatus::ReadinessUnconfirmed,
           "consumer generation changed after cleanup");
    if (expected.role == "monitor")
      monitorSockets = current.sockets;
    if (expected.role != "monitor" &&
        (!monitorSockets.count(expected.monitorSocket) ||
         !current.sockets.count(expected.consumerSocket) ||
         !peers.count(expected.consumerSocket) ||
         peers.at(expected.consumerSocket) != expected.monitorSocket ||
         !peers.count(expected.monitorSocket) ||
         peers.at(expected.monitorSocket) != expected.consumerSocket))
      fail(ActivationStatus::ReadinessUnconfirmed,
           "consumer connection changed after cleanup");
  }
  verifyNativeCode(contract);
}

} // namespace fic::service::sssd::detail_i3
