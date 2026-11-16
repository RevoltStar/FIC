// Included by the existing disposable systemd native fixture only.
// Child actor closes every inherited descriptor except its barrier and held file.
struct CleanupHolder {
    d::Fd control;
    pid_t child = -1;
    explicit CleanupHolder(const std::string& path) {
        int pair[2]; require(::socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, pair) == 0, "holder socketpair");
        child = ::fork(); require(child >= 0, "holder fork");
        if (!child) {
            const int file = ::open(path.c_str(), O_RDONLY|O_CLOEXEC);
            if (file < 0) ::_exit(80);
            std::vector<int> inherited;
            for (const auto& e : fs::directory_iterator("/proc/self/fd")) {
                const int fd = std::stoi(e.path().filename());
                if (fd > 2 && fd != pair[1] && fd != file) inherited.push_back(fd);
            }
            for (int fd : inherited) ::close(fd);
            sendPacket(pair[1], "HELD");
            pollfd p{pair[1], POLLIN, 0};
            if (::poll(&p, 1, 15000) <= 0) ::_exit(81);
            const auto delay = std::stoul(receive(pair[1]));
            ::usleep(delay * 1000);
            ::close(file); ::close(pair[1]); ::_exit(0);
        }
        ::close(pair[1]); control = d::Fd(pair[0]);
        require(receive(control.get()) == "HELD", "holder open barrier");
    }
    void release(unsigned delay = 0) { sendPacket(control.get(), std::to_string(delay)); }
    ~CleanupHolder() {
        if (child > 0) {
            ::send(control.get(), "0", 1, MSG_NOSIGNAL);
            int status = 0; ::waitpid(child, &status, 0);
        }
    }
};
void cleanupRetryCases() {
    const auto before = configurationDigest();
    // A retry hook is called only after the first real kernel EBUSY. Release
    // starts at that barrier, so the initial failure cannot race the timer.
    for (unsigned scenario = 0; scenario < 5; ++scenario) {
        const bool multi = scenario == 1 || scenario == 2;
        const bool persistent = scenario == 2;
        const bool primaryFailure = scenario >= 3;
        std::unique_ptr<CleanupHolder> oneHolder, dirHolder;
        std::map<std::size_t, unsigned> calls;
        std::chrono::steady_clock::time_point cleanupStart;
        d::TestHooks hooks;
        hooks.checkpoint = [&](d::TestPhase phase, const std::string&) {
            if (phase != d::TestPhase::BeforeCleanup) return;
            cleanupStart = std::chrono::steady_clock::now();
            oneHolder = std::make_unique<CleanupHolder>(root + "/one.conf");
            if (multi) dirHolder = std::make_unique<CleanupHolder>(root + "/dropins/a.conf");
        };
        hooks.fault = [&](const std::string& action, std::size_t index) {
            if (action != "umount") return 0;
            const auto count = ++calls[index];
            // reverse indices: [directory, one, workspace] or [one, workspace].
            if (count == 2) {
                if (multi && index == 0) dirHolder->release(150);
                if (index == (multi ? 1U : 0U) && !persistent && scenario != 4) oneHolder->release(350);
            }
            return 0; // Actual umount2, never synthetic EBUSY.
        };
        auto r = multi ? request({one(), directory()}) : request();
        if (primaryFailure) { write(runRoot + "/mode", "silent"); r.timeout = std::chrono::milliseconds(1000); }
        const auto result = activate(r, hooks);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - cleanupStart).count();
        const bool failCleanup = persistent || scenario == 4;
        const auto primary = primaryFailure ? ActivationStatus::TimedOut : ActivationStatus::Success;
        require(result.primaryStatus == primary, "retry changed primary status");
        require(result.status == (failCleanup ? ActivationStatus::CleanupFailed : primary), "retry final status");
        require(calls[multi ? 1 : 0] > 2, "real held FD did not cause repeated kernel EBUSY");
        if (failCleanup) {
            require(ms >= 4900 && ms < 7000, "cleanup did not use one independent five-second grace");
            require(activationDiagnostic(result).find("retry deadline exhausted; attempts=") != std::string::npos, "deadline diagnostic absent");
            require(result.residualPaths.size()==1 && result.cleanupErrors.size()==1 && result.residualPaths[0]==root+"/one.conf", "persistent busy residual/duplicate diagnostic");
            require(result.cleanupErrors[0].find("stage=umount2")!=std::string::npos && result.cleanupErrors[0].find("errno=16 ")!=std::string::npos, "persistent errno/stage");
            if(primaryFailure)require(activationDiagnostic(result).find("primaryStatus=TimedOut status=CleanupFailed")!=std::string::npos && !result.diagnostic.empty(), "primary timeout diagnostic lost");
            if (multi) require(calls[0] > 2 && calls[0] < calls[1], "other mount never got retries");
        } else {
            require(ms >= 350 && ms < 3000 && result.cleanupErrors.empty() && result.residualPaths.empty() && leftovers().empty(), "transient cleanup differs from success");
            require(calls[multi ? 2 : 1] == 1, "released workspace retried");
        }
        if (persistent) {
            const auto remaining = leftovers();
            require(std::none_of(remaining.begin(), remaining.end(), [](const auto& m) { return m.target == root + "/dropins"; }), "persistent target starved releasable mount");
        }
        std::cout << "RETRY_EVIDENCE " << Json{{"scenario",scenario},{"kernel_ebusy",true},{"elapsed_ms",ms},
            {"calls",calls},{"status",activationStatusName(result.status)},{"primary",activationStatusName(result.primaryStatus)},
            {"residual",result.residualPaths}}.dump() << std::endl;
        oneHolder.reset(); dirHolder.reset(); manualCleanup(); clean(before);
        if (primaryFailure) active();
        pass("cleanup retry real FD scenario " + std::to_string(scenario));
    }
    // Replace the target between passes, after a real EBUSY on the first pass.
    d::Fd busy; unsigned targetCalls = 0; d::TestHooks replace;
    replace.checkpoint = [&](d::TestPhase phase, const std::string&) {
        if (phase == d::TestPhase::BeforeCleanup) busy = d::openAbsolute(root + "/one.conf", O_RDONLY);
    };
    replace.fault = [&](const std::string& action, std::size_t index) {
        if (action == "umount") {
            if (index == 0) ++targetCalls;
            if (index == 1) {
                require(::mount((root + "/alternate").c_str(), (root + "/one.conf").c_str(), nullptr, MS_BIND, nullptr) == 0, "retry foreign overlay");
                busy = d::Fd();
            }
        }
        return 0;
    };
    auto result = activate(request(), replace);
    require(result.status == ActivationStatus::CleanupFailed && targetCalls == 1 && read(root + "/one.conf") == "foreign\n", "retry removed foreign mount");
    require(result.cleanupErrors.size() == 1 && result.cleanupErrors[0].find("stage=verify_identity") != std::string::npos && result.cleanupErrors[0].find("errno=") == std::string::npos, "retry mismatch used stale errno");
    require(::umount2((root + "/one.conf").c_str(), 0) == 0, "remove test overlay"); manualCleanup(); clean(before);
    pass("retry revalidates identity and preserves replacement without stale errno");
    // Non-EBUSY and immediate success perform exactly one pass, with no sleep.
    for (int error : {0, EIO, EPERM, EINVAL, ENOENT, EACCES}) {
        std::map<std::size_t,unsigned> calls; d::TestHooks hooks;
        std::chrono::steady_clock::time_point start;
        hooks.checkpoint = [&](d::TestPhase p,const std::string&) {if(p==d::TestPhase::BeforeCleanup)start=std::chrono::steady_clock::now();};
        hooks.fault = [&](const std::string& action,std::size_t index) {if(action=="umount"){++calls[index];return index==0?error:0;}return 0;};
        result=activate(request(),hooks);
        require(calls[0]==1 && calls[1]==1, "nonbusy or success retried");
        require(std::chrono::steady_clock::now()-start<std::chrono::seconds(1), "unnecessary cleanup wait");
        require(error ? result.status==ActivationStatus::CleanupFailed && result.cleanupErrors.size()==1 && result.cleanupErrors[0].find("errno="+std::to_string(error)+" ")!=std::string::npos : result.success()&&result.cleanupErrors.empty()&&result.residualPaths.empty(), "nonbusy result/errno");
        manualCleanup();clean(before);pass("one-pass cleanup errno="+std::to_string(error));
    }
}
