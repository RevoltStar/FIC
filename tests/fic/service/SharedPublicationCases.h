#pragma once
#include "service/VerifiedConfigActivationProof.h"

// Closed internal proof fixture; the public/default entrypoint remains strict.
d::ActivationProof sharedProof(const ActivationRequest& r) {
    d::ActivationProof p;
    p.propagation = d::PublicationPropagationPolicy::AllowKnownShared;
    d::SystemdActivation service(r.unit, std::chrono::steady_clock::now()+r.timeout, r.paths);
    p.expectedConfiguration = service.preflight().properties;
    for (const auto* key : {"ActiveState","SubState","MainPID","InvocationID","Job","Result"}) p.expectedConfiguration.erase(key);
    for (const auto& path : r.paths) {
        auto fd = d::openAbsolute(path.path, O_RDONLY); auto budget = r.maxSnapshotBytes;
        p.sourceRoots.emplace(path.path.string(), d::identity(fd.get()));
        p.sourceAttributes.emplace(path.path.string(), d::readTree(fd.get(),path.kind,budget).attributes);
    }
    p.published=[](auto){};
    p.ready=[r](const auto&,auto){require(matchesPublished(Json::parse(read(runRoot+"/report")),publishedIds(r)),"actual trusted reader receipt");};
    return p;
}
struct DownstreamPublication {
    d::Fd connection; pid_t pid=-1;
    static std::string packet(int fd) {
        waitFd(fd,POLLIN); std::vector<char> b(65536); auto n=::recv(fd,b.data(),b.size(),0);
        require(n>0 && size_t(n)<b.size(),"downstream bounded packet"); return {b.data(),size_t(n)};
    }
    static Json view() {
        Json v{{"fic",leftovers().size()},{"alpha",read(root+"/dropins/a.conf")}};
        d::Fd fd(::open((root+"/dropins/a.conf").c_str(),O_WRONLY|O_CLOEXEC));
        v["write_errno"]=fd?0:errno;
        return v;
    }
    explicit DownstreamPublication(bool sharedSlave, bool peer=false) {
        int pair[2]; require(::socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair)==0,"downstream socket");
        pid=::fork(); require(pid>=0,"downstream fork");
        if(!pid) {
            ::close(pair[0]);
            try {
                require(::unshare(CLONE_NEWNS)==0,"downstream namespace");
                if(!peer) require(::mount(nullptr,"/",nullptr,MS_REC|MS_SLAVE,nullptr)==0,"downstream slave");
                if(sharedSlave) for(const auto& p:{root,std::string("/run/fic")})
                    require(::mount(nullptr,p.c_str(),nullptr,MS_SHARED,nullptr)==0,"shared-slave parent");
                std::unique_ptr<DownstreamPublication> second;
                if(sharedSlave) second=std::make_unique<DownstreamPublication>(false,true);
                std::map<std::uint64_t,d::MountRecord> owned;
                std::uint64_t nested=0; const auto child=root+"/dropins/sub";
                sendPacket(pair[1],"READY");
                for(;;) {
                    auto cmd=packet(pair[1]); if(cmd=="EXIT") break;
                    if(cmd=="REMEMBER") {
                        for(const auto& m:leftovers()) owned.emplace(m.id,m);
                        if(second) second->ask("REMEMBER");
                    }
                    if(cmd=="NESTED") {
                        require(::mount("fic-test-downstream",child.c_str(),"tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,"size=1048576")==0,"nested mount on existing RO directory");
                        auto fd=d::openAbsolute(child,O_PATH|O_DIRECTORY); nested=d::identity(fd.get()).mount;
                    }
                    if(cmd=="CLEAN") {
                        if(nested) {
                            auto fd=d::openAbsolute(child,O_PATH|O_DIRECTORY);
                            require(d::identity(fd.get()).mount==nested,"nested cleanup identity"); fd=d::Fd();
                            require(::umount2(child.c_str(),0)==0,"ordinary child cleanup"); nested=0;
                        }
                        auto mounts=leftovers(); std::sort(mounts.begin(),mounts.end(),[](const auto&a,const auto&b){return a.target.size()>b.target.size();});
                        for(const auto& m:mounts) {
                            require(owned.count(m.id) && owned.at(m.id).source==m.source && owned.at(m.id).target==m.target,"no residual adoption");
                            auto fd=d::openAbsolute(m.target,O_PATH); require(d::identity(fd.get()).mount==m.id,"residual cleanup identity"); fd=d::Fd();
                            require(::umount2(m.target.c_str(),0)==0,"ordinary downstream residual cleanup");
                        }
                        if(second) second->ask("CLEAN");
                    }
                    auto v=view(); if(second) v["peer"]=second->ask("VIEW"); sendPacket(pair[1],v.dump());
                }
                second.reset(); ::_exit(0);
            } catch(const std::exception& e) { try{sendPacket(pair[1],Json{{"error",e.what()}}.dump());}catch(...){} ::_exit(1); }
        }
        ::close(pair[1]); connection=d::Fd(pair[0]); require(packet(connection.get())=="READY","downstream ready");
    }
    Json ask(const std::string& cmd) {
        sendPacket(connection.get(),cmd); auto v=Json::parse(packet(connection.get())); require(!v.contains("error"),v.dump()); return v;
    }
    ~DownstreamPublication() {
        if(pid>0) { ::send(connection.get(),"EXIT",4,MSG_NOSIGNAL); int status=0; ::waitpid(pid,&status,0); }
    }
};
void sharedPublicationCases() {
    // Only opted-in disposable native tests reach this function. No inherited
    // propagation links may connect the synthetic topology to a host.
    for(const auto& m:d::readMountInfo()) require(!m.shared&&!m.slave,"shared tests require isolated initial topology");
    const auto saved=read("/etc/systemd/system/"+unit), before=configurationDigest();
    const auto env=root+"/shared.env";write(env,"FIC_VCSA_WORD=shared\n");
    write("/etc/systemd/system/"+unit,saved+"EnvironmentFile="+env+"\n");mustCtl({"daemon-reload"});active();
    auto r=request({one(),directory(),{env,ControlledPathKind::File,digest(read(env)),{}}});
    for(int t=1;t<=4;++t) {
        for(const auto& p:{root,std::string("/run/fic")}) {
            require(::mount(p.c_str(),p.c_str(),nullptr,MS_BIND,nullptr)==0,"shared test bind");
            require(::mount(nullptr,p.c_str(),nullptr,t==4?MS_PRIVATE:MS_SHARED,nullptr)==0,"shared test propagation");
        }
        {
            DownstreamPublication downstream(t==3);
            auto proof=sharedProof(r);
            if(t==1) {
                const auto table=read("/proc/self/mountinfo");
                require(VerifiedConfigServiceActivator::activate(r).status==ActivationStatus::UnsupportedConfiguration,"public activation inherited shared authority");
                bool denied=false;try{d::validatePublicationEnvironment(r);}catch(const d::Failure&e){denied=e.status==ActivationStatus::UnsupportedConfiguration;}
                require(denied && read("/proc/self/mountinfo")==table,"default/SSSD preflight inherited shared authority");
                d::SnapshotValidationProof validation;
                validation.expectedConfiguration=proof.expectedConfiguration;validation.sourceRoots=proof.sourceRoots;validation.sourceAttributes=proof.sourceAttributes;
                unsigned calls=0;validation.validate=[&](auto){++calls;require(configurationDigest()==before,"validation snapshot bytes");};
                require(!d::validateSnapshotWithProof(r,validation).success()&&calls==0,"default validation inherited authority");
                validation.propagation=proof.propagation;
                const auto state=ctl({"show",unit,"-p","InvocationID","--value"}).standardOutput;
                require(d::validateSnapshotWithProof(r,validation).success()&&calls==1&&leftovers().empty(),"explicit shared snapshot validation");
                require(ctl({"show",unit,"-p","InvocationID","--value"}).standardOutput==state,"validation restarted service");
                pass("strict public/default preflight and validation; explicit shared validation without restart");
            }
            Gate gate; d::TestHooks hooks;
            hooks.checkpoint=[&](d::TestPhase phase,const std::string&){
                if(phase==d::TestPhase::Watching) {
                    auto v=downstream.ask("REMEMBER");require(v.at("fic")== (t==4?0:4),"unexpected downstream publication");
                    if(t!=1) downstream.ask("NESTED");
                }
                if(phase==d::TestPhase::RestartQueued){gate.beforeRead();gate.readNow();require(matchesPublished(gate.report,publishedIds(r)),"shared actual reader mount/hash");require(gate.report.at("env").at("FIC_VCSA_WORD")=="shared","protected manager EnvironmentFile");gate.notify();}
            };
            const auto result=t==4?d::activateForTests(r,hooks):d::activateWithProofForTests(r,proof,hooks);
            require(result.success()&&result.primaryStatus==ActivationStatus::Success&&result.readinessConfirmed&&result.cleanupErrors.empty()&&result.residualPaths.empty(),"shared local success contract");clean(before);
            auto v=downstream.ask("VIEW");const bool retained=t==2||t==3;
            require(v.at("fic")== (retained?1:0),"downstream nested-mount contract changed");
            if(t==3)require(v.at("peer").at("fic")==1,"shared-slave peer residual missing");
            write(root+"/dropins/a.conf","persistent-witness\n");v=downstream.ask("VIEW");
            require(v.at("alpha")== (retained?"alpha\n":"persistent-witness\n"),"persistent versus retained snapshot view");
            require(v.at("write_errno")== (retained?EROFS:0),"retained snapshot not RO");
            v=downstream.ask("CLEAN");require(v.at("fic")==0,"test downstream cleanup");if(t==3)require(v.at("peer").at("fic")==0,"test peer cleanup");
            write(root+"/dropins/a.conf","alpha\n");
            pass("shared cleanup T"+std::to_string(t)+": local success; expected downstream retention; ordinary test cleanup");
        }
        for(const auto& p:{root,std::string("/run/fic")})require(::umount2(p.c_str(),0)==0,"fixture parent cleanup");
    }
    // The container's initial mounts had no host propagation links (checked
    // above). Change only this disposable namespace, then restore it.
    require(::mount(nullptr,"/",nullptr,MS_REC|MS_SHARED,nullptr)==0,"isolated shared root/run");
    auto proof=sharedProof(r);require(d::activateWithProof(r,proof).success()&&leftovers().empty(),"shared root/run activation");
    require(::mount(nullptr,"/",nullptr,MS_REC|MS_PRIVATE,nullptr)==0,"restore isolated root propagation");
    write("/etc/systemd/system/"+unit,saved);mustCtl({"daemon-reload"});active();clean(before);
    pass("explicit trusted proof on shared root/run without directory boundaries");
}
