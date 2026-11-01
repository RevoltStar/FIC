#pragma once
#include "rollback/MutationRecord.h"
#include "service/sssd/SssdRuntimeProof.h"

namespace fic::service::sssd::detail_i6 {
inline rollback::SssdReleaseRuntimeReceipt captureReceipt(const SssdVerifiedActivationResult& proof) {
    if(!proof.success()||proof.processes.empty())
        throw std::runtime_error("SSSD runtime receipt requires successful nonempty I3 proof");
    rollback::SssdReleaseRuntimeReceipt out;
    out.invocation=proof.newInvocation;out.configDbGeneration=proof.configDbGeneration;out.nativeCode=proof.nativeCode;
    for(const auto& p:proof.processes) {
        if(p.pid<=0||p.parent<0||!p.initializationConfirmed)
            throw std::runtime_error("SSSD uninitialized process cannot enter release receipt");
        out.processes.push_back({static_cast<std::uint32_t>(p.pid),static_cast<std::uint32_t>(p.parent),p.uid,p.gid,
            p.role,p.domain,p.startToken,p.executable,p.consumerSocket,p.monitorSocket});
    }
    return out;
}
// This is only a reprojection of journaled I3 observations. The caller must
// independently reprove graph, service generation, expectations and journal.
inline void confirmReceipt(const rollback::SssdReleaseRuntimeReceipt& receipt,
                           const detail_i3::NativeRuntimeContract& contract,
                           const EffectiveConfiguration& configuration, Deadline deadline) {
    if(receipt.processes.empty()||receipt.processes.front().role!="monitor"||receipt.nativeCode!=contract.code)
        throw std::runtime_error("SSSD release receipt/native code mismatch");
    SssdVerifiedActivationResult proof;
    proof.newInvocation=receipt.invocation;proof.configDbGeneration=receipt.configDbGeneration;
    std::set<std::string> backends;bool monitor=false,pam=false;
    for(const auto& p:receipt.processes) {
        if(p.role=="monitor") {
            if(monitor||p.executable!="/usr/sbin/sssd"||!p.domain.empty())throw std::runtime_error("invalid SSSD monitor receipt");
            monitor=true;
        } else {
            if(p.parent!=receipt.processes.front().pid)throw std::runtime_error("SSSD receipt consumer parent mismatch");
            if(p.role=="backend") {
                if(p.executable!="/usr/libexec/sssd/sssd_be"||!backends.insert(p.domain).second)
                    throw std::runtime_error("invalid SSSD backend receipt");
            } else if(p.role=="pam") {
                if(pam||p.executable!="/usr/libexec/sssd/sssd_pam"||!p.domain.empty())throw std::runtime_error("invalid SSSD PAM receipt");
                pam=true;
            } else throw std::runtime_error("unknown SSSD consumer receipt");
        }
        SssdProcessEvidence process;
        process.pid=p.pid;process.parent=p.parent;process.uid=p.uid;process.gid=p.gid;
        process.role=p.role;process.domain=p.domain;process.startToken=p.startToken;process.executable=p.executable;
        process.consumerSocket=p.consumerSocket;process.monitorSocket=p.monitorSocket;
        proof.processes.push_back(std::move(process));
    }
    const auto& enabled=configuration.scope.data().enabled;
    if(backends!=std::set<std::string>(enabled.begin(),enabled.end())||pam!=contract.needsPam)
        throw std::runtime_error("SSSD receipt has incomplete domain/responder coverage");
    detail_i3::confirmRuntime(contract,proof,deadline);
}
}
