#ifndef FIC_IDENTITY_ACCESS_POLICY_H
#define FIC_IDENTITY_ACCESS_POLICY_H

#include <fic/policy/Policy.h>

#include <mutex>

class IdentityAccessPolicy : public Policy {
public:
    ~IdentityAccessPolicy() override = default;

    // Serializes all identity configuration mutations. Composite and leaf
    // policies must use the same lock before inspecting or changing the OS.
    // Public so that non-Policy mutation paths that drive the SAME identity
    // domain (the joint C2 password topology rollback in the rollback
    // executor) serialize with policy apply as well.
    static std::mutex& configurationMutex();

protected:
    explicit IdentityAccessPolicy(const char* submoduleName);
};

#endif // FIC_IDENTITY_ACCESS_POLICY_H
