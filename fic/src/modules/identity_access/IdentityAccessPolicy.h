#ifndef FIC_IDENTITY_ACCESS_POLICY_H
#define FIC_IDENTITY_ACCESS_POLICY_H

#include <fic/policy/Policy.h>

#include <mutex>

class IdentityAccessPolicy : public Policy {
public:
    ~IdentityAccessPolicy() override = default;

protected:
    explicit IdentityAccessPolicy(const char* submoduleName);

    // Serializes all identity configuration mutations. Composite and leaf
    // policies must use the same lock before inspecting or changing the OS.
    static std::mutex& configurationMutex();
};

#endif // FIC_IDENTITY_ACCESS_POLICY_H
