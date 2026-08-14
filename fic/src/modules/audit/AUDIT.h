#ifndef AUDIT_H
#define AUDIT_H

#include <fic/policy/Policy.h>

class Audit : public Policy
{
public:
    Audit();
    ~Audit() override = default;

    bool apply() override;
};

#endif // AUDIT_H
