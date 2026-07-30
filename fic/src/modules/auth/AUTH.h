#ifndef FIC_AUTH_H
#define FIC_AUTH_H

#include <fic/policy/Policy.h>

class Auth : public Policy {
public:
    Auth();
    ~Auth() override = default;
};

#endif // FIC_AUTH_H
