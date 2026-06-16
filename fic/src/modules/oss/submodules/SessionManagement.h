#ifndef SESSION_MANAGEMENT_H
#define SESSION_MANAGEMENT_H

#include "modules/oss/OSS.h"

class SessionManagement : public OSS
{
public:
    SessionManagement();
    virtual ~SessionManagement() = default;

    bool apply() override;
};

#endif // SESSION_MANAGEMENT_H
