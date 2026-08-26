// BlockInfoCollector.h
#ifndef BLOCKINFOCOLLECTOR_H
#define BLOCKINFOCOLLECTOR_H

#include "UDEVInfoCollector.h"

class BlockInfoCollector : public UDEVInfoCollector {
protected:
    std::vector<std::string> control_list_for_current_env() const override;

public:
    BlockInfoCollector();
};

#endif // BLOCKINFOCOLLECTOR_H
