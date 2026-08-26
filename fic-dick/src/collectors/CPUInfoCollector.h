#ifndef CPUINFOCOLLECTOR_H
#define CPUINFOCOLLECTOR_H

#include "InfoCollector.h"

//Обработка процессора
class CPUInfoCollector : public InfoCollector{
public:
    CPUInfoCollector();

    bool process_device_concrete() override;
};


#endif // CPUINFOCOLLECTOR_H

