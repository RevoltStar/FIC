#ifndef MEMORYINFOCOLLECTOR_H
#define MEMORYINFOCOLLECTOR_H

#include "InfoCollector.h"

//Обработка процессора
class MemoryInfoCollector : public InfoCollector{
public:
    MemoryInfoCollector();

    bool process_device_concrete()override;


};


#endif // CPUINFOCOLLECTOR_H


