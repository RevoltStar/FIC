#ifndef BOARDINFOCOLLECTOR_H
#define BOARDINFOCOLLECTOR_H

#include "InfoCollector.h"

//Обработка процессора
class BoardInfoCollector : public InfoCollector{
public:
    BoardInfoCollector();

    bool process_device_concrete() override;
};

#endif // BOARDINFOCOLLECTOR_H
