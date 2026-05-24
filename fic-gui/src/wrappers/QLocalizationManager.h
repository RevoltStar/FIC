#ifndef QLOCALIZATIONMANAGER_H
#define QLOCALIZATIONMANAGER_H

#include <QString>
#include "../utils/LocalizationManager.h"

//Класс для мультиязычности
class QLocalizationManager : public LocalizationManager{
public:
    //Дать перевод по строке
    static QString getLang(const QString& key);
};

#endif // QLOCALIZATIONMANAGER_H
