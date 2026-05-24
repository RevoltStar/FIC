#ifndef QCONFIGFILEHANDLER_H
#define QCONFIGFILEHANDLER_H


#include <QString>
#include "ConfigFileHandler.h"

class QConfigFileHandler : public ConfigFileHandler{
public:
    QConfigFileHandler(const QString& filepath, const QString& delimeter = "=");
    //Получить значение
    QString getValue(const QString& parameter="");
    // Загружаем конфигурационный файл
    bool loadConfig() override;
};


#endif // QCONFIGFILEHANDLER_H
