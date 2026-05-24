#ifndef QSINGLELINEFILEHANDLER_H
#define QSINGLELINEFILEHANDLER_H

#include <QString>
#include "SingleLineFileHandler.h"

class QSingleLineFileHandler : public SingleLineFileHandler{
public:
    QSingleLineFileHandler(const QString& filepath);
    //Получить значение
    QString getValue(const QString& parameter="");
    // Загружаем конфигурационный файл
    bool loadConfig() override;
};

#endif // QSINGLELINEFILEHANDLER_H
