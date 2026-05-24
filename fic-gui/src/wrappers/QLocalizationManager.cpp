#include "QLocalizationManager.h"

//Дать перевод по строке
QString QLocalizationManager::getLang(const QString& key){
    return QString::fromStdString(LocalizationManager::getLang(key.toStdString()));
}
