#include "QConfigFileHandler.h"

QConfigFileHandler::QConfigFileHandler(const QString& filepath, const QString& delimeter)
    : ConfigFileHandler(filepath.toStdString(), delimeter.toStdString()) {
}

QString QConfigFileHandler::getValue(const QString &parameter){
    //return QString::fromStdString(this->filepath_);
    return QString::fromStdString(ConfigFileHandler::getValue(parameter.toStdString()));
}

bool QConfigFileHandler::loadConfig() {
    return this->ConfigFileHandler::loadConfig();
}
