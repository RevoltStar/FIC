#include "QSingleLineFileHandler.h"

QSingleLineFileHandler::QSingleLineFileHandler(const QString& filepath)
    : SingleLineFileHandler(filepath.toStdString()) {
    this->data_line_index_ = -1;
}

QString QSingleLineFileHandler::getValue(const QString &parameter){
    //return QString::fromStdString(this->filepath_);
    return QString::fromStdString(SingleLineFileHandler::getValue());
}

bool QSingleLineFileHandler::loadConfig() {
    return this->SingleLineFileHandler::loadConfig();
}
