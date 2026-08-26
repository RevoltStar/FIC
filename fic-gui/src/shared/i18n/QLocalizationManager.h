#ifndef QLOCALIZATIONMANAGER_H
#define QLOCALIZATIONMANAGER_H

#include <QString>

class QLocalizationManager {
public:
    static QString getLang(const QString& key);
};

#endif // QLOCALIZATIONMANAGER_H
