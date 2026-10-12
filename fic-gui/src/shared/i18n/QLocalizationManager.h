#ifndef QLOCALIZATIONMANAGER_H
#define QLOCALIZATIONMANAGER_H

#include <QString>
#include <QByteArray>

class QLocalizationManager {
public:
    static QString getLang(const QString& key);
    // Install a bundle acquired by a worker, without synchronous GUI IPC.
    static bool installBundle(const QByteArray& bundle);
};

#endif // QLOCALIZATIONMANAGER_H
