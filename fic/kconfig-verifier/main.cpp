#include <KConfigGroup>
#include <KSharedConfig>

#include <QCoreApplication>
#include <QTextStream>

#include <array>
#include <cstdio>

int main(int argc, char* argv[]) {
    QCoreApplication application(argc, argv);
    if (argc != 1) return 2;

    constexpr std::array<const char*, 5> keys{
        "Autolock", "Timeout", "Lock", "LockGrace", "RequirePassword"};
    const KSharedConfig::Ptr config = KSharedConfig::openConfig(
        QStringLiteral("kscreenlockerrc"), KConfig::FullConfig);
    const KConfigGroup daemon(config, QStringLiteral("Daemon"));
    QTextStream output(stdout);
    output << "FIC-KCONFIG-V1\n";
    for (const char* key : keys) {
        const QString name = QString::fromLatin1(key);
        output << name << '\t' << daemon.readEntry(key, QString()) << '\t'
               << (daemon.isEntryImmutable(key) ? '1' : '0') << '\n';
    }
    return output.status() == QTextStream::Ok ? 0 : 3;
}
