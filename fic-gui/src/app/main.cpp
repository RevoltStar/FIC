#include "app/MainWindow.h"

#include <QApplication>
#include <QCoreApplication>
#include <QImageReader>
#include <QTimer>
#include <QWidget>
#include <QtGlobal>

#include <fic/version/BuildInfo.h>
#include <fic/version/ProductVersion.h>

#include <dlfcn.h>
#include <iostream>
#include <string>

namespace {

void writeLicenseInfo()
{
    std::cout
        << "FIC is licensed under the Sustainable Use License 1.0.\n\n"
        << "fic-gui uses Qt as separately licensed third-party software.\n\n"
        << "The bundled Qt components used by fic-gui are distributed by FIC under GNU LGPL "
           "version 3 where that license option applies. Distribution package notices may "
           "describe alternative Qt licensing options and licenses of embedded third-party "
           "components.\n\n"
        << "Full license texts, distribution notices, the provenance manifest, and Corresponding "
           "Source information are installed in /usr/share/doc/fic-gui/.\n";
}

std::string loadedQtCorePath()
{
    Dl_info information{};
    if (dladdr(reinterpret_cast<void*>(&qVersion), &information) == 0 ||
        information.dli_fname == nullptr) {
        return {};
    }
    return information.dli_fname;
}

int runGuiSmokeTest(QApplication& application)
{
    QImageReader reader(QStringLiteral(":/fic/FIC.jpg"), "JPEG");
    const QImage image = reader.read();
    if (image.isNull()) {
        std::cerr << "JPEG smoke check failed: "
                  << reader.errorString().toStdString() << std::endl;
        return 1;
    }

    QWidget widget;
    widget.setWindowTitle(QStringLiteral("FIC GUI smoke test"));
    widget.resize(64, 64);
    widget.show();

    const std::string qtCorePath = loadedQtCorePath();
    if (qtCorePath.empty()) {
        std::cerr << "Unable to determine the loaded Qt Core library path" << std::endl;
        return 1;
    }

    std::cout << "qpa-platform=" << QApplication::platformName().toStdString() << '\n'
              << "jpeg-plugin=ok\n"
              << "qt-core-path=" << qtCorePath << std::endl;
    QTimer::singleShot(50, &application, &QCoreApplication::quit);
    return application.exec();
}

} // namespace

int main(int argc, char *argv[])
{
    if (argc == 2 && std::string(argv[1]) == "--version") {
        std::cout << "fic-gui " << fic::version::PRODUCT_VERSION
                  << " ipc-api=" << fic::version::IPC_API_VERSION << std::endl;
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--build-info") {
        fic::version::writeBuildInfo(std::cout, "fic-gui");
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--license-info") {
        writeLicenseInfo();
        return 0;
    }
    QApplication a(argc, argv);
    if (argc == 2 && std::string(argv[1]) == "--gui-smoke-test") {
        return runGuiSmokeTest(a);
    }
    MainWindow w;
    w.show();
    return a.exec();
}
