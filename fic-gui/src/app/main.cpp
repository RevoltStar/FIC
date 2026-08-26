#include "app/MainWindow.h"

#include <QApplication>

#include <fic/version/BuildInfo.h>
#include <fic/version/ProductVersion.h>

#include <iostream>
#include <string>

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
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
