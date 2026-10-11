// Compile with the unmodified upstream ConfigReader.cpp/.h matching the
// installed SDDM version. No daemon, service or session is started.
#include "ConfigReader.h"
#include <QCoreApplication>
#include <iostream>
class Reader final : public SDDM::ConfigBase {
public:
    SDDM::ConfigSection autologin{this,QStringLiteral("Autologin")};
    SDDM::ConfigEntry<QString> user{&autologin,QStringLiteral("User"),QString(),QString()};
    Reader(const QString& file,const QString& directory,const QString& systemDirectory)
        :SDDM::ConfigBase(file,directory,systemDirectory){load();}
};
int main(int argc,char** argv){
    QCoreApplication app(argc,argv);if(argc!=4)return 1;
    Reader reader(QString::fromLocal8Bit(argv[1]),QString::fromLocal8Bit(argv[2]),QString::fromLocal8Bit(argv[3]));
    std::cout<<reader.user.get().toStdString()<<'\n';return 0;
}
