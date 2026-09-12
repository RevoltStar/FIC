#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

class QPushButton;
class QString;
class QWidget;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    void addModules();

private:
    void clearModules();
    void showModules();
    void showRefreshFallback(const QString& error);

    Ui::MainWindow* ui;
    QWidget* refreshFallback_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
};

#endif // MAINWINDOW_H
