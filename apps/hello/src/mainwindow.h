#pragma once

#include "home/Environment.h"
#include <QMainWindow>

class QListWidget;
class QStackedWidget;
class ToolRunner;
class SoftwarePage;
class MaintenancePage;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(const Environment &environment = Environment::detect(), QWidget *parent = nullptr);

private:
    void navigate(const QString &page);
    void dispatchHomeAction(const QString &action);
    void viewInstallLogs();

    bool live_ = false;
    QListWidget *navigation_ = nullptr;
    QStackedWidget *pages_ = nullptr;
    ToolRunner *tools_ = nullptr;
    SoftwarePage *software_ = nullptr;
    MaintenancePage *maintenance_ = nullptr;
};
