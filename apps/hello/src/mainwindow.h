#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "GeneralNewsTab.h"
#include "PostInstallGuideTab.h"
#include "AssistantTab.h"
#include "TipsTab.h"
#include "InstallAppsTab.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onSoftwareNewsButtonClicked();
    void onViewLogsButtonClicked();
    void onNoShowButtonClicked();
    void onExitButtonClicked();

private:
    Ui::MainWindow *ui;

    GeneralNewsTab *generalNewsTab{};
    PostInstallGuideTab *postInstallGuideTab{};
    AssistantTab *assistantTab{};
    TipsTab *tipsTab{};
    InstallAppsTab *installAppsTab{};
};

#endif // MAINWINDOW_H
