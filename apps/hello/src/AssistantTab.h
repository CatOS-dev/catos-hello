#ifndef ASSISTANTTAB_H
#define ASSISTANTTAB_H

#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QTemporaryFile>
#include <QDir>
#include "MirrorListWindow.h"
#include "RepoListWindow.h"

class AssistantTab : public QWidget
{
    Q_OBJECT

public:
    explicit AssistantTab(QWidget *parent = nullptr);

private slots:
    void onMirrorButtonClicked();
    void onRepoButtonClicked();
    void onUpdateButtonClicked();
    void onUpdateAURButtonClicked();
    void onResetButtonClicked();
    void onCleanButtonClicked();
    void onReduceButtonClicked();
    void onCleanAURButtonClicked();
    void onUninstallButtonClicked();
    void onReinstallButtonClicked();
    void onUnlockButtonClicked();
    void onListFailedServicesClicked();
    void onViewPacmanLogClicked();

private:
    QLabel *assistantLabel;
    QVBoxLayout *layout;
    QGridLayout *gridLayout;

    QPushButton *mirrorButton;
    QPushButton *repoButton;
    QPushButton *updateButton;
    QPushButton *updateAURButton;
    QPushButton *resetButton;
    QPushButton *cleanButton;
    QPushButton *reduceButton;
    QPushButton *uninstallButton;
    QPushButton *reinstallButton;
    QPushButton *cleanAURButton;
    QPushButton *uninstallAURButton;
    QPushButton *reinstallAURButton;
    QPushButton *unlockButton;
    QPushButton *listFailedServicesButton;
    QPushButton *viewPacmanLogButton;
};

#endif // ASSISTANTTAB_H
