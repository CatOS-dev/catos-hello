#include "AssistantTab.h"
#include <QTimer>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QMessageBox>
#include <QProcess>

AssistantTab::AssistantTab(QWidget *parent)
    : QWidget(parent)
{
    // 创建布局和控件
    layout = new QVBoxLayout(this);
    assistantLabel = new QLabel(tr("Get help from the assistant."), this);
    assistantLabel->setSizePolicy(assistantLabel->sizePolicy().horizontalPolicy(), QSizePolicy::Fixed);

    gridLayout = new QGridLayout;
    mirrorButton = new QPushButton(tr("Modify Mirror List"));
    repoButton = new QPushButton(tr("Modify Repo List"));
    updateButton = new QPushButton(tr("Update Native Packages"));
    updateAURButton = new QPushButton(tr("Update Native Packages && AUR Packages"));
    resetButton = new QPushButton(tr("Reset Arch GPG keys"));
    cleanButton = new QPushButton(tr("Clean up all local packages caches"));
    reduceButton = new QPushButton(tr("Clean local caches, except for the most recent three"));
    cleanAURButton = new QPushButton(tr("Clean up all local packages and AUR caches"));
    uninstallButton = new QPushButton(tr("Uninstall unused packages"));
    reinstallButton = new QPushButton(tr("Reinstall all packages"));
    unlockButton = new QPushButton(tr("Unlock pacman database"));
    listFailedServicesButton = new QPushButton(tr("List failed systemd services"));
    viewPacmanLogButton = new QPushButton(tr("View pacman log"));

    // 连接信号和槽
    connect(mirrorButton, SIGNAL(clicked()), this, SLOT(onMirrorButtonClicked()));
    connect(repoButton, SIGNAL(clicked()), this, SLOT(onRepoButtonClicked()));
    connect(updateButton, SIGNAL(clicked()), this, SLOT(onUpdateButtonClicked()));
    connect(updateAURButton, SIGNAL(clicked()), this, SLOT(onUpdateAURButtonClicked()));
    connect(resetButton, SIGNAL(clicked()), this, SLOT(onResetButtonClicked()));
    connect(cleanButton, SIGNAL(clicked()), this, SLOT(onCleanButtonClicked()));
    connect(reduceButton, SIGNAL(clicked()), this, SLOT(onReduceButtonClicked()));
    connect(cleanAURButton, SIGNAL(clicked()), this, SLOT(onCleanAURButtonClicked()));
    connect(uninstallButton, SIGNAL(clicked()), this, SLOT(onUninstallButtonClicked()));
    connect(reinstallButton, SIGNAL(clicked()), this, SLOT(onReinstallButtonClicked()));
    connect(unlockButton, SIGNAL(clicked()), this, SLOT(onUnlockButtonClicked()));
    connect(listFailedServicesButton, SIGNAL(clicked()), this, SLOT(onListFailedServicesClicked()));
    connect(viewPacmanLogButton, SIGNAL(clicked()), this, SLOT(onViewPacmanLogClicked()));

    // 添加控件到布局
    gridLayout->addWidget(mirrorButton, 0, 0);
    gridLayout->addWidget(repoButton, 0, 1);
    gridLayout->addWidget(updateButton, 1, 0);
    gridLayout->addWidget(updateAURButton, 1, 1);
    gridLayout->addWidget(cleanButton, 2, 0);
    gridLayout->addWidget(reduceButton, 2, 1);
    gridLayout->addWidget(cleanAURButton, 3, 0);
    gridLayout->addWidget(uninstallButton, 3, 1);
    gridLayout->addWidget(reinstallButton, 4, 0);
    gridLayout->addWidget(resetButton, 4, 1);
    gridLayout->addWidget(unlockButton, 5, 0);
    gridLayout->addWidget(listFailedServicesButton, 5, 1);
    gridLayout->addWidget(viewPacmanLogButton, 6, 0);
    layout->addWidget(assistantLabel, 0);
    layout->addLayout(gridLayout);
    layout->addWidget(new QLabel("", this)); // 空白标签

    // 设置布局
    setLayout(layout);
}

void AssistantTab::onMirrorButtonClicked()
{
    qInfo() << "AssistantTab: open MirrorListWindow";
    QScopedPointer mirrorWindow(new MirrorListWindow(this));
    mirrorWindow->exec();
}

void AssistantTab::onRepoButtonClicked()
{
    qInfo() << "AssistantTab: open RepoListWindow";
    QScopedPointer repoWindow(new RepoListWindow(this));
    repoWindow->exec();
}

void AssistantTab::onUpdateButtonClicked() {
    qInfo() << "AssistantTab: update native packages";
    QString command = "sudo pacman -Syu";
    QString prompt = tr("Update Native Packages");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void AssistantTab::onUpdateAURButtonClicked() {
    qInfo() << "AssistantTab: update native and AUR packages";
    QString command = "paru";
    QString prompt = tr("Update Native Packages && AUR Packages");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void AssistantTab::onResetButtonClicked() {
    qInfo() << "AssistantTab: reset Arch keyring";
    const QString installedPath = "/usr/bin/ResetKeyring";

    if (QFile::exists(installedPath)) {
        qInfo() << "AssistantTab: using installed ResetKeyring at" << installedPath;
        QStringList args;
        args << "--prompt" << "Reset Arch Keyring" << installedPath;
        QProcess::startDetached("RunInTerminal", args);
        return;
    }

    qWarning() << "AssistantTab: ResetKeyring not found at" << installedPath;
    QMessageBox::critical(this, tr("Error"), tr("ResetKeyring not found. Please install the package 'catos-hello' so /usr/bin/ResetKeyring is available."));
}

void AssistantTab::onCleanButtonClicked() {
    qInfo() << "AssistantTab: clean all package caches";
    QString command = "sudo pacman -Scc";
    QString prompt = tr("Clean up all local packages caches");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void AssistantTab::onReduceButtonClicked() {
    qInfo() << "AssistantTab: reduce package caches";
    QString command = "sudo paccache -rk3";
    QString prompt = tr("Clean local packages caches, except for the most recent three");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void AssistantTab::onCleanAURButtonClicked() {
    qInfo() << "AssistantTab: clean package and AUR caches";
    QString command = "paru -Scc";
    QString prompt = tr("Clean up all local packages and AUR caches");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void AssistantTab::onUninstallButtonClicked() {
    qInfo() << "AssistantTab: uninstall unused packages";
    QString command = "sudo pacman -Rns $(pacman -Qtdq)";
    QString prompt = tr("Uninstall unused packages");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void AssistantTab::onReinstallButtonClicked() {
    qInfo() << "AssistantTab: reinstall all packages";
    QString command = "pacman -Qqn | sudo pacman --overwrite=* -S -";
    QString prompt = tr("Reinstall all packages");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void AssistantTab::onUnlockButtonClicked()
{
    qInfo() << "AssistantTab: unlock pacman database";
    QString command = "sudo rm /var/lib/pacman/db.lck";
    QString prompt = tr("Unlock pacman database");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void AssistantTab::onListFailedServicesClicked()
{
    qInfo() << "AssistantTab: list failed systemd services";
    QString command = "systemctl --failed";
    QString prompt = tr("List failed systemd services");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void AssistantTab::onViewPacmanLogClicked()
{
    qInfo() << "AssistantTab: view pacman log";
    QString command = "less /var/log/pacman.log";
    QString prompt = tr("View pacman log");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}
