#include "PostInstallGuideTab.h"
#include "MirrorListWindow.h"

#include <QDesktopServices>
#include <QProcess>
#include <QDebug>
#include <QInputDialog>
#include <QMessageBox>
#include <QDir>

PostInstallGuideTab::PostInstallGuideTab(QWidget *parent)
    : QWidget(parent)
{
    // 创建布局和控件
    layout = new QVBoxLayout(this);
    postInstallGuideLabel = new QLabel(tr("You can get help from these manuals."), this);
    postInstallGuideLabel->setSizePolicy(postInstallGuideLabel->sizePolicy().horizontalPolicy(), QSizePolicy::Fixed);

    gridLayout = new QGridLayout;
    pacmanButton = new QPushButton(tr("Correspondence between package managers"), this);
    // logButton = new QPushButton(tr("Troubleshooting Log"), this);
    mirrorButton = new QPushButton(tr("Modify Mirror List"), this);
    collectLogsButton = new QPushButton(tr("Collect Logs"), this);
    vacuumJournalButton = new QPushButton(tr("Vacuum Journal"), this);
    clearTempButton = new QPushButton(tr("Clear Temporary Files"), this);
    updateAURButton = new QPushButton(tr("Update Native & AUR Packages"), this);
    updateButton = new QPushButton(tr("Update Native Packages"), this);
    driverConfigButton = new QPushButton(tr("Driver Configuration"), this);
    offlinePostInstallButton = new QPushButton(tr("Offline Post-install: Refresh Keys & Update"), this);

    connect(pacmanButton, SIGNAL(clicked()), this, SLOT(onPacmanButtonClicked()));
    connect(driverConfigButton, SIGNAL(clicked()), this, SLOT(onDriverConfigButtonClicked()));
    connect(mirrorButton, SIGNAL(clicked()), this, SLOT(onMirrorButtonClicked()));
    connect(updateButton, SIGNAL(clicked()), this, SLOT(onUpdateButtonClicked()));
    connect(updateAURButton, SIGNAL(clicked()), this, SLOT(onUpdateAURButtonClicked()));
    connect(offlinePostInstallButton, SIGNAL(clicked()), this, SLOT(onOfflinePostInstallClicked()));
    connect(collectLogsButton, &QPushButton::clicked, this, &PostInstallGuideTab::onCollectLogsClicked);
    connect(vacuumJournalButton, &QPushButton::clicked, this, &PostInstallGuideTab::onVacuumJournalClicked);
    connect(clearTempButton, &QPushButton::clicked, this, &PostInstallGuideTab::onClearTempClicked);

    // 添加控件到布局
    gridLayout->addWidget(mirrorButton, 0, 0);
    gridLayout->addWidget(pacmanButton, 0, 1);
    gridLayout->addWidget(collectLogsButton, 1, 0);
    gridLayout->addWidget(updateButton, 1, 1);
    gridLayout->addWidget(updateAURButton, 2, 0);
    gridLayout->addWidget(offlinePostInstallButton, 3, 0);
    gridLayout->addWidget(vacuumJournalButton, 2, 1);
    gridLayout->addWidget(clearTempButton, 3, 0);
    gridLayout->addWidget(driverConfigButton, 3, 1);
    // gridLayout->addWidget(logButton, 4, 1);

    layout->addWidget(postInstallGuideLabel, 0);
    layout->addLayout(gridLayout);
    layout->addWidget(new QLabel("", this)); // 空白标签

    // 设置布局
    setLayout(layout);
}

void PostInstallGuideTab::onPacmanButtonClicked()
{
    qInfo() << "PostInstallGuideTab: open pacman docs";
    QDesktopServices::openUrl(QUrl("https://wiki.archlinuxcn.org/wiki/Pacman/%E5%90%84%E8%BD%AF%E4%BB%B6%E5%8C%85%E7%AE%A1%E7%90%86%E5%99%A8%E5%91%BD%E4%BB%A4%E5%AF%B9%E5%BA%94%E5%85%B3%E7%B3%BB"));
}

void PostInstallGuideTab::onDriverConfigButtonClicked()
{
    qInfo() << "PostInstallGuideTab: start driver configuration";
    QString command = "sudo chwd -a";
    QString prompt = tr("Install and configure drivers");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void PostInstallGuideTab::onMirrorButtonClicked()
{
    qInfo() << "PostInstallGuideTab: open MirrorListWindow";
    QScopedPointer<MirrorListWindow> mirrorWindow(new MirrorListWindow(this));
    mirrorWindow->exec();
}

void PostInstallGuideTab::onUpdateButtonClicked()
{
    qInfo() << "PostInstallGuideTab: update native packages";
    QString command = "sudo pacman -Syu";
    QString prompt = tr("Update Native Packages");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void PostInstallGuideTab::onUpdateAURButtonClicked()
{
    qInfo() << "PostInstallGuideTab: update native and AUR packages";
    QString command = "paru";
    QString prompt = tr("Update Native & AUR Packages");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void PostInstallGuideTab::onOfflinePostInstallClicked()
{
    qInfo() << "PostInstallGuideTab: run offline post-install tasks (ResetKeyring + paru)";
    const QString resetPath = "/usr/bin/ResetKeyring";
    if (!QFile::exists(resetPath)) {
        QMessageBox::critical(this, tr("Error"), tr("ResetKeyring not found at %1. Please install catos-hello package.").arg(resetPath));
        qWarning() << "PostInstallGuideTab: ResetKeyring not found at" << resetPath;
        return;
    }

    QString command = QString("sudo %1 && paru -Syu").arg(resetPath);
    QString prompt = tr("Offline Post-install: Refresh Keys & Update");
    QStringList args;
    args << "--prompt" << prompt << command;
    QProcess::startDetached("RunInTerminal", args);
}

void PostInstallGuideTab::onCollectLogsClicked()
{
    qInfo() << "PostInstallGuideTab: collect logs requested";

    // Only use system-installed binary
    const QString program = "/usr/bin/CollectLogs";
    if (!QFile::exists(program)) {
        QMessageBox::critical(this, tr("Error"), tr("collect-logs not found at /usr/bin/CollectLogs."));
        qWarning() << "PostInstallGuideTab: collect-logs not found at" << program;
        return;
    }

    // Run via pkexec to get root privileges for collecting protected logs
    QString user = QString::fromLocal8Bit(qgetenv("USER"));
    if (user.isEmpty()) {
        user = QString::fromLocal8Bit(qgetenv("SUDO_USER"));
    }
    bool started = QProcess::startDetached("pkexec", QStringList() << program << user);
    if (started) {
        QMessageBox::information(this, tr("Collect Logs"), tr("collect-logs started with elevated privileges. It will place an archive on your Desktop when finished."));
    } else {
        QMessageBox::critical(this, tr("Error"), tr("Failed to start collect-logs with pkexec."));
        qWarning() << "PostInstallGuideTab: failed to start pkexec" << program;
    }
}

void PostInstallGuideTab::onVacuumJournalClicked()
{
    qInfo() << "PostInstallGuideTab: vacuum journal requested";
    bool ok;
    QString defaultVal = QStringLiteral("2weeks");
    QString timeStr = QInputDialog::getText(this, tr("Vacuum Journal"), tr("Enter vacuum time (e.g. 2weeks, 30days):"), QLineEdit::Normal, defaultVal, &ok);
    if (!ok || timeStr.isEmpty()) return;

    QStringList args;
    args << "journalctl" << QString("--vacuum-time=%1").arg(timeStr);

    QProcess process;
    process.start("pkexec", args);
    if (!process.waitForFinished()) {
        QMessageBox::critical(this, tr("Error"), tr("pkexec failed to run journalctl"));
        qWarning() << "PostInstallGuideTab: pkexec journalctl failed to start";
        return;
    }

    if (process.exitCode() == 0) {
        QMessageBox::information(this, tr("Success"), tr("journalctl vacuum completed."));
        qInfo() << "PostInstallGuideTab: journal vacuum completed";
    } else {
        QString err = process.readAllStandardError();
        QMessageBox::critical(this, tr("Error"), tr("journalctl vacuum failed: ") + err);
        qWarning() << "PostInstallGuideTab: journalctl vacuum failed:" << err;
    }
}

void PostInstallGuideTab::onClearTempClicked()
{
    qInfo() << "PostInstallGuideTab: clear temporary files requested";

    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Clear Temporary Files"),
                                                              tr("This will clear your ~/.cache and attempt to clear /tmp and /var/tmp. Continue?"),
                                                              QMessageBox::Yes | QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    // Clear user cache (no sudo)
    QString homeCache = QDir::homePath() + "/.cache";
    QProcess proc;
    if (QFile::exists(homeCache)) {
        proc.start("bash", {"-c", QString("rm -rf '%1'/*").arg(homeCache)});
        proc.waitForFinished();
        qInfo() << "PostInstallGuideTab: cleared" << homeCache << "exit" << proc.exitCode();
    }

    // Clear /tmp and /var/tmp using pkexec
    QString cmd = "rm -rf /tmp/* /var/tmp/*";
    QProcess proc2;
    proc2.start("pkexec", {"bash", "-c", cmd});
    if (!proc2.waitForFinished()) {
        QMessageBox::warning(this, tr("Warning"), tr("Failed to run pkexec to clear /tmp. It may require manual cleanup."));
        return;
    }

    if (proc2.exitCode() == 0) {
        QMessageBox::information(this, tr("Success"), tr("Temporary files cleared."));
        qInfo() << "PostInstallGuideTab: cleared /tmp and /var/tmp";
    } else {
        QString err = proc2.readAllStandardError();
        QMessageBox::warning(this, tr("Partial Success"), tr("User cache cleared; system tmp cleanup reported: ") + err);
        qWarning() << "PostInstallGuideTab: tmp clear error:" << err;
    }
}
