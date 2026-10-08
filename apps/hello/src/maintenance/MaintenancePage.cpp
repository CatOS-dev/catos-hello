#include "maintenance/MaintenancePage.h"
#include "ToolRunner.h"
#include "MirrorListWindow.h"
#include "RepoListWindow.h"

#include <QFrame>
#include <QGroupBox>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

void MaintenancePage::addCommand(QVBoxLayout *layout, const QString &label, const QString &title,
                                  const QString &command, bool confirm)
{
    auto *button = new QPushButton(label, this);
    connect(button, &QPushButton::clicked, this, [this, title, command, confirm] {
        if (confirm && QMessageBox::question(this, title,
                tr("This operation changes system packages or settings. Continue?")) != QMessageBox::Yes)
            return;
        tools_->runInTerminal(title, command, [this, title](int code, const QString &, const QString &error) {
            if (code != 0)
                QMessageBox::warning(this, title, tr("Operation did not finish successfully (%1). %2").arg(code).arg(error));
        });
    });
    layout->addWidget(button, 0, Qt::AlignLeft);
}

MaintenancePage::MaintenancePage(ToolRunner *tools, QWidget *parent) : QWidget(parent), tools_(tools)
{
    auto *outer = new QVBoxLayout(this);
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    outer->addWidget(scroll);
    auto *content = new QWidget(scroll);
    scroll->setWidget(content);
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(18, 14, 22, 20);

    auto *title = new QLabel(tr("System maintenance"), content);
    QFont font = title->font();
    font.setBold(true);
    font.setPointSize(font.pointSize() + 7);
    title->setFont(font);
    layout->addWidget(title);
    layout->addWidget(new QLabel(tr("Review system status and open a tool when needed."), content));

    auto *updates = new QGroupBox(tr("Updates"), content);
    auto *updatesLayout = new QVBoxLayout(updates);
    auto *shelly = new QPushButton(tr("Open Shelly package manager"), updates);
    connect(shelly, &QPushButton::clicked, this, [this] {
        if (!ToolRunner::launch(QStringLiteral("shelly-ui")))
            QMessageBox::warning(this, tr("Shelly unavailable"), tr("The Shelly graphical application is not installed."));
    });
    updatesLayout->addWidget(shelly, 0, Qt::AlignLeft);
    addCommand(updatesLayout, tr("Update installed packages (terminal)"), tr("Update CatOS"),
               QStringLiteral("sudo pacman -Syu"), true);
    layout->addWidget(updates);

    auto *drivers = new QGroupBox(tr("Hardware drivers"), content);
    drivers->setObjectName(QStringLiteral("driverSection"));
    auto *driversLayout = new QVBoxLayout(drivers);
    addCommand(driversLayout, tr("View compatible hardware drivers"), tr("Available drivers"),
               QStringLiteral("chwd --list --detail"));
    addCommand(driversLayout, tr("Automatically configure drivers"), tr("Configure hardware"),
               QStringLiteral("sudo chwd -a"), true);
    layout->addWidget(drivers);

    auto *repositories = new QGroupBox(tr("Package sources"), content);
    auto *repositoriesLayout = new QVBoxLayout(repositories);
    auto *mirrors = new QPushButton(tr("Select package mirrors"), repositories);
    connect(mirrors, &QPushButton::clicked, this, [this] { MirrorListWindow(this).exec(); });
    repositoriesLayout->addWidget(mirrors, 0, Qt::AlignLeft);
    auto *repos = new QPushButton(tr("Edit pacman repositories"), repositories);
    connect(repos, &QPushButton::clicked, this, [this] { RepoListWindow(this).exec(); });
    repositoriesLayout->addWidget(repos, 0, Qt::AlignLeft);
    layout->addWidget(repositories);

    auto *diagnosis = new QGroupBox(tr("Troubleshooting"), content);
    auto *diagnosisLayout = new QVBoxLayout(diagnosis);
    addCommand(diagnosisLayout, tr("Check failed services"), tr("System services"),
               QStringLiteral("systemctl --failed"));
    addCommand(diagnosisLayout, tr("Read pacman history"), tr("Package manager log"),
               QStringLiteral("less /var/log/pacman.log"));
    auto *logs = new QPushButton(tr("Collect system logs"), diagnosis);
    connect(logs, &QPushButton::clicked, this, [this] {
        tools_->run(QStringLiteral("pkexec"),
                    {QStringLiteral("/usr/bin/CollectLogs"), qEnvironmentVariable("USER")},
                    [this](int code, const QString &, const QString &error) {
            if (code == 0) QMessageBox::information(this, tr("System logs"),
                tr("The diagnostic archive was saved to your Desktop."));
            else QMessageBox::warning(this, tr("System logs"), error.isEmpty() ?
                tr("Unable to collect diagnostic logs.") : error);
        });
    });
    diagnosisLayout->addWidget(logs, 0, Qt::AlignLeft);
    layout->addWidget(diagnosis);

    auto *advanced = new QGroupBox(tr("Advanced maintenance (optional)"), content);
    advanced->setCheckable(true);
    advanced->setChecked(false);
    auto *advancedLayout = new QVBoxLayout(advanced);
    addCommand(advancedLayout, tr("Refresh package signing keys"), tr("Keyring maintenance"),
               QStringLiteral("sudo ResetKeyring"), true);
    addCommand(advancedLayout, tr("Trim old package cache"), tr("Package cache cleanup"),
               QStringLiteral("sudo paccache -rk3"), true);
    addCommand(advancedLayout, tr("Remove unused packages"), tr("Remove orphaned packages"),
               QStringLiteral("orphans=$(pacman -Qtdq); if [ -n \"$orphans\" ]; then sudo pacman -Rns $orphans; else echo 'No orphaned packages'; fi"), true);
    addCommand(advancedLayout, tr("Full package cache cleanup"), tr("Clear package cache"),
               QStringLiteral("sudo pacman -Scc"), true);
    addCommand(advancedLayout, tr("Reinstall installed repository packages"), tr("Reinstall packages"),
               QStringLiteral("pacman -Qqn | sudo pacman --overwrite='*' -S -"), true);
    layout->addWidget(advanced);
    layout->addStretch();
}

void MaintenancePage::showDrivers()
{
    if (auto *drivers = findChild<QGroupBox *>(QStringLiteral("driverSection")))
        drivers->setFocus(Qt::OtherFocusReason);
}
