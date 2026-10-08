#include "maintenance/MaintenancePage.h"
#include "ToolRunner.h"
#include "MirrorListWindow.h"
#include "RepoListWindow.h"
#include "ui/ActionList.h"

#include <QFrame>
#include <QInputDialog>
#include <QLineEdit>
#include <QMessageBox>
#include <QRegularExpression>
#include <QScrollArea>
#include <QToolButton>
#include <QVBoxLayout>

ActionRow *MaintenancePage::addCommand(QVBoxLayout *layout, const QString &label,
                                       const QString &detail, const QString &icon,
                                       const QString &title, const QString &command, bool confirm)
{
    auto *action = Ui::addAction(layout, this, label, detail, icon);
    connect(action, &QPushButton::clicked, this, [this, title, command, confirm] {
        if (confirm && QMessageBox::question(this, title,
                tr("This operation changes system packages or settings. Continue?")) != QMessageBox::Yes)
            return;
        tools_->runInTerminal(title, command, [this, title](int code, const QString &, const QString &error) {
            if (code != 0)
                QMessageBox::warning(this, title, tr("Operation did not finish successfully (%1). %2").arg(code).arg(error));
        });
    });
    return action;
}

MaintenancePage::MaintenancePage(ToolRunner *tools, QWidget *parent) : QWidget(parent), tools_(tools)
{
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    outer->addWidget(scroll);
    auto *content = new QWidget(scroll);
    scroll->setWidget(content);
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(28, 18, 34, 28);
    layout->setSpacing(4);

    Ui::addTitle(layout, content, tr("System maintenance"),
                 tr("Review system status and open a tool when needed."));

    Ui::addSection(layout, content, tr("Updates"));
    auto *catosUpdater = Ui::addAction(layout, content, tr("Run CatOS updater (news and updates)"),
                        tr("Check important news and update CatOS safely."),
                        QStringLiteral("system-software-update"));
    connect(catosUpdater, &QPushButton::clicked, this, [this] {
        tools_->runInTerminal(tr("Update CatOS"), QStringLiteral("sysup"),
                              [this](int code, const QString &, const QString &error) {
            if (code != 0) QMessageBox::warning(this, tr("Update CatOS"),
                tr("System update did not finish successfully (%1). %2").arg(code).arg(error));
        });
    });
    addCommand(layout, tr("Update installed packages (terminal)"),
               tr("Update packages from configured pacman repositories."),
               QStringLiteral("package-x-generic"), tr("Update CatOS"),
               QStringLiteral("sudo pacman -Syu"), true);
    addCommand(layout, tr("Update native and AUR packages"),
               tr("Run the original pacman and AUR update workflow with paru."),
               QStringLiteral("software-install"), tr("Update packages with paru"),
               QStringLiteral("paru"), true);

    Ui::addSection(layout, content, tr("Hardware drivers"));
    driversAnchor_ = addCommand(layout, tr("View compatible hardware drivers"),
                                tr("Inspect available hardware and matching driver profiles."),
                                QStringLiteral("preferences-system"), tr("Available drivers"),
                                QStringLiteral("chwd --list --detail"));
    driversAnchor_->setObjectName(QStringLiteral("driverSection"));
    addCommand(layout, tr("Automatically configure drivers"),
               tr("Apply compatible hardware drivers after reviewing your system."),
               QStringLiteral("computer"), tr("Configure hardware"),
               QStringLiteral("sudo chwd -a"), true);

    Ui::addSection(layout, content, tr("Package sources"));
    auto *mirrors = Ui::addAction(layout, content, tr("Select package mirrors"),
                                  tr("Choose and rank repository mirror servers."),
                                  QStringLiteral("network-server"));
    connect(mirrors, &QPushButton::clicked, this, [this] { MirrorListWindow(this).exec(); });
    auto *repos = Ui::addAction(layout, content, tr("Edit pacman repositories"),
                                tr("Review enabled software repositories."),
                                QStringLiteral("document-edit"));
    connect(repos, &QPushButton::clicked, this, [this] { RepoListWindow(this).exec(); });

    Ui::addSection(layout, content, tr("Troubleshooting"));
    addCommand(layout, tr("Check failed services"),
               tr("List systemd units that failed to start."),
               QStringLiteral("dialog-warning"), tr("System services"),
               QStringLiteral("systemctl --failed"));
    addCommand(layout, tr("Read pacman history"),
               tr("View the local package transaction log."),
               QStringLiteral("text-x-log"), tr("Package manager log"),
               QStringLiteral("less /var/log/pacman.log"));
    auto *logs = Ui::addAction(layout, content, tr("Collect system logs"),
                               tr("Save a diagnostic archive to your Desktop."),
                               QStringLiteral("document-save"));
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

    layout->addSpacing(23);
    auto *advancedToggle = new QToolButton(content);
    advancedToggle->setObjectName(QStringLiteral("advancedToggle"));
    advancedToggle->setText(tr("Advanced maintenance (optional)"));
    advancedToggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    advancedToggle->setArrowType(Qt::RightArrow);
    advancedToggle->setCheckable(true);
    advancedToggle->setAutoRaise(true);
    advancedToggle->setCursor(Qt::PointingHandCursor);
    auto toggleFont = advancedToggle->font();
    toggleFont.setBold(true);
    advancedToggle->setFont(toggleFont);
    layout->addWidget(advancedToggle, 0, Qt::AlignLeft);

    auto *advanced = new QWidget(content);
    advanced->setObjectName(QStringLiteral("advancedSection"));
    auto *advancedLayout = new QVBoxLayout(advanced);
    advancedLayout->setContentsMargins(0, 0, 0, 0);
    advancedLayout->setSpacing(4);
    addCommand(advancedLayout, tr("Refresh package signing keys"),
               tr("Reset the Arch Linux package signing keyring."),
               QStringLiteral("security-high"), tr("Keyring maintenance"),
               QStringLiteral("sudo ResetKeyring"), true);
    addCommand(advancedLayout, tr("Trim old package cache"),
               tr("Keep the three most recent versions of each package."),
               QStringLiteral("edit-clear-history"), tr("Package cache cleanup"),
               QStringLiteral("sudo paccache -rk3"), true);
    addCommand(advancedLayout, tr("Remove unused packages"),
               tr("Uninstall orphaned dependencies no longer required."),
               QStringLiteral("edit-delete"), tr("Remove orphaned packages"),
               QStringLiteral("orphans=$(pacman -Qtdq); if [ -n \"$orphans\" ]; then sudo pacman -Rns $orphans; else echo 'No orphaned packages'; fi"), true);
    addCommand(advancedLayout, tr("Full package cache cleanup"),
               tr("Remove all cached pacman package files."),
               QStringLiteral("edit-clear-all"), tr("Clear package cache"),
               QStringLiteral("sudo pacman -Scc"), true);
    addCommand(advancedLayout, tr("Reinstall installed repository packages"),
               tr("Reinstall repository packages already present on the system."),
               QStringLiteral("view-refresh"), tr("Reinstall packages"),
               QStringLiteral("pacman -Qqn | sudo pacman --overwrite='*' -S -"), true);
    addCommand(advancedLayout, tr("Clean AUR and local package caches"),
               tr("Clear cached packages and builds managed by paru."),
               QStringLiteral("edit-clear"), tr("AUR cache cleanup"),
               QStringLiteral("paru -Scc"), true);
    addCommand(advancedLayout, tr("Unlock pacman database"),
               tr("Remove a stale package database lock after checking active processes."),
               QStringLiteral("object-locked"), tr("Remove package database lock"),
               QStringLiteral("sudo rm /var/lib/pacman/db.lck"), true);
    addCommand(advancedLayout, tr("Offline post-install: refresh keys and update"),
               tr("Refresh package keys and update after offline installation."),
               QStringLiteral("system-run"), tr("Post-install initialization"),
               QStringLiteral("sudo ResetKeyring && paru -Syu"), true);

    auto *vacuum = Ui::addAction(advancedLayout, advanced, tr("Vacuum journal"),
                                 tr("Choose how long to retain system journal entries."),
                                 QStringLiteral("edit-clear-history"));
    connect(vacuum, &QPushButton::clicked, this, [this] {
        bool accepted = false;
        const QString interval = QInputDialog::getText(this, tr("Vacuum journal"),
            tr("Keep journal entries for (e.g. 2weeks, 30days):"),
            QLineEdit::Normal, QStringLiteral("2weeks"), &accepted);
        if (!accepted || interval.isEmpty()) return;
        if (!QRegularExpression(QStringLiteral("^[0-9]+(seconds|minutes|hours|days|weeks|months|years)$"))
                .match(interval).hasMatch()) {
            QMessageBox::warning(this, tr("Vacuum journal"), tr("Invalid journal retention period."));
            return;
        }
        if (QMessageBox::question(this, tr("Vacuum journal"),
                tr("Delete journal entries older than %1?").arg(interval)) != QMessageBox::Yes) return;
        tools_->run(QStringLiteral("pkexec"),
                    {QStringLiteral("journalctl"), QStringLiteral("--vacuum-time=") + interval},
                    [this](int code, const QString &, const QString &error) {
            if (code == 0) QMessageBox::information(this, tr("Vacuum journal"), tr("Journal cleanup completed."));
            else QMessageBox::warning(this, tr("Vacuum journal"), tr("Journal cleanup failed: %1").arg(error));
        });
    });
    auto *clearTemporary = Ui::addAction(advancedLayout, advanced, tr("Clear temporary files"),
                                          tr("Remove user caches and system temporary files."),
                                          QStringLiteral("user-trash"));
    connect(clearTemporary, &QPushButton::clicked, this, [this] {
        if (QMessageBox::question(this, tr("Clear temporary files"),
                tr("This removes the user cache and files in /tmp and /var/tmp. Continue?")) != QMessageBox::Yes) return;
        tools_->runInTerminal(tr("Clear temporary files"),
               QStringLiteral("rm -rf -- \"$HOME\"/.cache/* && sudo rm -rf -- /tmp/* /var/tmp/*"),
               [this](int code, const QString &, const QString &error) {
            if (code != 0) QMessageBox::warning(this, tr("Clear temporary files"),
                tr("Temporary file cleanup did not finish successfully (%1). %2").arg(code).arg(error));
        });
    });
    advanced->hide();
    connect(advancedToggle, &QToolButton::toggled, this, [advancedToggle, advanced](bool open) {
        advanced->setVisible(open);
        advancedToggle->setArrowType(open ? Qt::DownArrow : Qt::RightArrow);
    });
    layout->addWidget(advanced);
    layout->addStretch();
}

void MaintenancePage::showDrivers()
{
    if (!driversAnchor_) return;
    if (auto *scroll = findChild<QScrollArea *>()) scroll->ensureWidgetVisible(driversAnchor_);
    driversAnchor_->setFocus(Qt::OtherFocusReason);
}
