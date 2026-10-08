#include "desktop/DesktopPage.h"
#include "ToolRunner.h"
#include "home/Environment.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QStandardPaths>
#include <QTreeWidget>
#include <QVBoxLayout>

DesktopPage::DesktopPage(ToolRunner *tools, QWidget *parent)
    : QWidget(parent), catdot_(new CatdotClient(tools, this))
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 4, 0, 0);
    auto *title = new QLabel(tr("Personalize your desktop"), this);
    QFont font = title->font();
    font.setBold(true);
    title->setFont(font);
    layout->addWidget(title);

    const QString desktop = Environment::detect().desktop;
    layout->addWidget(new QLabel(tr("Current session: %1").arg(desktop), this));
    QString settings;
    if (desktop == QStringLiteral("KDE Plasma")) settings = QStringLiteral("systemsettings");
    else if (desktop == QStringLiteral("GNOME")) settings = QStringLiteral("gnome-control-center");
    if (!settings.isEmpty()) {
        auto *button = new QPushButton(tr("Open %1 settings").arg(desktop), this);
        connect(button, &QPushButton::clicked, this, [this, settings] {
            if (!ToolRunner::launch(settings))
                QMessageBox::warning(this, tr("Settings"), tr("The desktop settings application is not installed."));
        });
        layout->addWidget(button, 0, Qt::AlignLeft);
    }

    auto *bar = new QHBoxLayout;
    bar->addWidget(new QLabel(tr("Catdot desktop Profiles"), this));
    bar->addStretch();
    refresh_ = new QPushButton(tr("Refresh"), this);
    connect(refresh_, &QPushButton::clicked, this, &DesktopPage::refresh);
    bar->addWidget(refresh_);
    layout->addLayout(bar);
    status_ = new QLabel(tr("Checking available Profiles…"), this);
    status_->setWordWrap(true);
    layout->addWidget(status_);

    profiles_ = new QTreeWidget(this);
    profiles_->setHeaderLabels({tr("Profile"), tr("Status"), tr("Description")});
    profiles_->setRootIsDecorated(false);
    profiles_->setMinimumHeight(170);
    layout->addWidget(profiles_);
    auto *actions = new QHBoxLayout;
    preview_ = new QPushButton(tr("Review and switch Profile"), this);
    preview_->setEnabled(false);
    connect(preview_, &QPushButton::clicked, this, &DesktopPage::previewSelected);
    connect(profiles_, &QTreeWidget::itemSelectionChanged, this, [this] {
        const auto selection = profiles_->selectedItems();
        preview_->setEnabled(!selection.isEmpty() &&
                             selection.first()->data(1, Qt::UserRole).toString() != QStringLiteral("active") &&
                             selection.first()->data(1, Qt::UserRole).toString() != QStringLiteral("unavailable"));
    });
    actions->addWidget(preview_, 0, Qt::AlignLeft);
    actions->addStretch();
    layout->addLayout(actions);
    auto *hint = new QLabel(tr("Catdot switches complete configuration Profiles and keeps backups of replaced files. Changes may require logging out."), this);
    hint->setWordWrap(true);
    layout->addWidget(hint);
    if (QStandardPaths::findExecutable(QStringLiteral("catdot")).isEmpty()) {
        refresh_->hide();
        profiles_->hide();
        preview_->hide();
        status_->setText(tr("Catdot is not installed. This desktop may use its own settings instead."));
    } else {
        refresh();
    }
}

void DesktopPage::refresh()
{
    refresh_->setEnabled(false);
    preview_->setEnabled(false);
    status_->setText(tr("Loading Catdot Profiles…"));
    catdot_->list([this](const QVector<DesktopProfile> &profiles, const QString &active,
                        const QString &error) {
        refresh_->setEnabled(true);
        profiles_->clear();
        if (!error.isEmpty()) {
            status_->setText(tr("Catdot is unavailable: %1").arg(error));
            return;
        }
        status_->setText(active.isEmpty() ? tr("No Catdot Profile is currently active.")
                                          : tr("Active Catdot Profile: %1").arg(active));
        for (const auto &profile : profiles) {
            auto *row = new QTreeWidgetItem(profiles_);
            row->setText(0, profile.name);
            row->setText(1, profile.status);
            row->setText(2, profile.description);
            row->setData(0, Qt::UserRole, profile.id);
            row->setData(1, Qt::UserRole, profile.status);
            row->setToolTip(0, tr("Packages: %1").arg(profile.packages.join(QStringLiteral(", "))));
        }
        if (profiles.isEmpty()) status_->setText(tr("No installed Catdot Profiles were found."));
    });
}

void DesktopPage::previewSelected()
{
    const auto selected = profiles_->selectedItems();
    if (selected.isEmpty()) return;
    const QString id = selected.first()->data(0, Qt::UserRole).toString();
    preview_->setEnabled(false);
    catdot_->plan(id, [this, id](const ProfilePlan &plan, const QString &error) {
        preview_->setEnabled(true);
        if (!error.isEmpty()) {
            QMessageBox::warning(this, tr("Profile preview"), error);
            return;
        }
        const QString affected = plan.existingPathsAffected.isEmpty()
            ? tr("No existing paths need replacement.")
            : tr("Existing paths affected (%1):\n%2")
                .arg(plan.existingPathsAffected.size())
                .arg(plan.existingPathsAffected.mid(0, 8).join(QStringLiteral("\n")));
        const QString packages = plan.missingPackages.isEmpty()
            ? tr("All declared packages are installed.")
            : tr("Packages to install: %1").arg(plan.missingPackages.join(QStringLiteral(", ")));
        const QString detail = tr("This is a complete desktop Profile, not just a theme.\n\n%1\n"
                                  "Files written: %2 · Files removed: %3\n\n%4\n\n"
                                  "Catdot backs up existing files before replacing them. "
                                  "The preview can change before execution; you may need to sign out after switching.")
            .arg(packages)
            .arg(plan.pathsWritten.size())
            .arg(plan.pathsRemoved.size())
            .arg(affected);
        if (QMessageBox::question(this, tr("Switch to %1?").arg(id), detail,
                                  QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
            return;
        status_->setText(tr("Activating Profile %1 in a terminal…").arg(id));
        catdot_->select(id, !plan.missingPackages.isEmpty(), [this, id](bool ok, const QString &message) {
            if (ok) {
                refresh();
                QMessageBox::information(this, tr("Profile activated"),
                    tr("%1 is active. Sign out and sign back in for desktop changes to take effect.").arg(id));
            } else {
                status_->setText(tr("Profile switch did not complete."));
                QMessageBox::warning(this, tr("Profile activation"),
                    message.isEmpty() ? tr("The Profile was not activated. Review the terminal output.") : message);
            }
        });
    });
}
