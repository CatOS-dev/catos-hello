#include "InstallAppsTab.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QProcess>
#include <QRegularExpression>
#include <QStringList>
#include <QTextStream>

InstallAppsTab::InstallAppsTab(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    onReloadClicked();
}

void InstallAppsTab::setupUi()
{
    layout = new QVBoxLayout(this);

    installAppsLabel = new QLabel(tr("Select desktop environment packages to install."), this);
    sourceLabel = new QLabel(this);
    sourceLabel->setWordWrap(true);

    groupsTreeView = new QTreeWidget(this);
    groupsTreeView->setHeaderLabels({ tr("Desktop / Package"), tr("Description / Status") });
    groupsTreeView->setAlternatingRowColors(true);
    groupsTreeView->setRootIsDecorated(true);
    groupsTreeView->setUniformRowHeights(true);
    groupsTreeView->header()->setStretchLastSection(false);
    groupsTreeView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    groupsTreeView->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);

    installButton = new QPushButton(tr("Install Selected"), this);
    reloadButton = new QPushButton(tr("Reload"), this);

    auto* actionLayout = new QHBoxLayout();
    actionLayout->addWidget(reloadButton);
    actionLayout->addStretch();
    actionLayout->addWidget(installButton);

    layout->addWidget(installAppsLabel);
    layout->addWidget(sourceLabel);
    layout->addWidget(groupsTreeView, 1);
    layout->addLayout(actionLayout);

    connect(installButton, &QPushButton::clicked, this, &InstallAppsTab::onInstallClicked);
    connect(reloadButton, &QPushButton::clicked, this, &InstallAppsTab::onReloadClicked);

    setLayout(layout);
}

QString InstallAppsTab::locateDesktopYaml() const
{
    const QStringList candidates = {
        QStringLiteral("/var/lib/catos-hello/desktop.yaml"),
        QDir::currentPath() + QStringLiteral("/data/desktop.yaml"),
        QCoreApplication::applicationDirPath() + QStringLiteral("/desktop.yaml")
    };

    for (const QString& path : candidates) {
        if (QFileInfo::exists(path)) {
            return path;
        }
    }
    return QString();
}

bool InstallAppsTab::loadDesktopGroups(QString* errorMessage)
{
    groups_.clear();

    const QString yamlPath = locateDesktopYaml();
    if (yamlPath.isEmpty()) {
        if (errorMessage) {
            *errorMessage = tr("desktop.yaml not found. Expected at /var/lib/catos-hello/desktop.yaml");
        }
        return false;
    }

    QFile file(yamlPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (errorMessage) {
            *errorMessage = tr("Unable to open %1").arg(yamlPath);
        }
        return false;
    }

    sourceLabel->setText(tr("Data source: %1").arg(yamlPath));

    QTextStream in(&file);
    DesktopGroup currentGroup;
    bool inPackages = false;
    bool seenGroup = false;
    auto parseBool = [](const QString& value) {
        const QString normalized = value.trimmed().toLower();
        return normalized == QStringLiteral("true")
               || normalized == QStringLiteral("yes")
               || normalized == QStringLiteral("on")
               || normalized == QStringLiteral("1");
    };

    while (!in.atEnd()) {
        const QString rawLine = in.readLine();
        const QString line = rawLine.trimmed();
        if (line.isEmpty() || line.startsWith('#')) {
            continue;
        }

        QRegularExpression groupRx("^\\s*-\\s*name\\s*:\\s*(.+)\\s*$");
        QRegularExpression packageRx("^\\s*-\\s*([a-zA-Z0-9@._+-]+)\\s*$");

        auto groupMatch = groupRx.match(rawLine);
        if (groupMatch.hasMatch()) {
            if (seenGroup && !currentGroup.name.isEmpty()) {
                currentGroup.packages.removeDuplicates();
                groups_.append(currentGroup);
            }
            currentGroup = DesktopGroup{};
            QString name = groupMatch.captured(1).trimmed();
            if ((name.startsWith('"') && name.endsWith('"')) || (name.startsWith('\'') && name.endsWith('\''))) {
                name = name.mid(1, name.size() - 2);
            }
            currentGroup.name = name;
            inPackages = false;
            seenGroup = true;
            continue;
        }

        if (line == QStringLiteral("packages:")) {
            inPackages = true;
            continue;
        }

        if (line.startsWith(QStringLiteral("description:"))) {
            QString value = line.section(':', 1).trimmed();
            if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith('\'') && value.endsWith('\''))) {
                value = value.mid(1, value.size() - 2);
            }
            currentGroup.description = value;
            inPackages = false;
            continue;
        }

        if (line.startsWith(QStringLiteral("expanded:"))) {
            const QString value = line.section(':', 1).trimmed();
            currentGroup.expanded = parseBool(value);
            inPackages = false;
            continue;
        }

        if (inPackages) {
            auto pkgMatch = packageRx.match(rawLine);
            if (pkgMatch.hasMatch()) {
                currentGroup.packages.append(pkgMatch.captured(1).trimmed());
            }
        }
    }

    if (seenGroup && !currentGroup.name.isEmpty()) {
        currentGroup.packages.removeDuplicates();
        groups_.append(currentGroup);
    }

    if (groups_.isEmpty()) {
        if (errorMessage) {
            *errorMessage = tr("No desktop groups found in %1").arg(yamlPath);
        }
        return false;
    }

    return true;
}

QSet<QString> InstallAppsTab::queryInstalledPackages() const
{
    QSet<QString> result;
    QProcess pacman;
    pacman.start(QStringLiteral("pacman"), { QStringLiteral("-Qq") });
    if (!pacman.waitForFinished(12000) || pacman.exitCode() != 0) {
        return result;
    }

    const QString output = QString::fromUtf8(pacman.readAllStandardOutput());
    const QStringList pkgs = output.split('\n', Qt::SkipEmptyParts);
    for (const QString& pkg : pkgs) {
        result.insert(pkg.trimmed());
    }
    return result;
}

void InstallAppsTab::rebuildTree()
{
    groupsTreeView->clear();
    itemPackageMap_.clear();

    for (const DesktopGroup& group : groups_) {
        auto* groupItem = new QTreeWidgetItem(groupsTreeView);
        groupItem->setText(0, group.name);
        groupItem->setText(1, group.description);
        groupItem->setToolTip(0, group.description);
        groupItem->setToolTip(1, group.description);
        groupItem->setFlags(groupItem->flags() | Qt::ItemIsUserCheckable | Qt::ItemIsUserTristate);
        groupItem->setCheckState(0, Qt::Unchecked);

        int installedCount = 0;
        for (const QString& pkg : group.packages) {
            auto* pkgItem = new QTreeWidgetItem(groupItem);
            const bool installed = installedPackages_.contains(pkg);
            pkgItem->setText(0, pkg);
            pkgItem->setText(1, installed ? tr("Installed") : tr("Not installed"));
            pkgItem->setData(0, Qt::UserRole, installed);
            pkgItem->setFlags(pkgItem->flags() | Qt::ItemIsUserCheckable);
            pkgItem->setCheckState(0, installed ? Qt::Checked : Qt::Unchecked);
            itemPackageMap_.insert(pkgItem, pkg);
            if (installed) {
                installedCount++;
            }
        }

        if (installedCount == group.packages.size() && !group.packages.isEmpty()) {
            groupItem->setCheckState(0, Qt::Checked);
        } else if (installedCount > 0) {
            groupItem->setCheckState(0, Qt::PartiallyChecked);
        }
    }

    for (int row = 0; row < groupsTreeView->topLevelItemCount(); ++row) {
        auto* groupItem = groupsTreeView->topLevelItem(row);
        if (!groupItem) {
            continue;
        }
        const bool expanded = groups_.value(row).expanded;
        if (expanded) {
            groupsTreeView->expandItem(groupItem);
        } else {
            groupsTreeView->collapseItem(groupItem);
        }
    }
}

void InstallAppsTab::onReloadClicked()
{
    QString error;
    if (!loadDesktopGroups(&error)) {
        groupsTreeView->clear();
        QMessageBox::warning(this, tr("Install Apps"), error);
        return;
    }

    installedPackages_ = queryInstalledPackages();
    rebuildTree();
}

void InstallAppsTab::onInstallClicked()
{
    const QString runInTerminal = QStringLiteral("/usr/bin/RunInTerminal");
    if (!QFileInfo::exists(runInTerminal)) {
        QMessageBox::critical(
            this,
            tr("Install Apps"),
            tr("RunInTerminal not found at %1").arg(runInTerminal));
        return;
    }

    installedPackages_ = queryInstalledPackages();
    QStringList toInstall;

    for (auto it = itemPackageMap_.cbegin(); it != itemPackageMap_.cend(); ++it) {
        QTreeWidgetItem* item = it.key();
        if (item->checkState(0) != Qt::Checked) {
            continue;
        }
        const QString pkg = it.value();
        if (!installedPackages_.contains(pkg)) {
            toInstall.append(pkg);
        }
    }

    toInstall.removeDuplicates();
    if (toInstall.isEmpty()) {
        QMessageBox::information(this, tr("Install Apps"), tr("No new packages selected for installation."));
        return;
    }

    const QString command = QStringLiteral("sudo pacman -S --needed ") + toInstall.join(' ');
    QStringList args;
    args << QStringLiteral("--prompt")
         << tr("Install desktop environment packages")
         << command;

    QProcess::startDetached(runInTerminal, args);
}
