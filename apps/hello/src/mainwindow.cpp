#include "mainwindow.h"
#include "ToolRunner.h"
#include "about/AboutPage.h"
#include "MirrorListWindow.h"
#include "RepoListWindow.h"
#include "home/HomePage.h"
#include "maintenance/MaintenancePage.h"
#include "software/SoftwarePage.h"
#include "ui/ActionList.h"

#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QScrollArea>
#include <QStackedWidget>
#include <QTemporaryDir>
#include <QUrl>
#include <QVBoxLayout>
#include <memory>
#include <unistd.h>

MainWindow::MainWindow(const Environment &environment, QWidget *parent)
    : QMainWindow(parent), live_(environment.live)
{
    setWindowTitle(tr("CatOS Hello"));
    resize(1040, 700);
    setMinimumSize(760, 520);
    tools_ = new ToolRunner(this);
    auto *central = new QWidget(this);
    auto *layout = new QHBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    auto *sidebar = new QFrame(central);
    sidebar->setFrameShape(QFrame::NoFrame);
    sidebar->setFixedWidth(218);
    auto sidebarPalette = sidebar->palette();
    sidebarPalette.setColor(QPalette::Window, sidebarPalette.color(QPalette::AlternateBase));
    sidebar->setPalette(sidebarPalette);
    sidebar->setAutoFillBackground(true);
    auto *sidebarLayout = new QVBoxLayout(sidebar);
    sidebarLayout->setContentsMargins(14, 20, 14, 16);
    auto *logo = new QLabel(tr("CatOS Hello"), sidebar);
    QFont brand = logo->font();
    brand.setBold(true);
    brand.setPointSize(brand.pointSize() + 5);
    logo->setFont(brand);
    sidebarLayout->addWidget(logo);
    navigation_ = new QListWidget(sidebar);
    navigation_->setObjectName(QStringLiteral("navigation"));
    if (live_) navigation_->addItems({tr("Install CatOS"), tr("Disk and recovery"), tr("About CatOS")});
    else navigation_->addItems({tr("Home"), tr("Software and desktop"),
                                tr("System maintenance"), tr("About CatOS")});
    navigation_->setFrameShape(QFrame::NoFrame);
    navigation_->setSpacing(7);
    navigation_->setStyleSheet(QStringLiteral(
        "QListWidget { background: transparent; border: none; }"
        "QListWidget::item { padding: 10px 12px; border-radius: 8px; }"
        "QListWidget::item:selected { background: palette(highlight); color: palette(highlighted-text); }"));
    sidebarLayout->addWidget(navigation_);

    if (!live_) {
        auto *hideAtLogin = new QPushButton(tr("Don't open at login"), sidebar);
        connect(hideAtLogin, &QPushButton::clicked, this, [this, hideAtLogin] {
            const QString path = QDir::homePath() + QStringLiteral("/.config/autostart/catos-hello.desktop");
            if (QFile::exists(path) && !QFile::remove(path)) {
                QMessageBox::warning(this, tr("Autostart"), tr("Could not disable automatic startup."));
                return;
            }
            hideAtLogin->setEnabled(false);
            hideAtLogin->setText(tr("Autostart disabled"));
        });
        hideAtLogin->setFlat(true);
        sidebarLayout->addWidget(hideAtLogin);
        if (!QFile::exists(QDir::homePath() + QStringLiteral("/.config/autostart/catos-hello.desktop"))) {
            hideAtLogin->setEnabled(false);
            hideAtLogin->setText(tr("Autostart disabled"));
        }
    }
    auto *exitButton = new QPushButton(tr("Exit"), sidebar);
    exitButton->setObjectName(QStringLiteral("exitButton"));
    exitButton->setFlat(true);
    connect(exitButton, &QPushButton::clicked, qApp, &QApplication::quit);
    sidebarLayout->addWidget(exitButton);
    layout->addWidget(sidebar);

    auto *mainContent = new QWidget(central);
    auto *contentLayout = new QVBoxLayout(mainContent);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    auto *languageBar = new QHBoxLayout;
    languageBar->setContentsMargins(18, 8, 20, 4);
    languageBar->addStretch();
    languageBar->addWidget(new QLabel(tr("Language"), mainContent));
    auto *languages = new QComboBox(mainContent);
    languages->setObjectName(QStringLiteral("languageSelect"));
    languages->addItem(tr("System default"), QString());
    languages->addItem(QStringLiteral("简体中文"), QStringLiteral("zh_CN"));
    languages->addItem(QStringLiteral("English"), QStringLiteral("en_US"));
    languages->addItem(QStringLiteral("Français"), QStringLiteral("fr"));
    languages->addItem(QStringLiteral("Deutsch"), QStringLiteral("de"));
    const QString selected = qApp->arguments().value(1);
    const int current = languages->findData(selected);
    if (current >= 0) languages->setCurrentIndex(current);
    languageBar->addWidget(languages);
    auto *apply = new QPushButton(tr("Apply"), mainContent);
    apply->setObjectName(QStringLiteral("applyLanguage"));
    connect(apply, &QPushButton::clicked, this, [languages] {
        QStringList args;
        const QString locale = languages->currentData().toString();
        if (!locale.isEmpty()) args << locale;
        if (QProcess::startDetached(QCoreApplication::applicationFilePath(), args)) qApp->quit();
    });
    languageBar->addWidget(apply);
    contentLayout->addLayout(languageBar);

    pages_ = new QStackedWidget(mainContent);
    auto *home = new HomePage(environment, pages_);
    pages_->addWidget(home);
    if (live_) {
        auto *recovery = new QWidget(pages_);
        auto *recoveryOuter = new QVBoxLayout(recovery);
        recoveryOuter->setContentsMargins(0, 0, 0, 0);
        auto *scroll = new QScrollArea(recovery);
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        recoveryOuter->addWidget(scroll);
        auto *content = new QWidget(scroll);
        scroll->setWidget(content);
        auto *recoveryLayout = new QVBoxLayout(content);
        recoveryLayout->setContentsMargins(28, 20, 34, 28);
        recoveryLayout->setSpacing(4);
        Ui::addTitle(recoveryLayout, content, tr("Disk and recovery"),
                     tr("Tools for disk preparation and troubleshooting in the live session."));
        Ui::addSection(recoveryLayout, content, tr("Disk utilities"));
        for (const auto &item : {
                 qMakePair(tr("Partition disks (GParted)"), QStringLiteral("partition")),
                 qMakePair(tr("Recover partitions (TestDisk)"), QStringLiteral("testdisk"))}) {
            auto *action = Ui::addAction(recoveryLayout, content, item.first,
                item.second == QStringLiteral("partition")
                    ? tr("Create, resize or inspect disk partitions.")
                    : tr("Find and recover missing partition tables."),
                QStringLiteral("drive-harddisk"));
            action->setObjectName(item.second);
            connect(action, &QPushButton::clicked, this, [this, operation = item.second] {
                dispatchHomeAction(operation);
            });
        }
        Ui::addSection(recoveryLayout, content, tr("Installation diagnostics"));
        for (const auto &item : {
                 qMakePair(tr("Get installation logs"), QStringLiteral("install-log")),
                 qMakePair(tr("Collect system logs"), QStringLiteral("collect-logs"))}) {
            auto *action = Ui::addAction(recoveryLayout, content, item.first,
                item.second == QStringLiteral("install-log")
                    ? tr("Extract Calamares logs and open them in Kate.")
                    : tr("Export system information for troubleshooting."),
                QStringLiteral("text-x-log"));
            action->setObjectName(item.second);
            connect(action, &QPushButton::clicked, this, [this, operation = item.second] {
                dispatchHomeAction(operation);
            });
        }
        Ui::addSection(recoveryLayout, content, tr("Additional tools"));
        for (const auto &item : {
                 qMakePair(tr("Open terminal"), QStringLiteral("terminal")),
                 qMakePair(tr("Select package mirrors"), QStringLiteral("mirrors")),
                 qMakePair(tr("Edit pacman repositories"), QStringLiteral("repositories"))}) {
            const QString detail = item.second == QStringLiteral("terminal")
                ? tr("Run commands in the live session.")
                : item.second == QStringLiteral("mirrors")
                ? tr("Choose package download mirror servers.")
                : tr("Review pacman repository configuration.");
            const QString icon = item.second == QStringLiteral("terminal")
                ? QStringLiteral("utilities-terminal") : QStringLiteral("network-server");
            auto *action = Ui::addAction(recoveryLayout, content, item.first, detail, icon);
            action->setObjectName(item.second);
            connect(action, &QPushButton::clicked, this, [this, operation = item.second] {
                dispatchHomeAction(operation);
            });
        }
        recoveryLayout->addStretch();
        pages_->addWidget(recovery);
    } else {
        software_ = new SoftwarePage(tools_, pages_);
        maintenance_ = new MaintenancePage(tools_, pages_);
        pages_->addWidget(software_);
        pages_->addWidget(maintenance_);
    }
    pages_->addWidget(new AboutPage(pages_));
    contentLayout->addWidget(pages_, 1);
    layout->addWidget(mainContent, 1);
    setCentralWidget(central);

    connect(navigation_, &QListWidget::currentRowChanged, pages_, &QStackedWidget::setCurrentIndex);
    navigation_->setCurrentRow(0);
    connect(home, &HomePage::navigateTo, this, &MainWindow::navigate);
    connect(home, &HomePage::actionRequested, this, &MainWindow::dispatchHomeAction);
}

void MainWindow::navigate(const QString &page)
{
    if (live_) {
        if (page == QStringLiteral("recovery")) navigation_->setCurrentRow(1);
        else if (page == QStringLiteral("about")) navigation_->setCurrentRow(2);
        return;
    }
    if (page == QStringLiteral("software") || page == QStringLiteral("desktop")) {
        navigation_->setCurrentRow(1);
        if (page == QStringLiteral("desktop")) software_->showDesktopSettings();
    } else if (page == QStringLiteral("maintenance") || page == QStringLiteral("drivers")) {
        navigation_->setCurrentRow(2);
        if (page == QStringLiteral("drivers")) maintenance_->showDrivers();
    } else if (page == QStringLiteral("about")) navigation_->setCurrentRow(3);
    else navigation_->setCurrentRow(0);
}

void MainWindow::dispatchHomeAction(const QString &action)
{
    if (live_) {
        if (action == QStringLiteral("install") || action == QStringLiteral("install-advanced")) {
            QStringList args;
            if (action == QStringLiteral("install-advanced"))
                args << QStringLiteral("--config") << QStringLiteral("/usr/share/calamares-advanced");
            if (!ToolRunner::launch(QStringLiteral("calamares_polkit"), args))
                QMessageBox::warning(this, tr("Installer"), tr("Calamares is not available."));
        } else if (action == QStringLiteral("install-log")) viewInstallLogs();
        else if (action == QStringLiteral("partition")) {
            if (!ToolRunner::launch(QStringLiteral("gparted")))
                QMessageBox::warning(this, tr("Disk and recovery"), tr("GParted is not available."));
        } else if (action == QStringLiteral("testdisk")) {
            if (!ToolRunner::launch(QStringLiteral("konsole"), {QStringLiteral("-e"), QStringLiteral("pkexec"), QStringLiteral("testdisk")}))
                QMessageBox::warning(this, tr("Disk and recovery"), tr("TestDisk is not available."));
        } else if (action == QStringLiteral("terminal")) {
            if (!ToolRunner::launch(QStringLiteral("konsole")))
                QMessageBox::warning(this, tr("Disk and recovery"), tr("Terminal is not available."));
        } else if (action == QStringLiteral("mirrors")) MirrorListWindow(this).exec();
        else if (action == QStringLiteral("repositories")) RepoListWindow(this).exec();
        else if (action == QStringLiteral("collect-logs")) {
            tools_->run(QStringLiteral("pkexec"),
                        {QStringLiteral("/usr/bin/CollectLogs"), qEnvironmentVariable("USER")},
                        [this](int code, const QString &, const QString &error) {
                if (code == 0) QMessageBox::information(this, tr("System logs"),
                    tr("The diagnostic archive was saved to your Desktop."));
                else QMessageBox::warning(this, tr("System logs"), error.isEmpty() ?
                    tr("Unable to collect diagnostic logs.") : error);
            });
        }
        return;
    }
    if (action == QStringLiteral("update")) {
        tools_->runInTerminal(tr("Update CatOS"), QStringLiteral("sysup"),
                              [this](int code, const QString &, const QString &error) {
            if (code != 0) QMessageBox::warning(this, tr("Update CatOS"),
                tr("System update did not finish successfully (%1). %2").arg(code).arg(error));
        });
    } else if (action == QStringLiteral("drivers")) navigate(QStringLiteral("drivers"));
    else navigate(action);
}

void MainWindow::viewInstallLogs()
{
    auto directory = std::make_shared<QTemporaryDir>(QDir::tempPath() + QStringLiteral("/catos-install-log-XXXXXX"));
    if (!directory->isValid()) {
        QMessageBox::warning(this, tr("Installation logs"), tr("Unable to prepare a temporary directory."));
        return;
    }
    directory->setAutoRemove(false);
    tools_->run(QStringLiteral("pkexec"),
                {QStringLiteral("/usr/bin/GetInstallLog"), directory->path(),
                 QString::number(getuid()), QString::number(getgid())},
                [this, directory](int code, const QString &, const QString &error) {
        if (code != 0) {
            QMessageBox::warning(this, tr("Installation logs"),
                                 tr("Unable to extract Calamares installation logs. %1").arg(error));
            return;
        }
        QStringList files;
        QDirIterator entries(directory->path(), {QStringLiteral("*.log"), QStringLiteral("*.txt")},
                             QDir::Files, QDirIterator::Subdirectories);
        while (entries.hasNext()) files << entries.next();
        if (files.isEmpty() || !ToolRunner::launch(QStringLiteral("kate"), files))
            QDesktopServices::openUrl(QUrl::fromLocalFile(directory->path()));
    });
}
