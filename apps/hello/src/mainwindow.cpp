#include "mainwindow.h"
#include "ToolRunner.h"
#include "about/AboutPage.h"
#include "home/HomePage.h"
#include "maintenance/MaintenancePage.h"
#include "software/SoftwarePage.h"

#include <QFile>
#include <QDir>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QStackedWidget>
#include <QVBoxLayout>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
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
    sidebar->setFrameShape(QFrame::StyledPanel);
    sidebar->setFixedWidth(214);
    auto *sidebarLayout = new QVBoxLayout(sidebar);
    sidebarLayout->setContentsMargins(14, 20, 14, 16);
    auto *logo = new QLabel(tr("CatOS Hello"), sidebar);
    QFont brand = logo->font();
    brand.setBold(true);
    brand.setPointSize(brand.pointSize() + 5);
    logo->setFont(brand);
    sidebarLayout->addWidget(logo);
    navigation_ = new QListWidget(sidebar);
    navigation_->addItems({tr("Home"), tr("Software and desktop"),
                           tr("System maintenance"), tr("About CatOS")});
    navigation_->setFrameShape(QFrame::NoFrame);
    navigation_->setSpacing(7);
    sidebarLayout->addWidget(navigation_);

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
    sidebarLayout->addWidget(hideAtLogin);
    if (!QFile::exists(QDir::homePath() + QStringLiteral("/.config/autostart/catos-hello.desktop"))) {
        hideAtLogin->setEnabled(false);
        hideAtLogin->setText(tr("Autostart disabled"));
    }
    layout->addWidget(sidebar);

    pages_ = new QStackedWidget(central);
    auto *home = new HomePage(pages_);
    software_ = new SoftwarePage(tools_, pages_);
    maintenance_ = new MaintenancePage(tools_, pages_);
    pages_->addWidget(home);
    pages_->addWidget(software_);
    pages_->addWidget(maintenance_);
    pages_->addWidget(new AboutPage(pages_));
    layout->addWidget(pages_, 1);
    setCentralWidget(central);
    connect(navigation_, &QListWidget::currentRowChanged, pages_, &QStackedWidget::setCurrentIndex);
    navigation_->setCurrentRow(0);
    connect(home, &HomePage::navigateTo, this, &MainWindow::navigate);
    connect(home, &HomePage::actionRequested, this, &MainWindow::dispatchHomeAction);
}

void MainWindow::navigate(const QString &page)
{
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
    if (action == QStringLiteral("shelly")) {
        if (!ToolRunner::launch(QStringLiteral("shelly-ui")))
            QMessageBox::warning(this, tr("Shelly unavailable"), tr("The Shelly graphical application is not installed."));
    } else if (action == QStringLiteral("install")) {
        if (!ToolRunner::launch(QStringLiteral("calamares_polkit")))
            QMessageBox::warning(this, tr("Installer"), tr("Calamares is not available."));
    } else if (action == QStringLiteral("install-advanced")) {
        if (!ToolRunner::launch(QStringLiteral("calamares_polkit"), {QStringLiteral("--config"),
                                                                     QStringLiteral("/usr/share/calamares-advanced")}))
            QMessageBox::warning(this, tr("Installer"), tr("Calamares is not available."));
    } else if (action == QStringLiteral("drivers")) navigate(QStringLiteral("drivers"));
    else navigate(action);
}
