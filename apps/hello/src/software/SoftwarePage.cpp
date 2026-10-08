#include "software/SoftwarePage.h"
#include "ToolRunner.h"
#include "desktop/DesktopPage.h"
#include "software/InstallAppsTab.h"
#include "ui/ActionList.h"

#include <QDialog>
#include <QFrame>
#include <QMessageBox>
#include <QScrollArea>
#include <QVBoxLayout>

SoftwarePage::SoftwarePage(ToolRunner *tools, QWidget *parent) : QWidget(parent)
{
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    auto *scroll = new QScrollArea(this);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidgetResizable(true);
    outer->addWidget(scroll);
    auto *content = new QWidget(scroll);
    scroll->setWidget(content);
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(28, 20, 34, 28);
    layout->setSpacing(4);

    Ui::addTitle(layout, content, tr("Software and desktop"));
    Ui::addSection(layout, content, tr("Applications"));
    auto *shelly = Ui::addAction(layout, content, tr("Open Shelly"),
        tr("Install and manage repository, AUR, Flatpak and AppImage applications."),
        QStringLiteral("applications-system"));
    connect(shelly, &QPushButton::clicked, this, [this] {
        if (!ToolRunner::launch(QStringLiteral("shelly-ui")))
            QMessageBox::warning(this, tr("Shelly unavailable"),
                                 tr("The Shelly graphical application is not installed."));
    });

    Ui::addSection(layout, content, tr("Desktop environments"));
    auto *choose = Ui::addAction(layout, content, tr("Install other desktop environments"),
                                 tr("Choose desktop packages and check which are already installed."),
                                 QStringLiteral("preferences-desktop"));
    choose->setObjectName(QStringLiteral("desktopPackagesButton"));
    choose->setToolTip(tr("Choose desktop environments…"));
    connect(choose, &QPushButton::clicked, this, [this] {
        QDialog dialog(this);
        dialog.setObjectName(QStringLiteral("desktopPackagesDialog"));
        dialog.setWindowTitle(tr("Install desktop environments"));
        dialog.resize(860, 580);
        auto *dialogLayout = new QVBoxLayout(&dialog);
        dialogLayout->addWidget(new InstallAppsTab(&dialog));
        dialog.exec();
    });

    Ui::addSection(layout, content, tr("Desktop settings"));
    auto *desktop = new QWidget(content);
    desktop->setObjectName(QStringLiteral("desktopSection"));
    desktopLayout_ = new QVBoxLayout(desktop);
    desktopLayout_->setContentsMargins(0, 0, 0, 0);
    desktopLayout_->addWidget(new DesktopPage(tools, desktop));
    layout->addWidget(desktop);
    layout->addStretch();
}

void SoftwarePage::showDesktopSettings()
{
    if (auto *desktop = findChild<QWidget *>(QStringLiteral("desktopSection")))
        if (auto *scroll = findChild<QScrollArea *>()) scroll->ensureWidgetVisible(desktop);
}
