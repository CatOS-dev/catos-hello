#include "software/SoftwarePage.h"
#include "ToolRunner.h"
#include "desktop/DesktopPage.h"
#include "software/InstallAppsTab.h"

#include <QFrame>
#include <QDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QMessageBox>

SoftwarePage::SoftwarePage(ToolRunner *tools, QWidget *parent) : QWidget(parent)
{
    auto *outer = new QVBoxLayout(this);
    auto *scroll = new QScrollArea(this);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidgetResizable(true);
    outer->addWidget(scroll);
    auto *content = new QWidget(scroll);
    scroll->setWidget(content);
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(18, 14, 22, 20);
    layout->setSpacing(18);

    auto *title = new QLabel(tr("Software and desktop"), content);
    QFont font = title->font();
    font.setPointSize(font.pointSize() + 7);
    font.setBold(true);
    title->setFont(font);
    layout->addWidget(title);

    auto *software = new QFrame(content);
    software->setFrameShape(QFrame::StyledPanel);
    auto *softwareLayout = new QVBoxLayout(software);
    auto *heading = new QLabel(tr("Install applications with Shelly"), software);
    QFont headingFont = heading->font();
    headingFont.setBold(true);
    heading->setFont(headingFont);
    softwareLayout->addWidget(heading);
    auto *info = new QLabel(tr("Manage repository packages, AUR, Flatpak and AppImage applications in one place."), software);
    info->setWordWrap(true);
    softwareLayout->addWidget(info);
    auto *open = new QPushButton(tr("Open Shelly"), software);
    connect(open, &QPushButton::clicked, this, [this] {
        if (!ToolRunner::launch(QStringLiteral("shelly-ui")))
            QMessageBox::warning(this, tr("Shelly unavailable"), tr("The Shelly graphical application is not installed."));
    });
    softwareLayout->addWidget(open, 0, Qt::AlignLeft);
    layout->addWidget(software);

    auto *desktop = new QFrame(content);
    desktop->setObjectName(QStringLiteral("desktopSection"));
    desktop->setFrameShape(QFrame::StyledPanel);
    desktopLayout_ = new QVBoxLayout(desktop);
    desktopLayout_->addWidget(new DesktopPage(tools, desktop));
    auto *environments = new QFrame(content);
    auto *environmentsLayout = new QHBoxLayout(environments);
    environmentsLayout->setContentsMargins(0, 6, 0, 6);
    auto *description = new QLabel(tr("Install other desktop environments"), environments);
    environmentsLayout->addWidget(description, 1);
    auto *choose = new QPushButton(tr("Choose desktop environments…"), environments);
    choose->setObjectName(QStringLiteral("desktopPackagesButton"));
    connect(choose, &QPushButton::clicked, this, [this] {
        QDialog dialog(this);
        dialog.setObjectName(QStringLiteral("desktopPackagesDialog"));
        dialog.setWindowTitle(tr("Install desktop environments"));
        dialog.resize(860, 580);
        auto *dialogLayout = new QVBoxLayout(&dialog);
        dialogLayout->addWidget(new InstallAppsTab(&dialog));
        dialog.exec();
    });
    environmentsLayout->addWidget(choose);
    layout->addWidget(environments);

    layout->addWidget(desktop);
    layout->addStretch();
}

void SoftwarePage::showDesktopSettings()
{
    if (auto *desktop = findChild<QFrame *>(QStringLiteral("desktopSection")))
        if (auto *scroll = findChild<QScrollArea *>()) scroll->ensureWidgetVisible(desktop);
}
