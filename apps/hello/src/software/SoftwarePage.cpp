#include "software/SoftwarePage.h"
#include "ToolRunner.h"
#include "desktop/DesktopPage.h"

#include <QFrame>
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
    auto *heading = new QLabel(tr("Install and update applications with Shelly"), software);
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
    layout->addWidget(desktop);
    layout->addStretch();
}

void SoftwarePage::showDesktopSettings()
{
    if (auto *desktop = findChild<QFrame *>(QStringLiteral("desktopSection")))
        if (auto *scroll = findChild<QScrollArea *>()) scroll->ensureWidgetVisible(desktop);
}
