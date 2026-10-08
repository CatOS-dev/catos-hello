#include "about/AboutPage.h"
#include "home/Environment.h"
#include "TipsTab.h"
#include "ui/ActionList.h"

#include <QGridLayout>
#include <QLabel>
#include <QUrl>
#include <QVBoxLayout>

AboutPage::AboutPage(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(28, 20, 34, 28);
    layout->setSpacing(5);
    Ui::addTitle(layout, this, tr("About CatOS"),
        tr("%1 — based on Arch Linux, built for daily use.").arg(Environment::detect().osName));

    auto addLinks = [this, layout](const QString &section,
                                   const QList<QPair<QString, QString>> &items) {
        Ui::addSection(layout, this, section);
        auto *grid = new QGridLayout;
        grid->setHorizontalSpacing(24);
        grid->setVerticalSpacing(12);
        int index = 0;
        for (const auto &item : items) {
            auto *link = new QLabel(this);
            link->setTextFormat(Qt::RichText);
            link->setText(QStringLiteral("<a href=\"%1\">%2 ↗</a>")
                              .arg(item.second.toHtmlEscaped(), item.first.toHtmlEscaped()));
            link->setTextInteractionFlags(Qt::TextBrowserInteraction);
            link->setOpenExternalLinks(true);
            link->setFocusPolicy(Qt::StrongFocus);
            link->setAccessibleName(item.first);
            grid->addWidget(link, index / 2, index % 2);
            ++index;
        }
        layout->addLayout(grid);
    };

    addLinks(tr("CatOS resources"), {
        {tr("CatOS website"), QStringLiteral("https://www.catos.info/")},
        {tr("CatOS project"), QStringLiteral("https://github.com/CatOS-Home/CatOS")},
        {tr("CatOS update history"), QStringLiteral("https://github.com/CatOS-Home/CatOS/commits/main/")},
        {tr("CatOS releases"), QStringLiteral("https://github.com/CatOS-Home/CatOS/releases")},
        {tr("Support CatOS on DistroWatch"), QStringLiteral("https://distrowatch.com/dwres-mobile.php?resource=links#new")}
    });
    addLinks(tr("Documentation and community"), {
        {tr("Arch Linux website"), QStringLiteral("https://archlinux.org/")},
        {tr("Arch Linux Wiki"), QStringLiteral("https://wiki.archlinux.org")},
        {tr("Arch LinuxCN Wiki"), QStringLiteral("https://wiki.archlinuxcn.org/")},
        {tr("Package manager command reference"),
         QStringLiteral("https://wiki.archlinuxcn.org/wiki/Pacman/%E5%90%84%E8%BD%AF%E4%BB%B6%E5%8C%85%E7%AE%A1%E7%90%86%E5%99%A8%E5%91%BD%E4%BB%A4%E5%AF%B9%E5%BA%94%E5%85%B3%E7%B3%BB")},
        {tr("Software news"), QStringLiteral("https://archlinux.org/")}
    });

    Ui::addSection(layout, this, tr("Getting to know CatOS"));
    layout->addWidget(new TipsTab(this), 1);
}
