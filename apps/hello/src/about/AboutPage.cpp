#include "about/AboutPage.h"
#include "home/Environment.h"
#include "TipsTab.h"

#include <QGridLayout>
#include <QDesktopServices>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QUrl>
#include <QVBoxLayout>

AboutPage::AboutPage(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    auto *title = new QLabel(tr("About CatOS"), this);
    QFont font = title->font();
    font.setPointSize(font.pointSize() + 7);
    font.setBold(true);
    title->setFont(font);
    layout->addWidget(title);
    auto *description = new QLabel(tr("%1 — based on Arch Linux, built for daily use.")
                                       .arg(Environment::detect().osName), this);
    description->setWordWrap(true);
    layout->addWidget(description);

    auto *links = new QGridLayout;
    int index = 0;
    for (const auto &item : {
             qMakePair(tr("CatOS website"), QStringLiteral("https://www.catos.info/")),
             qMakePair(tr("CatOS project"), QStringLiteral("https://github.com/CatOS-Home/CatOS")),
             qMakePair(tr("CatOS update history"), QStringLiteral("https://github.com/CatOS-Home/CatOS/commits/main/")),
             qMakePair(tr("CatOS releases"), QStringLiteral("https://github.com/CatOS-Home/CatOS/releases")),
             qMakePair(tr("Arch Linux website"), QStringLiteral("https://archlinux.org/")),
             qMakePair(tr("Arch Linux Wiki"), QStringLiteral("https://wiki.archlinux.org")),
             qMakePair(tr("Arch LinuxCN Wiki"), QStringLiteral("https://wiki.archlinuxcn.org/")),
             qMakePair(tr("Support CatOS on DistroWatch"), QStringLiteral("https://distrowatch.com/dwres-mobile.php?resource=links#new")),
             qMakePair(tr("Package manager command reference"),
                       QStringLiteral("https://wiki.archlinuxcn.org/wiki/Pacman/%E5%90%84%E8%BD%AF%E4%BB%B6%E5%8C%85%E7%AE%A1%E7%90%86%E5%99%A8%E5%91%BD%E4%BB%A4%E5%AF%B9%E5%BA%94%E5%85%B3%E7%B3%BB")),
             qMakePair(tr("Software news"), QStringLiteral("https://archlinux.org/"))}) {
        auto *button = new QPushButton(item.first, this);
        connect(button, &QPushButton::clicked, this, [url = item.second] {
            QDesktopServices::openUrl(QUrl(url));
        });
        links->addWidget(button, index / 2, index % 2);
        ++index;
    }
    layout->addLayout(links);

    auto *tips = new QLabel(tr("Getting to know CatOS"), this);
    QFont tipsFont = tips->font();
    tipsFont.setBold(true);
    tips->setFont(tipsFont);
    layout->addWidget(tips);
    layout->addWidget(new TipsTab(this), 1);
}
