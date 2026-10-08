#include "about/AboutPage.h"
#include "home/Environment.h"
#include "TipsTab.h"

#include <QApplication>
#include <QComboBox>
#include <QDesktopServices>
#include <QHBoxLayout>
#include <QLabel>
#include <QProcess>
#include <QCoreApplication>
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

    auto *links = new QHBoxLayout;
    for (const auto &item : {qMakePair(tr("CatOS project"), QStringLiteral("https://github.com/CatOS-Home/CatOS")),
                             qMakePair(tr("Arch Linux Wiki"), QStringLiteral("https://wiki.archlinux.org")),
                             qMakePair(tr("CatOS releases"), QStringLiteral("https://github.com/CatOS-Home/CatOS/releases"))}) {
        auto *button = new QPushButton(item.first, this);
        connect(button, &QPushButton::clicked, this, [url = item.second] {
            QDesktopServices::openUrl(QUrl(url));
        });
        links->addWidget(button);
    }
    layout->addLayout(links);

    auto *language = new QHBoxLayout;
    language->addWidget(new QLabel(tr("Language"), this));
    auto *options = new QComboBox(this);
    options->addItem(tr("System default"), QString());
    options->addItem(QStringLiteral("简体中文"), QStringLiteral("zh_CN"));
    options->addItem(QStringLiteral("English"), QStringLiteral("en_US"));
    options->addItem(QStringLiteral("Français"), QStringLiteral("fr"));
    options->addItem(QStringLiteral("Deutsch"), QStringLiteral("de"));
    const QString selected = qApp->arguments().value(1);
    if (!selected.isEmpty()) {
        const int index = options->findData(selected);
        if (index >= 0) options->setCurrentIndex(index);
    }
    language->addWidget(options);
    auto *apply = new QPushButton(tr("Apply (restart Hello)"), this);
    connect(apply, &QPushButton::clicked, this, [options] {
        QStringList args;
        const QString locale = options->currentData().toString();
        if (!locale.isEmpty()) args << locale;
        if (QProcess::startDetached(QCoreApplication::applicationFilePath(), args)) qApp->quit();
    });
    language->addWidget(apply);
    layout->addLayout(language);

    auto *tips = new QLabel(tr("Getting to know CatOS"), this);
    QFont tipsFont = tips->font();
    tipsFont.setBold(true);
    tips->setFont(tipsFont);
    layout->addWidget(tips);
    layout->addWidget(new TipsTab(this), 1);
}
