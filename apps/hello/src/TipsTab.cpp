#include "TipsTab.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLocale>
#include <QStringList>

TipsTab::TipsTab(QWidget *parent)
    : QWidget(parent)
{
    layout = new QVBoxLayout(this);
    tipsBrowser = new QTextBrowser(this);

    tipsBrowser->setHtml(loadTipsHtml(detectUiLanguage()));
    tipsBrowser->setOpenExternalLinks(true);

    layout->addWidget(tipsBrowser);
    setLayout(layout);
}

QString TipsTab::detectUiLanguage() const
{
    const QString cliLang = QCoreApplication::arguments().value(1).trimmed();
    if (!cliLang.isEmpty()) {
        return cliLang;
    }
    return QLocale::system().name();
}

QString TipsTab::locateTipsHtml(const QString& uiLang) const
{
    const QString normalized = uiLang.trimmed();
    const QString languageOnly = normalized.section('_', 0, 0);

    const QStringList fileCandidates = {
        normalized + QStringLiteral(".html"),
        languageOnly + QStringLiteral(".html"),
        QStringLiteral("en_US.html"),
        QStringLiteral("en.html")
    };

    const QStringList baseDirs = {
        QStringLiteral("/var/lib/catos-hello/news"),
        QDir::currentPath() + QStringLiteral("/data/news"),
        QCoreApplication::applicationDirPath() + QStringLiteral("/news")
    };

    for (const QString& dir : baseDirs) {
        for (const QString& file : fileCandidates) {
            if (file == QStringLiteral(".html")) {
                continue;
            }
            const QString path = dir + QLatin1Char('/') + file;
            if (QFileInfo::exists(path) && QFileInfo(path).isFile()) {
                return path;
            }
        }
    }
    return QString();
}

QString TipsTab::loadTipsHtml(const QString& uiLang) const
{
    const QString htmlPath = locateTipsHtml(uiLang);
    if (htmlPath.isEmpty()) {
        return QStringLiteral(
            "<h3>Tips Content Missing</h3>"
            "<p>Could not find tips HTML under /var/lib/catos-hello/news.</p>");
    }

    QFile file(htmlPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return QStringLiteral(
            "<h3>Tips Content Error</h3>"
            "<p>Failed to read tips HTML file: %1</p>")
            .arg(htmlPath.toHtmlEscaped());
    }

    return QString::fromUtf8(file.readAll());
}
