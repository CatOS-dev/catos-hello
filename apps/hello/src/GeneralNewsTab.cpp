#include "GeneralNewsTab.h"
#include <QApplication>
#include <QLocale>
#include <QComboBox>
#include <QPushButton>
#include <QMessageBox>
#include <QSettings>
#include <QFile>
#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QSet>

GeneralNewsTab::GeneralNewsTab(QWidget *parent)
    : QWidget(parent)
{
    bool inLiveCd = isLiveCd();
    layout = new QVBoxLayout(this);
    generalNewsLabel = new QLabel(tr("General News"), this);
    generalNewsLabel->setSizePolicy(generalNewsLabel->sizePolicy().horizontalPolicy(), QSizePolicy::Fixed);

    gridLayout = new QGridLayout();

    websiteButton = new QPushButton(tr("Visit Website"));
    archButton = new QPushButton(tr("Visit ArchLinux Website"));
    wikiButton = new QPushButton(tr("Visit ArchLinux Wiki"));
    wikicnButton = new QPushButton(tr("Visit ArchLinuxCN Wiki"));
    supportButton = new QPushButton(tr("Support us on Distrowatch.com"));
    languageComboBox = new QComboBox();
    applyButton = new QPushButton(tr("Apply"));
    mirrorButton = new QPushButton(tr("Modify Mirror List"));
    repoButton = new QPushButton(tr("Modify Repo List"));

    if (inLiveCd) {
        installCatOSButton = new QPushButton(tr("Install CatOS"));
        installCatOSNetButton = new QPushButton(tr("Install CatOS Net Install"));
        getLogButton = new QPushButton(tr("Get Install Log"));
    }

    // 加载语言
    loadLanguages();

    // 连接信号与槽
    connect(applyButton, SIGNAL(clicked()), this, SLOT(onApplyButtonClicked()));
    connect(websiteButton, SIGNAL(clicked()), this, SLOT(onWebsiteButtonClicked()));
    connect(archButton, SIGNAL(clicked()), this, SLOT(onArchWebsiteButtonClicked()));
    connect(wikiButton, SIGNAL(clicked()), this, SLOT(onWikiWebsiteButtonClicked()));
    connect(wikicnButton, SIGNAL(clicked()), this, SLOT(onWikicnWebsiteButtonClicked()));
    connect(mirrorButton, SIGNAL(clicked()), this, SLOT(onMirrorButtonClicked()));
    connect(repoButton, SIGNAL(clicked()), this, SLOT(onRepoButtonClicked()));
    connect(supportButton, SIGNAL(clicked()), this, SLOT(onSupportButtonClicked()));
    if (inLiveCd) {
        connect(installCatOSButton, SIGNAL(clicked()), this, SLOT(onInstallCatOSButtonClicked()));
        connect(installCatOSNetButton, SIGNAL(clicked()), this, SLOT(onInstallCatOSNetButtonClicked()));
        connect(getLogButton, SIGNAL(clicked()), this, SLOT(onGetLogButtonClicked()));
    }
    // 布局
    gridLayout->addWidget(languageComboBox, 0, 0);
    gridLayout->addWidget(applyButton, 0, 1);
    gridLayout->addWidget(websiteButton, 1, 0);
    gridLayout->addWidget(archButton, 1, 1);
    gridLayout->addWidget(wikicnButton, 2, 0);
    gridLayout->addWidget(wikiButton, 2, 1);
    gridLayout->addWidget(mirrorButton, 3, 0);
    gridLayout->addWidget(repoButton, 3, 1);
    gridLayout->addWidget(supportButton, 4, 0);
    if (inLiveCd) {
        gridLayout->addWidget(installCatOSButton, 5, 0);
        gridLayout->addWidget(installCatOSNetButton, 5, 1);
        gridLayout->addWidget(getLogButton, 6, 0);
    }

    layout->addWidget(generalNewsLabel, 0);
    layout->addLayout(gridLayout);
    layout->addWidget(new QLabel("", this)); // 空白标签
}

void GeneralNewsTab::loadLanguages()
{
    qInfo() << "GeneralNewsTab: loadLanguages start";
    languageComboBox->clear();

    // 添加一个表示不加载语言包的 English 选项（放在最前面）
    languageComboBox->addItem(tr("English(US)"), QString());

    // 优先从当前目录加载（用于 debug），然后从系统安装目录加载（打包后使用）
    const QStringList searchPaths = { QDir::currentPath(), QStringLiteral("/usr/share/catos-hello/translations") };
    QSet<QString> seenLocales;
    for (const QString &path : searchPaths) {
        QDir dir(path);
        if (!dir.exists()) {
            qInfo() << "GeneralNewsTab: translations dir not exists:" << path;
            continue;
        }
        const QFileInfoList files = dir.entryInfoList(QStringList() << "*.qm", QDir::Files, QDir::Name);
        for (const QFileInfo &fi : files) {
            const QString base = fi.baseName(); // e.g. CatOS-Hello_zh_CN or zh_CN or en or app_en
            QString localeCode;
            const QStringList parts = base.split('_');
            if (parts.size() >= 3) {
                // e.g. CatOS-Hello_zh_CN -> take last two parts -> zh_CN
                localeCode = parts.mid(parts.size() - 2).join('_');
            } else if (parts.size() == 2) {
                // e.g. zh_CN or app_en -> take the last part (en or CN)
                localeCode = parts.last();
                // if it's like zh_CN (two parts), parts.size()==2 and last() would be CN,
                // but zh_CN files usually appear as single base like zh_CN (parts==2),
                // handling for zh_CN with both parts should be covered by parts.size()>=3 case above
            } else {
                localeCode = base;
            }
            if (localeCode.isEmpty())
                continue;
            if (seenLocales.contains(localeCode))
                continue;
            seenLocales.insert(localeCode);

            QLocale locale(localeCode);
            QString nativeName = locale.nativeLanguageName();
            QString countryName = locale.nativeTerritoryName();
            QString displayText = nativeName;
            if (!countryName.isEmpty())
                displayText += " (" + countryName + ")";
            languageComboBox->addItem(displayText, localeCode);
            qInfo() << "GeneralNewsTab: added language" << localeCode << "from" << path;
        }
    }

    // 如果没有找到任何 .qm 文件，回退到内置的静态列表
    if (languageComboBox->count() == 0) {
        QList<QLocale> locales = {
            QLocale(QLocale::English), QLocale(QLocale::Chinese, QLocale::China),
            QLocale(QLocale::Spanish), QLocale(QLocale::French),
        };
        for (const QLocale &locale : locales) {
            QString nativeName = locale.nativeLanguageName();
            QString countryName = locale.nativeTerritoryName();
            QString languageCode = locale.name();
            QString displayText = nativeName + " (" + countryName + ")";
            languageComboBox->addItem(displayText, languageCode);
        }
    }

    // 设置默认值为当前语言
    int currentIndex = languageComboBox->findData(lang);
    if (currentIndex != -1) {
        languageComboBox->setCurrentIndex(currentIndex);
    }
    qInfo() << "GeneralNewsTab: loadLanguages done";
}

void GeneralNewsTab::applyLanguageChange(const QString &langCode)
{
    qInfo() << "GeneralNewsTab: applyLanguageChange" << langCode;
    restartApplication(langCode);
}

bool GeneralNewsTab::isLiveCd() const
{
    const bool liveCd = QFile::exists("/bin/calamares");
    qInfo() << "GeneralNewsTab: isLiveCd" << liveCd;
    return liveCd;
}

void GeneralNewsTab::restartApplication(const QString &langCode)
{
    qInfo() << "GeneralNewsTab: restartApplication" << langCode;
    QString program = qApp->arguments().first();
    QStringList arguments;
    if (!langCode.isEmpty()) {
        arguments << langCode;
        QProcess::startDetached(program, arguments);
    } else {
        QProcess::startDetached(program);
    }
    QApplication::quit();
}

void GeneralNewsTab::onApplyButtonClicked()
{
    QString langCode = languageComboBox->currentData().toString();
    qInfo() << "GeneralNewsTab: onApplyButtonClicked" << langCode;
    applyLanguageChange(langCode);
}

void GeneralNewsTab::onWebsiteButtonClicked()
{
    qInfo() << "GeneralNewsTab: open website";
    QDesktopServices::openUrl(QUrl("https://www.catos.info/"));
}

void GeneralNewsTab::onArchWebsiteButtonClicked()
{
    qInfo() << "GeneralNewsTab: open ArchLinux website";
    QDesktopServices::openUrl(QUrl("https://archlinux.org/"));
}

void GeneralNewsTab::onWikiWebsiteButtonClicked()
{
    qInfo() << "GeneralNewsTab: open ArchLinux wiki";
    QDesktopServices::openUrl(QUrl("https://wiki.archlinux.org/"));
}

void GeneralNewsTab::onWikicnWebsiteButtonClicked()
{
    qInfo() << "GeneralNewsTab: open ArchLinuxCN wiki";
    QDesktopServices::openUrl(QUrl("https://wiki.archlinuxcn.org/"));
}

void GeneralNewsTab::onSupportButtonClicked()
{
    qInfo() << "GeneralNewsTab: open Distrowatch support";
    QDesktopServices::openUrl(QUrl("https://distrowatch.com/dwres-mobile.php?resource=links#new"));
}

void GeneralNewsTab::onMirrorButtonClicked()
{
    qInfo() << "GeneralNewsTab: open MirrorListWindow";
    // 创建并显示 MirrorListWindow
    QScopedPointer mirrorWindow(new MirrorListWindow(this));
    mirrorWindow->exec();
}

void GeneralNewsTab::onRepoButtonClicked()
{
    qInfo() << "GeneralNewsTab: open RepoListWindow";
    QScopedPointer repoWindow(new RepoListWindow(this));
    repoWindow->exec();
}

void GeneralNewsTab::onInstallCatOSButtonClicked()
{
    qInfo() << "GeneralNewsTab: start calamares_polkit";
    QProcess::startDetached("calamares_polkit");
}

void GeneralNewsTab::onInstallCatOSNetButtonClicked()
{
    qInfo() << "GeneralNewsTab: start calamares_polkit net install";
    QProcess::startDetached("calamares_polkit", {"--config", "/usr/share/calamares-advanced"});
}

void GeneralNewsTab::onGetLogButtonClicked()
{
    qInfo() << "GeneralNewsTab: get calamares logs";
    const QString destDir = QStringLiteral("/tmp/calamares-log");
    const QString copyCmd = QStringLiteral("rm -rf %1 && cp -r /root/.cache/calamares %1").arg(destDir);

    const int copyExit = QProcess::execute("pkexec", {"bash", "-c", copyCmd});
    if (copyExit == 0) {
        qInfo() << "GeneralNewsTab: calamares logs copied" << destDir;
        QProcess::startDetached("bash", {"-c", QStringLiteral("kate %1/*").arg(destDir)});
    } else {
        qWarning() << "GeneralNewsTab: failed to copy calamares logs" << copyExit;
        QMessageBox::critical(this, tr("Error"), tr("Failed to copy calamares logs"));
    }
}
