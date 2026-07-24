#ifndef GENERALNEWSTAB_H
#define GENERALNEWSTAB_H

#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QComboBox>
#include <QMessageBox>
#include <QProcess>
#include <QDesktopServices>
#include <QUrl>
#include "MirrorListWindow.h"
#include "RepoListWindow.h"

extern QString lang;

class GeneralNewsTab : public QWidget
{
    Q_OBJECT

public:
    explicit GeneralNewsTab(QWidget *parent = nullptr);

private slots:
    void onApplyButtonClicked();
    void onWebsiteButtonClicked();
    void onArchWebsiteButtonClicked();
    void onWikiWebsiteButtonClicked();
    void onWikicnWebsiteButtonClicked();
    void onSupportButtonClicked();
    void onMirrorButtonClicked();
    void onRepoButtonClicked();
    void onInstallCatOSButtonClicked();
    void onInstallCatOSNetButtonClicked();
    void onGetLogButtonClicked();

private:
    void loadLanguages(); // 加载语言和地区
    void applyLanguageChange(const QString &langCode); // 应用语言更改
    void restartApplication(const QString &langCode); // 重启程序
    bool isLiveCd() const; // 检测Live CD环境

    QLabel *generalNewsLabel;
    QVBoxLayout *layout;
    QGridLayout *gridLayout;
    QPushButton *websiteButton;
    QPushButton *archButton;
    QPushButton *wikiButton;
    QPushButton *wikicnButton;
    QPushButton *supportButton;
    QComboBox *languageComboBox;
    QPushButton *applyButton;
    QPushButton *mirrorButton;
    QPushButton *repoButton;
    QPushButton *installCatOSButton;
    QPushButton *installCatOSNetButton;
    QPushButton *getLogButton;

    MirrorListWindow *mirrorWindow{};
    RepoListWindow *repoWindow{};
};

#endif // GENERALNEWSTAB_H
