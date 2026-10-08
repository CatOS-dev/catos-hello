#ifndef INSTALLAPPSTAB_H
#define INSTALLAPPSTAB_H

#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <QPushButton>
#include <QTreeWidget>
#include <QMap>
#include <QSet>

struct DesktopGroup
{
    QString name;
    QString description;
    bool expanded { false };
    QStringList packages;
};

class InstallAppsTab : public QWidget
{
    Q_OBJECT

public:
    explicit InstallAppsTab(QWidget *parent = nullptr);

private slots:
    void onInstallClicked();
    void onReloadClicked();

private:
    void setupUi();
    bool loadDesktopGroups(QString* errorMessage = nullptr);
    QString locateDesktopYaml() const;
    QSet<QString> queryInstalledPackages() const;
    void rebuildTree();

    QLabel* installAppsLabel{};
    QLabel* sourceLabel{};
    QTreeWidget* groupsTreeView{};
    QPushButton* installButton{};
    QPushButton* reloadButton{};
    QVBoxLayout* layout{};
    QList<DesktopGroup> groups_;
    QMap<QTreeWidgetItem*, QString> itemPackageMap_;
    QSet<QString> installedPackages_;
};

#endif // INSTALLAPPSTAB_H
