#ifndef MIRRORLISTWINDOW_H
#define MIRRORLISTWINDOW_H

#include <QDialog>
#include <QMap>
#include <QStringList>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QListWidget>
#include <QVBoxLayout>
#include <QPushButton>
#include <QMessageBox>
#include <QScrollArea>
#include <QProcess>
#include <QFile>
#include <QPlainTextEdit>
#include <QTextStream>
#include <QLabel>
#include <QGridLayout>

class MirrorListWindow : public QDialog
{
    Q_OBJECT

public:
    explicit MirrorListWindow(QWidget *parent = nullptr);

private slots:
    void onMirrorListLoaded(QNetworkReply *reply);
    void onCountryButtonClicked(const QString &country);
    void onSaveButtonClicked();

private:
    void loadMirrorList();
    void showMirrorsForCountry(const QString &country);
    void runRateMirrors(const QStringList &mirrors, QPlainTextEdit *textEdit, QDialog *parentDialog);
    bool checkRateMirrorsInstalled();

    QNetworkAccessManager *manager{};
    QMap<QString, QStringList> countryMirrorsMap; // 存储国家和镜像列表
    QScrollArea *scrollArea; // 滚动区域
    QWidget *scrollContent; // 滚动区域的内容
    QGridLayout *scrollLayout; // 滚动区域的布局
    QLabel *loadingLabel{}; // 加载提示标签
};

#endif // MIRRORLISTWINDOW_H
