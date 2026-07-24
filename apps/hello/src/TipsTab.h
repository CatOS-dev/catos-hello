#ifndef TIPSTAB_H
#define TIPSTAB_H

#include <QWidget>
#include <QString>
#include <QTextBrowser>
#include <QVBoxLayout>

class TipsTab : public QWidget
{
    Q_OBJECT

public:
    explicit TipsTab(QWidget *parent = nullptr);

private:
    QString detectUiLanguage() const;
    QString locateTipsHtml(const QString& uiLang) const;
    QString loadTipsHtml(const QString& uiLang) const;

    QTextBrowser* tipsBrowser {};
    QVBoxLayout* layout {};
};

#endif // TIPSTAB_H
