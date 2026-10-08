#pragma once

#include <QString>

struct Environment {
    QString osName;
    QString desktop;
    QString sessionType;
    bool live = false;
    bool networkAvailable = false;

    static Environment detect();
    static bool isLiveCd(const QString &installer = QStringLiteral("/bin/calamares"));
    static QString desktopName(const QString &currentDesktop, const QString &session);
};
