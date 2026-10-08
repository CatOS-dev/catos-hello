#pragma once

#include <QString>

struct Environment {
    QString osName;
    QString desktop;
    QString sessionType;
    bool live = false;
    bool networkAvailable = false;

    static Environment detect();
    static QString desktopName(const QString &currentDesktop, const QString &session);
};
