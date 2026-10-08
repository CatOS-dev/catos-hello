#include "home/Environment.h"

#include <QFile>
#include <QFileInfo>
#include <QNetworkInterface>
#include <QTextStream>

QString Environment::desktopName(const QString &currentDesktop, const QString &session)
{
    QString value = currentDesktop.section(':', 0, 0).trimmed();
    if (value.isEmpty()) value = session.trimmed();
    if (value.isEmpty()) return QStringLiteral("Unknown desktop");
    if (value.compare(QStringLiteral("plasma"), Qt::CaseInsensitive) == 0 ||
        value.compare(QStringLiteral("kde"), Qt::CaseInsensitive) == 0) return QStringLiteral("KDE Plasma");
    if (value.compare(QStringLiteral("gnome"), Qt::CaseInsensitive) == 0) return QStringLiteral("GNOME");
    if (value.compare(QStringLiteral("hyprland"), Qt::CaseInsensitive) == 0) return QStringLiteral("Hyprland");
    if (value.compare(QStringLiteral("niri"), Qt::CaseInsensitive) == 0) return QStringLiteral("Niri");
    return value;
}

Environment Environment::detect()
{
    Environment result;
    result.osName = QStringLiteral("CatOS Rolling");
    QFile file(QStringLiteral("/etc/os-release"));
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream stream(&file);
        while (!stream.atEnd()) {
            const QString line = stream.readLine();
            if (line.startsWith(QStringLiteral("PRETTY_NAME="))) {
                result.osName = line.mid(12).remove('"');
                break;
            }
        }
    }
    result.desktop = desktopName(qEnvironmentVariable("XDG_CURRENT_DESKTOP"),
                                 qEnvironmentVariable("DESKTOP_SESSION"));
    result.sessionType = qEnvironmentVariable("XDG_SESSION_TYPE");
    result.live = QFileInfo::exists(QStringLiteral("/run/archiso/bootmnt")) ||
                  QFileInfo::exists(QStringLiteral("/run/archiso/cowspace"));
    for (const auto &interface : QNetworkInterface::allInterfaces()) {
        const auto flags = interface.flags();
        if ((flags & QNetworkInterface::IsUp) && (flags & QNetworkInterface::IsRunning) &&
            !(flags & QNetworkInterface::IsLoopBack) && !interface.addressEntries().isEmpty()) {
            result.networkAvailable = true;
            break;
        }
    }
    return result;
}
