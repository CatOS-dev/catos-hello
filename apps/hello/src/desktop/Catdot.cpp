#include "desktop/Catdot.h"
#include "ToolRunner.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

namespace {
QStringList strings(const QJsonValue &value)
{
    QStringList result;
    for (const auto &item : value.toArray()) result.append(item.toString());
    return result;
}

bool validProfileId(const QString &id)
{
    static const QRegularExpression pattern(QStringLiteral("^[a-z0-9][a-z0-9-]*$"));
    return pattern.match(id).hasMatch();
}
}

bool CatdotClient::parseList(const QByteArray &data, QVector<DesktopProfile> *profiles,
                             QString *active, QString *error)
{
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(data, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject() ||
        !document.object().value(QStringLiteral("profiles")).isArray()) {
        if (error) *error = QStringLiteral("Catdot returned an invalid Profile list: %1").arg(parseError.errorString());
        return false;
    }
    const auto object = document.object();
    *active = object.value(QStringLiteral("activeProfile")).toString();
    profiles->clear();
    for (const auto &item : object.value(QStringLiteral("profiles")).toArray()) {
        if (!item.isObject()) continue;
        const auto profile = item.toObject();
        const QString id = profile.value(QStringLiteral("id")).toString();
        if (!validProfileId(id)) continue;
        profiles->append({id, profile.value(QStringLiteral("name")).toString(),
                          profile.value(QStringLiteral("description")).toString(),
                          profile.value(QStringLiteral("status")).toString(),
                          strings(profile.value(QStringLiteral("packages")))});
    }
    return true;
}

bool CatdotClient::parsePlan(const QByteArray &data, ProfilePlan *plan, QString *error)
{
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(data, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("Catdot returned an invalid change preview: %1").arg(parseError.errorString());
        return false;
    }
    const auto object = document.object();
    plan->profile = object.value(QStringLiteral("profile")).toString();
    if (!validProfileId(plan->profile) || !object.value(QStringLiteral("missingPackages")).isArray() ||
        !object.value(QStringLiteral("pathsWritten")).isArray() ||
        !object.value(QStringLiteral("existingPathsAffected")).isArray()) {
        if (error) *error = QStringLiteral("Catdot returned an incomplete change preview.");
        return false;
    }
    plan->firstActivation = object.value(QStringLiteral("firstActivation")).toBool();
    plan->missingPackages = strings(object.value(QStringLiteral("missingPackages")));
    plan->pathsRemoved = strings(object.value(QStringLiteral("pathsRemoved")));
    plan->pathsWritten = strings(object.value(QStringLiteral("pathsWritten")));
    plan->existingPathsAffected = strings(object.value(QStringLiteral("existingPathsAffected")));
    return true;
}

void CatdotClient::list(ListCallback callback)
{
    tools_->run(QStringLiteral("catdot"), {QStringLiteral("list"), QStringLiteral("--json")},
                [callback](int code, const QString &out, const QString &err) {
        QVector<DesktopProfile> profiles;
        QString active, error;
        if (code == 0 && parseList(out.toUtf8(), &profiles, &active, &error))
            callback(profiles, active, {});
        else callback({}, {}, error.isEmpty() ? (err.isEmpty() ?
            QStringLiteral("Catdot could not start or returned an error.") : err.trimmed()) : error);
    });
}

void CatdotClient::plan(const QString &profile, PlanCallback callback)
{
    if (!validProfileId(profile)) { callback({}, QStringLiteral("Invalid Profile ID")); return; }
    tools_->run(QStringLiteral("catdot"), {QStringLiteral("plan"), profile, QStringLiteral("--json")},
                [callback](int code, const QString &out, const QString &err) {
        ProfilePlan plan;
        QString error;
        if (code == 0 && parsePlan(out.toUtf8(), &plan, &error)) callback(plan, {});
        else callback({}, error.isEmpty() ? err.trimmed() : error);
    });
}

void CatdotClient::select(const QString &profile, bool installPackages, Completion callback)
{
    if (!validProfileId(profile)) { callback(false, QStringLiteral("Invalid Profile ID")); return; }
    const QString command = QStringLiteral("catdot select %1 --packages=%2")
                                .arg(profile, installPackages ? QStringLiteral("install") : QStringLiteral("verify"));
    tools_->runInTerminal(QStringLiteral("Activate desktop Profile"), command,
                          [callback](int code, const QString &, const QString &err) {
        callback(code == 0, err.trimmed());
    });
}
