#pragma once

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVector>
#include <functional>

class ToolRunner;

struct DesktopProfile {
    QString id;
    QString name;
    QString description;
    QString status;
    QStringList packages;
};

struct ProfilePlan {
    QString profile;
    bool firstActivation = false;
    QStringList missingPackages;
    QStringList pathsRemoved;
    QStringList pathsWritten;
    QStringList existingPathsAffected;
};

class CatdotClient : public QObject {
public:
    using ListCallback = std::function<void(const QVector<DesktopProfile> &, const QString &, const QString &)>;
    using PlanCallback = std::function<void(const ProfilePlan &, const QString &)>;
    using Completion = std::function<void(bool, const QString &)>;

    explicit CatdotClient(ToolRunner *tools, QObject *parent = nullptr) : QObject(parent), tools_(tools) {}
    void list(ListCallback callback);
    void plan(const QString &profile, PlanCallback callback);
    void select(const QString &profile, bool installPackages, Completion callback);
    static bool parseList(const QByteArray &data, QVector<DesktopProfile> *profiles,
                          QString *active, QString *error);
    static bool parsePlan(const QByteArray &data, ProfilePlan *plan, QString *error);

private:
    ToolRunner *tools_;
};
