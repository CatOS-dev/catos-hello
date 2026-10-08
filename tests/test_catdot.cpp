#include <QtTest/QtTest>
#include "desktop/Catdot.h"

class CatdotTests : public QObject {
    Q_OBJECT
private slots:
    void listReadsAcceptedProfileAndStatus() {
        const QByteArray json = R"({"activeProfile":"catos-niri-dms","profiles":[{"id":"catos-niri-dms","name":"Niri DMS","description":"A desktop profile","status":"active","packages":["niri","dms-shell"]},{"id":"catos-hyprland-dms","name":"Hyprland DMS","description":"Alternative","status":"available","packages":["hyprland"]}],"diagnostics":[]})";
        QVector<DesktopProfile> profiles;
        QString active, error;
        QVERIFY(CatdotClient::parseList(json, &profiles, &active, &error));
        QCOMPARE(active, QStringLiteral("catos-niri-dms"));
        QCOMPARE(profiles.size(), 2);
        QCOMPARE(profiles[0].status, QStringLiteral("active"));
        QCOMPARE(profiles[0].packages, (QStringList{QStringLiteral("niri"), QStringLiteral("dms-shell")}));
        QCOMPARE(profiles[1].status, QStringLiteral("available"));
    }
    void planReadsChangesAndMissingPackages() {
        const QByteArray json = R"({"profile":"catos-hyprland-dms","firstActivation":true,"missingPackages":["hyprland"],"pathsRemoved":[".config/niri/config.kdl"],"pathsWritten":[".config/hypr/hyprland.conf"],"existingPathsAffected":[".config/hypr/hyprland.conf"]})";
        ProfilePlan plan;
        QString error;
        QVERIFY(CatdotClient::parsePlan(json, &plan, &error));
        QCOMPARE(plan.profile, QStringLiteral("catos-hyprland-dms"));
        QVERIFY(plan.firstActivation);
        QCOMPARE(plan.missingPackages, (QStringList{QStringLiteral("hyprland")}));
        QCOMPARE(plan.existingPathsAffected.size(), 1);
    }
    void malformedJsonCannotActivateProfile() {
        ProfilePlan plan;
        QString error;
        QVERIFY(!CatdotClient::parsePlan(R"({"profile":"../bad","missingPackages":[],"pathsWritten":[],"existingPathsAffected":[]})", &plan, &error));
        QVERIFY(!error.isEmpty());
        QVector<DesktopProfile> profiles;
        QString active;
        QVERIFY(!CatdotClient::parseList("invalid", &profiles, &active, &error));
    }
};
QTEST_GUILESS_MAIN(CatdotTests)
#include "test_catdot.moc"
