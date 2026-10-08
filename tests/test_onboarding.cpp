#include <QtTest/QtTest>
#include <QTemporaryDir>
#include "home/Onboarding.h"
#include "home/Environment.h"

class OnboardingTests : public QObject {
    Q_OBJECT
private slots:
    void persistedStepsCanBeSkippedAndResumed() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        const QString file = temporary.filePath(QStringLiteral("onboarding.ini"));
        {
            OnboardingStore state(file);
            QVERIFY(!state.dismissed());
            QVERIFY(!state.skipped(QStringLiteral("drivers")));
            state.setSkipped(QStringLiteral("drivers"), true);
            state.setMarkedDone(QStringLiteral("updates"), true);
            state.setDismissed(true);
        }
        {
            OnboardingStore state(file);
            QVERIFY(state.dismissed());
            QVERIFY(state.skipped(QStringLiteral("drivers")));
            QVERIFY(state.markedDone(QStringLiteral("updates")));
            QVERIFY(!state.skipped(QStringLiteral("updates")));
            state.reset();
            QVERIFY(!state.dismissed());
            QVERIFY(!state.skipped(QStringLiteral("drivers")));
            QVERIFY(!state.markedDone(QStringLiteral("updates")));
        }
    }
    void desktopDisplayUsesCurrentSession() {
        QCOMPARE(Environment::desktopName(QStringLiteral("KDE:PLASMA"), {}), QStringLiteral("KDE Plasma"));
        QCOMPARE(Environment::desktopName({}, QStringLiteral("niri")), QStringLiteral("Niri"));
        QCOMPARE(Environment::desktopName({}, {}), QStringLiteral("Unknown desktop"));
    }
};
QTEST_GUILESS_MAIN(OnboardingTests)
#include "test_onboarding.moc"
