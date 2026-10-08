#include <QtTest/QtTest>
#include <QEventLoop>
#include <QTimer>
#include "ToolRunner.h"

class ToolRunnerTests : public QObject {
    Q_OBJECT
private slots:
    void commandReportsOutputAndExitCode() {
        ToolRunner runner;
        QEventLoop loop;
        QTimer timeout;
        timeout.setSingleShot(true);
        QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
        bool completed = false;
        timeout.start(3000);
        runner.run(QStringLiteral("/bin/sh"),
                   {QStringLiteral("-c"), QStringLiteral("printf stdout; printf stderr >&2; exit 7")},
                   [&](int exitCode, const QString &output, const QString &error) {
            completed = true;
            QCOMPARE(exitCode, 7);
            QCOMPARE(output, QStringLiteral("stdout"));
            QCOMPARE(error, QStringLiteral("stderr"));
            loop.quit();
        });
        loop.exec();
        QVERIFY(completed);
    }
    void missingExecutableReportsFailure() {
        ToolRunner runner;
        QEventLoop loop;
        QTimer timeout;
        timeout.setSingleShot(true);
        QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
        bool completed = false;
        timeout.start(3000);
        runner.run(QStringLiteral("/this/path/does/not/exist/catos-no-tool"), {},
                   [&](int exitCode, const QString &, const QString &) {
            completed = true;
            QCOMPARE(exitCode, -1);
            loop.quit();
        });
        loop.exec();
        QVERIFY(completed);
    }
};
QTEST_GUILESS_MAIN(ToolRunnerTests)
#include "test_toolrunner.moc"
