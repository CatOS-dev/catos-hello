#include <QtTest/QtTest>
#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QDialog>
#include <QFile>
#include <QLabel>
#include <QGroupBox>
#include <QMenu>
#include <QScrollArea>
#include "maintenance/MaintenancePage.h"
#include <QToolButton>
#include <QListWidget>
#include <QPushButton>
#include <QTemporaryDir>
#include <QTimer>
#include <QTranslator>
#include <QTreeWidget>
#include "home/Environment.h"
#include "home/HomePage.h"
#include "home/Onboarding.h"
#include "mainwindow.h"

class HelloUiTests : public QObject {
    Q_OBJECT
private:
    QTemporaryDir settings_;

    static Environment environment(bool live) {
        Environment result;
        result.osName = QStringLiteral("CatOS Rolling");
        result.desktop = QStringLiteral("KDE Plasma");
        result.live = live;
        return result;
    }

    static bool hasButton(QWidget &widget, const QString &label) {
        for (auto *button : widget.findChildren<QPushButton *>())
            if (button->text() == label || button->accessibleName() == label) return true;
        return false;
    }

    static void screenshot(QWidget &widget, const QString &name) {
        const QString folder = qEnvironmentVariable("CATOS_HELLO_SCREENSHOTS");
        if (!folder.isEmpty()) QVERIFY2(widget.grab().save(folder + QLatin1Char('/') + name), "Cannot save UI screenshot");
    }

private slots:
    void initTestCase() {
        QVERIFY(settings_.isValid());
        qputenv("XDG_CONFIG_HOME", settings_.path().toUtf8());
        qApp->setOrganizationName(QStringLiteral("CatOS-Test"));
        qputenv("XDG_CURRENT_DESKTOP", "KDE");
        qApp->setApplicationName(QStringLiteral("catos-hello-test"));
    }

    void preservesOriginalLiveDetection() {
        const QString path = settings_.filePath(QStringLiteral("calamares"));
        QVERIFY(!Environment::isLiveCd(path));
        QFile file(path);
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.close();
        QVERIFY(Environment::isLiveCd(path));
    }

    void liveHasOnlyInstallationAndRecoveryTools() {
        MainWindow window(environment(true));
        auto *navigation = window.findChild<QListWidget *>(QStringLiteral("navigation"));
        QVERIFY(navigation);
        QCOMPARE(navigation->count(), 3);
        QVERIFY(window.findChild<QPushButton *>(QStringLiteral("install")));
        QVERIFY(window.findChild<QPushButton *>(QStringLiteral("install-advanced")));
        QVERIFY(window.findChild<QPushButton *>(QStringLiteral("install-log")));
        QVERIFY(window.findChild<QPushButton *>(QStringLiteral("partition")));
        QVERIFY(window.findChild<QComboBox *>(QStringLiteral("languageSelect")));
        QVERIFY(!window.findChild<QPushButton *>(QStringLiteral("desktopPackagesButton")));
        QVERIFY(!window.findChild<QPushButton *>(QStringLiteral("action_update")));
        QVERIFY(!window.findChild<QPushButton *>(QStringLiteral("action_drivers")));
        QVERIFY(!hasButton(window, QStringLiteral("Open Shelly")));
        window.show();
        QCoreApplication::processEvents();
        screenshot(window, QStringLiteral("hello-live-en.png"));
        window.resize(760, 520);
        QCoreApplication::processEvents();
        screenshot(window, QStringLiteral("hello-live-en-compact.png"));
        window.resize(1040, 700);
        navigation->setCurrentRow(1);
        QCoreApplication::processEvents();
        screenshot(window, QStringLiteral("hello-recovery-en.png"));
    }

    void installedHasNoInstallerOrRecoveryActions() {
        MainWindow window(environment(false));
        auto *navigation = window.findChild<QListWidget *>(QStringLiteral("navigation"));
        QVERIFY(navigation);
        QCOMPARE(navigation->count(), 4);
        QVERIFY(!window.findChild<QPushButton *>(QStringLiteral("install")));
        QVERIFY(!window.findChild<QPushButton *>(QStringLiteral("install-advanced")));
        QVERIFY(!window.findChild<QPushButton *>(QStringLiteral("install-log")));
        QVERIFY(!window.findChild<QPushButton *>(QStringLiteral("partition")));
        QVERIFY(window.findChild<QPushButton *>(QStringLiteral("desktopPackagesButton")));
        QVERIFY(window.findChild<QPushButton *>(QStringLiteral("action_update")));
        QVERIFY(hasButton(window, QStringLiteral("Run CatOS updater (news and updates)")));
        QVERIFY(window.findChildren<QGroupBox *>().isEmpty());
        auto *advanced = window.findChild<QWidget *>(QStringLiteral("advancedSection"));
        auto *toggle = window.findChild<QToolButton *>(QStringLiteral("advancedToggle"));
        QVERIFY(advanced && toggle);
        QVERIFY(advanced->isHidden());
        toggle->setChecked(true);
        QVERIFY(!advanced->isHidden());
        toggle->setChecked(false);
        QVERIFY(!hasButton(window, QStringLiteral("Get installation logs")));
        window.show();
        QCoreApplication::processEvents();
        screenshot(window, QStringLiteral("hello-installed-en.png"));
        navigation->setCurrentRow(2);
        QCoreApplication::processEvents();
        screenshot(window, QStringLiteral("hello-maintenance-en.png"));
        toggle->setChecked(true);
        if (auto *scroll = window.findChild<MaintenancePage *>()->findChild<QScrollArea *>())
            scroll->ensureWidgetVisible(advanced);
        QCoreApplication::processEvents();
        screenshot(window, QStringLiteral("hello-maintenance-advanced-en.png"));
        toggle->setChecked(false);
    }

    void firstKickRowsStillSupportNavigationAndProgress() {
        OnboardingStore state;
        state.reset();
        MainWindow window(environment(false));
        window.show();
        auto *navigation = window.findChild<QListWidget *>(QStringLiteral("navigation"));
        auto *software = window.findChild<QPushButton *>(QStringLiteral("action_software"));
        QVERIFY(software);
        QVERIFY(software->isFlat());
        QCOMPARE(navigation->currentRow(), 0);
        QTest::mouseClick(software, Qt::LeftButton);
        QCOMPARE(navigation->currentRow(), 1);
        navigation->setCurrentRow(0);
        auto *step = window.findChild<QWidget *>(QStringLiteral("step_updates"));
        QVERIFY(step);
        auto *menu = step->findChild<QMenu *>();
        QVERIFY(menu);
        QCOMPARE(menu->actions().size(), 2);
        menu->actions().first()->trigger();
        QVERIFY(step->isHidden());
        QVERIFY(state.markedDone(QStringLiteral("updates")));
        state.reset();
    }

    void desktopPackageSelectorOpensFullIndependentDialog() {
        MainWindow window(environment(false));
        auto *navigation = window.findChild<QListWidget *>(QStringLiteral("navigation"));
        navigation->setCurrentRow(1);
        window.show();
        QCoreApplication::processEvents();
        screenshot(window, QStringLiteral("hello-software-en.png"));
        auto *choose = window.findChild<QPushButton *>(QStringLiteral("desktopPackagesButton"));
        QVERIFY(choose);
        bool found = false;
        QTimer::singleShot(60, [&] {
            auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            if (dialog) {
                auto *tree = dialog->findChild<QTreeWidget *>();
                found = tree && tree->topLevelItemCount() > 3 &&
                        hasButton(*dialog, QStringLiteral("Install Selected")) &&
                        hasButton(*dialog, QStringLiteral("Reload"));
                if (found) screenshot(*dialog, QStringLiteral("hello-desktop-selector-en.png"));
                dialog->reject();
            }
        });
        choose->click();
        QVERIFY(found);
    }

    void forbiddenActionsCannotLaunchAcrossEnvironmentBoundary() {
        const QString fakeCommands = settings_.filePath(QStringLiteral("fake-commands"));
        QVERIFY(QDir().mkpath(fakeCommands));
        const QString marker = settings_.filePath(QStringLiteral("launched.txt"));
        for (const QString &name : {QStringLiteral("calamares_polkit"),
                                    QStringLiteral("RunInTerminal")}) {
            QFile program(fakeCommands + QLatin1Char('/') + name);
            QVERIFY(program.open(QIODevice::WriteOnly));
            program.write(("#!/bin/sh\necho launched > '" + marker + "'\n").toUtf8());
            program.close();
            QVERIFY(program.setPermissions(QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner));
        }
        const QByteArray oldPath = qgetenv("PATH");
        qputenv("PATH", (fakeCommands + QLatin1Char(':')).toUtf8() + oldPath);
        {
            MainWindow installed(environment(false));
            auto *home = installed.findChild<HomePage *>();
            QVERIFY(home);
            QVERIFY(QMetaObject::invokeMethod(home, "actionRequested", Qt::DirectConnection,
                                              Q_ARG(QString, QStringLiteral("install"))));
            QVERIFY(!QFile::exists(marker));
        }
        {
            MainWindow live(environment(true));
            auto *home = live.findChild<HomePage *>();
            QVERIFY(home);
            QVERIFY(QMetaObject::invokeMethod(home, "actionRequested", Qt::DirectConnection,
                                              Q_ARG(QString, QStringLiteral("update"))));
            QVERIFY(!QFile::exists(marker));
            auto *navigation = live.findChild<QListWidget *>(QStringLiteral("navigation"));
            QVERIFY(QMetaObject::invokeMethod(home, "navigateTo", Qt::DirectConnection,
                                              Q_ARG(QString, QStringLiteral("maintenance"))));
            QCOMPARE(navigation->currentRow(), 0);
        }
        qputenv("PATH", oldPath);
    }

    void chineseLanguageRendersOnBothViews() {
        QTranslator translator;
        QVERIFY2(translator.load(QStringLiteral(HELLO_QM_PATH)), "Generated Chinese QM is missing");
        QApplication::installTranslator(&translator);
        for (bool live : {true, false}) {
            MainWindow window(environment(live));
            auto *navigation = window.findChild<QListWidget *>(QStringLiteral("navigation"));
            QCOMPARE(navigation->item(0)->text(),
                     live ? QStringLiteral("安装 CatOS") : QStringLiteral("欢迎"));
            QCOMPARE(window.findChild<QComboBox *>(QStringLiteral("languageSelect"))->count(), 5);
            window.show();
            QCoreApplication::processEvents();
            screenshot(window, live ? QStringLiteral("hello-live-zh.png")
                                    : QStringLiteral("hello-installed-zh.png"));
            window.resize(760, 520);
            QCoreApplication::processEvents();
            screenshot(window, live ? QStringLiteral("hello-live-zh-compact.png")
                                    : QStringLiteral("hello-installed-zh-compact.png"));
            window.resize(1040, 700);
            navigation->setCurrentRow(live ? 1 : 2);
            QCoreApplication::processEvents();
            screenshot(window, live ? QStringLiteral("hello-recovery-zh.png")
                                    : QStringLiteral("hello-maintenance-zh.png"));
            navigation->setCurrentRow(live ? 2 : 3);
            QCoreApplication::processEvents();
            screenshot(window, live ? QStringLiteral("hello-about-live-zh.png")
                                    : QStringLiteral("hello-about-installed-zh.png"));
        }
        MainWindow installed(environment(false));
        installed.show();
        installed.findChild<QListWidget *>(QStringLiteral("navigation"))->setCurrentRow(1);
        QCoreApplication::processEvents();
        screenshot(installed, QStringLiteral("hello-software-zh.png"));
        auto *choose = installed.findChild<QPushButton *>(QStringLiteral("desktopPackagesButton"));
        QVERIFY(choose);
        bool found = false;
        QTimer::singleShot(60, [&] {
            auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
            if (dialog) {
                found = dialog->findChild<QTreeWidget *>() != nullptr &&
                        hasButton(*dialog, QStringLiteral("安装所选软件包"));
                if (found) screenshot(*dialog, QStringLiteral("hello-desktop-selector-zh.png"));
                dialog->reject();
            }
        });
        choose->click();
        QVERIFY(found);
        QApplication::removeTranslator(&translator);
    }
};

QTEST_MAIN(HelloUiTests)
#include "test_hello_ui.moc"
