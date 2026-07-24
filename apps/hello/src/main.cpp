#include <QApplication>
#include <QTranslator>
#include <QSettings>
#include "mainwindow.h"

QString lang;

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    app.setApplicationName("CatOS-Hello");
    app.setOrganizationName("CatOS");

    QLocale systemLocale = QLocale::system();
    lang = systemLocale.name();

    if (argc >= 2) {
        lang = argv[1];
    }

    QTranslator translator;
    if (!lang.isEmpty()) {
        if (translator.load(":/translations/catos-hello_" + lang + ".qm")) {
            app.installTranslator(&translator);
        }
    }

    MainWindow mainWindow;
    mainWindow.show();

    return app.exec();
}
