#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <functional>

class ToolRunner : public QObject {
public:
    using Completion = std::function<void(int, const QString &, const QString &)>;
    explicit ToolRunner(QObject *parent = nullptr) : QObject(parent) {}

    static bool launch(const QString &program, const QStringList &arguments = {});
    void run(const QString &program, const QStringList &arguments, Completion done);
    void runInTerminal(const QString &title, const QString &command, Completion done);
};
