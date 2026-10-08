#include "ToolRunner.h"

#include <QProcess>
#include <QStandardPaths>
#include <memory>

bool ToolRunner::launch(const QString &program, const QStringList &arguments)
{
    return !QStandardPaths::findExecutable(program).isEmpty() &&
           QProcess::startDetached(program, arguments);
}

void ToolRunner::run(const QString &program, const QStringList &arguments, Completion done)
{
    auto *process = new QProcess(this);
    auto completed = std::make_shared<bool>(false);
    auto finish = [process, completed, done](int exitCode) {
        if (*completed) return;
        *completed = true;
        done(exitCode, QString::fromUtf8(process->readAllStandardOutput()),
             QString::fromUtf8(process->readAllStandardError()));
        process->deleteLater();
    };
    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [finish](int exitCode, QProcess::ExitStatus status) {
                finish(status == QProcess::NormalExit ? exitCode : -1);
            });
    connect(process, &QProcess::errorOccurred, this, [finish](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) finish(-1);
    });
    process->start(program, arguments);
}

void ToolRunner::runInTerminal(const QString &title, const QString &command, Completion done)
{
    const QString terminal = QStandardPaths::findExecutable(QStringLiteral("RunInTerminal"));
    if (terminal.isEmpty()) {
        done(-1, {}, QStringLiteral("RunInTerminal is not installed"));
        return;
    }
    run(terminal, {QStringLiteral("--prompt"), title, command}, done);
}
