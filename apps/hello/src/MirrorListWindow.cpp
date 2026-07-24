#include "MirrorListWindow.h"
#include <QNetworkRequest>
#include <QElapsedTimer>
#include <QMessageBox>
#include <QDebug>
#include <QProcess>
#include <QFile>
#include <QTextStream>
#include <QTemporaryFile>

MirrorListWindow::MirrorListWindow(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Mirror List"));
    setModal(true);
    resize(800, 600);

    QVBoxLayout *layout = new QVBoxLayout(this);

    // 添加加载提示
    loadingLabel = new QLabel(tr("Loading mirror list..."), this);
    loadingLabel->setAlignment(Qt::AlignCenter);
    loadingLabel->setStyleSheet("QLabel { font-size: 14pt; color: #666; }");
    layout->addWidget(loadingLabel);

    scrollArea = new QScrollArea(this);
    scrollContent = new QWidget(scrollArea);
    scrollLayout = new QGridLayout(scrollContent);
    scrollArea->setWidget(scrollContent);
    scrollArea->setWidgetResizable(true);
    scrollArea->setVisible(false); // 初始隐藏
    layout->addWidget(scrollArea);

    loadMirrorList();
}

void MirrorListWindow::loadMirrorList()
{
    qInfo() << "MirrorListWindow: load mirror list";
    manager = new QNetworkAccessManager(this);
    connect(manager, &QNetworkAccessManager::finished, this, &MirrorListWindow::onMirrorListLoaded);

    QUrl url("https://archlinux.org/mirrorlist/all/");
    QNetworkRequest request(url);
    request.setTransferTimeout(30000); // 30秒超时
    manager->get(request);
}

void MirrorListWindow::onMirrorListLoaded(QNetworkReply *reply)
{
    if (reply->error() == QNetworkReply::NoError)
    {
        qInfo() << "MirrorListWindow: mirror list loaded";
        QByteArray data = reply->readAll();
        QString mirrorList = QString::fromUtf8(data);

        QStringList lines = mirrorList.split("\n");

        // 跳过前 4 行（文件头）
        for (int i = 4; i < lines.size(); ++i)
        {
            QString line = lines[i].trimmed();
            if (line.startsWith("## ")) // 提取国家
            {
                QString country = line.mid(3).trimmed(); // 去掉 "## " 前缀
                QStringList mirrors;

                // 提取当前国家的镜像 URL
                for (int j = i + 1; j < lines.size(); ++j)
                {
                    QString mirrorLine = lines[j].trimmed();
                    if (mirrorLine.startsWith("#Server = "))
                    {
                        QString mirrorUrl = mirrorLine.mid(9).trimmed(); // 去掉 "#Server = " 前缀
                        mirrors.append(mirrorUrl);
                    }
                    else if (mirrorLine.startsWith("## "))
                    {
                        // 遇到下一个国家，停止提取
                        break;
                    }
                }

                // 将国家和镜像列表存入 map
                if (!country.isEmpty() && !mirrors.isEmpty())
                {
                    countryMirrorsMap[country] = mirrors;
                }
            }
        }

        // 隐藏加载提示，显示按钮
        loadingLabel->setVisible(false);
        scrollArea->setVisible(true);

        int row = 0;
        int col = 0;
        const int columnsPerRow = 3;

        for (const QString &country : countryMirrorsMap.keys())
        {
            QPushButton *button = new QPushButton(country, scrollContent);
            connect(button, &QPushButton::clicked, this, [this, country]() {
                onCountryButtonClicked(country);
            });
            scrollLayout->addWidget(button, row, col);
            col++;
            if (col >= columnsPerRow)
            {
                col = 0;
                row++;
            }
        }
    }
    else
    {
        qWarning() << "MirrorListWindow: failed to load mirror list" << reply->errorString();
        loadingLabel->setText(tr("Failed to load mirror list. Click to retry."));
        loadingLabel->setCursor(Qt::PointingHandCursor);
        loadingLabel->setStyleSheet("QLabel { font-size: 14pt; color: red; }");
        
        // 添加点击重试
        disconnect(loadingLabel, nullptr, nullptr, nullptr);
        connect(loadingLabel, &QLabel::linkActivated, this, [this]() {
            loadingLabel->setText(tr("Loading mirror list..."));
            loadingLabel->setStyleSheet("QLabel { font-size: 14pt; color: #666; }");
            loadMirrorList();
        });
        
        QMessageBox::critical(this, tr("Error"), tr("Failed to load mirror list: ") + reply->errorString());
    }

    reply->deleteLater();
}

void MirrorListWindow::showMirrorsForCountry(const QString &country)
{
    qInfo() << "MirrorListWindow: show mirrors" << country;
    // 检查 rate-mirrors 是否安装
    if (!checkRateMirrorsInstalled()) {
        QMessageBox::warning(this, tr("Missing Tool"), 
                            tr("rate-mirrors is not installed. Please install it first:\n\nsudo pacman -S rate-mirrors"));
        return;
    }

    QStringList mirrors = countryMirrorsMap[country];

    QDialog *dialog = new QDialog(this);
    dialog->setWindowTitle("Mirrors in " + country);
    dialog->setModal(true);
    dialog->resize(800, 600);

    QVBoxLayout *layout = new QVBoxLayout(dialog);

    QPlainTextEdit *mirrorText = new QPlainTextEdit(dialog);
    mirrorText->setReadOnly(true);
    layout->addWidget(mirrorText);

    QPushButton *saveButton = new QPushButton(tr("Save to \"/etc/pacman.d/mirrorlist\""), dialog);
    layout->addWidget(saveButton);

    // 将 mirrorText 和 dialog 关联到 saveButton
    saveButton->setProperty("mirrorText", QVariant::fromValue(mirrorText));
    saveButton->setProperty("parentDialog", QVariant::fromValue(dialog));
    
    connect(saveButton, &QPushButton::clicked, this, &MirrorListWindow::onSaveButtonClicked);

    runRateMirrors(mirrors, mirrorText, dialog);

    dialog->setLayout(layout);

    // 确保对话框关闭后被销毁
    connect(dialog, &QDialog::finished, dialog, &QObject::deleteLater);

    dialog->exec();
}

void MirrorListWindow::runRateMirrors(const QStringList &mirrors, QPlainTextEdit *textEdit, QDialog *parentDialog)
{
    qInfo() << "MirrorListWindow: run rate-mirrors" << mirrors.size();
    QTemporaryFile *tempFile = new QTemporaryFile(parentDialog);
    if (!tempFile->open())
    {
        qWarning() << "MirrorListWindow: failed to create temp file";
        QMessageBox::critical(this, tr("Error"), tr("Failed to create temporary file."));
        return;
    }

    QTextStream out(tempFile);
    for (const QString &mirror : mirrors)
    {
        QString prefix = mirror.split("$repo").first();
        out << prefix << "\n";
    }
    out.flush();
    tempFile->close();

    QProcess *process = new QProcess(parentDialog);

    textEdit->appendPlainText(tr("Testing mirror speeds...\n"));

    connect(process, &QProcess::readyReadStandardOutput, this, [process, textEdit]() {
        QByteArray output = process->readAllStandardOutput();
        textEdit->appendPlainText(QString::fromUtf8(output));
    });

    connect(process, &QProcess::readyReadStandardError, this, [process, textEdit]() {
        QByteArray error = process->readAllStandardError();
        textEdit->appendPlainText(QString::fromUtf8(error));
    });

    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), 
            this, [process, textEdit, parentDialog](int exitCode, QProcess::ExitStatus exitStatus) {
        if (exitStatus == QProcess::CrashExit || exitCode != 0)
        {
            textEdit->appendPlainText("\n" + tr("Error: rate-mirrors command failed."));
            QMessageBox::critical(parentDialog, tr("Error"), tr("rate-mirrors command failed."));
        } else {
            textEdit->appendPlainText("\n" + tr("Done! Select the fastest mirrors above."));
        }
        process->deleteLater();
    });

    QStringList arguments;
    arguments << "stdin"
              << "--path-to-test=core/os/x86_64/core.db"
              << "--path-to-return=$repo/os/$arch"
              << "--comment-prefix=# "
              << "--output-prefix=Server = ";

    // 启动 rate-mirrors
    process->setStandardInputFile(tempFile->fileName());
    process->start("rate-mirrors", arguments);

    if (!process->waitForStarted())
    {
        qWarning() << "MirrorListWindow: failed to start rate-mirrors";
        QMessageBox::critical(parentDialog, tr("Error"), tr("Failed to start rate-mirrors command."));
        return;
    }
}

void MirrorListWindow::onCountryButtonClicked(const QString &country)
{
    qInfo() << "MirrorListWindow: country selected" << country;
    showMirrorsForCountry(country);
}

void MirrorListWindow::onSaveButtonClicked()
{
    qInfo() << "MirrorListWindow: save mirror list";
    QPushButton *button = qobject_cast<QPushButton *>(sender());
    if (!button) return;

    QPlainTextEdit *mirrorText = button->property("mirrorText").value<QPlainTextEdit*>();
    QDialog *dialog = button->property("parentDialog").value<QDialog*>();

    if (!mirrorText)
    {
        qWarning() << "MirrorListWindow: missing mirror text";
        QMessageBox::critical(this, tr("Error"), tr("Failed to find mirror text."));
        return;
    }

    QString content = mirrorText->toPlainText();

    QStringList lines = content.split("\n");
    QStringList validLines;
    for (const QString &line : lines)
    {
        QString trimmed = line.trimmed();
        if (!trimmed.startsWith("#") && !trimmed.isEmpty() && trimmed.startsWith("Server = "))
        {
            validLines.append(line);
        }
    }

    if (validLines.isEmpty())
    {
        qWarning() << "MirrorListWindow: no valid mirror servers";
        QMessageBox::warning(this, tr("Warning"), tr("No valid mirror servers found."));
        return;
    }

    // 只保留前 5 个最快的
    if (validLines.size() > 5)
    {
        validLines = validLines.mid(0, 5);
    }

    QTemporaryFile tempFile;
    if (!tempFile.open())
    {
        qWarning() << "MirrorListWindow: failed to create temp file";
        QMessageBox::critical(this, tr("Error"), tr("Failed to create temporary file."));
        return;
    }

    QTextStream out(&tempFile);
    for (const QString &line : validLines)
    {
        out << line << "\n";
    }
    out.flush();
    tempFile.close();

    QProcess process;
    process.start("pkexec", {"cp", tempFile.fileName(), "/etc/pacman.d/mirrorlist"});

    if (!process.waitForFinished())
    {
        qWarning() << "MirrorListWindow: pkexec copy did not finish";
        QMessageBox::critical(this, tr("Error"), tr("Failed to run pkexec command."));
        return;
    }

    if (process.exitCode() != 0)
    {
        qWarning() << "MirrorListWindow: failed to update mirror list" << process.exitCode();
        QString errorMsg = process.readAllStandardError();
        QMessageBox::critical(this, tr("Error"), tr("Failed to update mirror list: ") + errorMsg);
        return;
    }

    qInfo() << "MirrorListWindow: mirror list updated" << validLines.size();
    QMessageBox::information(this, tr("Success"), 
                            tr("Mirror list updated successfully with %1 mirrors.").arg(validLines.size()));
    
    if (dialog) {
        dialog->accept();
    }
}
bool MirrorListWindow::checkRateMirrorsInstalled()
{
    QProcess process;
    process.start("which", {"rate-mirrors"});
    process.waitForFinished();
    const bool installed = process.exitCode() == 0;
    qInfo() << "MirrorListWindow: rate-mirrors installed" << installed;
    return installed;
}