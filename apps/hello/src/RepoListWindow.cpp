#include "RepoListWindow.h"
#include <QFile>
#include <QTextStream>
#include <QMessageBox>
#include <QProcess>
#include <QTemporaryFile>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QFormLayout>
#include <QListWidget>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QPushButton>
#include <QInputDialog>
#include <QDateTime>
#include <QCloseEvent>
#include <QDebug>
#include <QRegularExpression>

RepoListWindow::RepoListWindow(QWidget *parent) : QDialog(parent) {
    setWindowTitle(tr("Repository Configuration"));
    resize(800, 500);
    setupUI();
    loadConfig();
    baseWindowTitle = windowTitle(); // 保存基础标题
    updateWindowTitle();
}

void RepoListWindow::setupUI() {
    // 初始化控件
    repoList = new QListWidget(this);
    repoNameEdit = new QLineEdit(this);
    includeEdit = new QLineEdit(this);
    serversEdit = new QPlainTextEdit(this);
    sigLevelCombo = new QComboBox(this);
    sigLevelCombo->addItems({"Never", "Optional", "Required", "Optional TrustAll", "Required TrustedOnly", "Optional TrustedOnly"});
    QPushButton *addRepoBtn = new QPushButton(tr("Add Repo"), this);
    QPushButton *deleteRepoBtn = new QPushButton(tr("Delete Repo"), this);
    QPushButton *saveBtn = new QPushButton(tr("Save"), this);

    // 布局管理
    QHBoxLayout *mainLayout = new QHBoxLayout;
    QVBoxLayout *leftButtonLayout = new QVBoxLayout;
    leftButtonLayout->addWidget(addRepoBtn);
    leftButtonLayout->addWidget(deleteRepoBtn);
    leftButtonLayout->addStretch();

    QHBoxLayout *repoListLayout = new QHBoxLayout;
    repoListLayout->addWidget(repoList);
    repoListLayout->addLayout(leftButtonLayout);

    QFormLayout *formLayout = new QFormLayout;
    formLayout->addRow(tr("Repo Name:"), repoNameEdit);
    formLayout->addRow(tr("Include Path:"), includeEdit);
    formLayout->addRow(tr("Mirror Server:"), serversEdit);
    formLayout->addRow(tr("SigLevel:"), sigLevelCombo);

    QVBoxLayout *rightLayout = new QVBoxLayout;
    rightLayout->addLayout(formLayout);
    rightLayout->addStretch();
    rightLayout->addWidget(saveBtn);
    mainLayout->addLayout(repoListLayout, 1);
    mainLayout->addLayout(rightLayout, 2);

    setLayout(mainLayout);

    // 信号槽连接
    connect(repoList, &QListWidget::currentRowChanged, this, &RepoListWindow::onRepoSelected);
    connect(repoNameEdit, &QLineEdit::textEdited, this, &RepoListWindow::onRepoNameEdited);
    connect(includeEdit, &QLineEdit::textEdited, this, &RepoListWindow::onIncludeEdited);
    connect(serversEdit, &QPlainTextEdit::textChanged, this, &RepoListWindow::onServersEdited);
    connect(sigLevelCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &RepoListWindow::onSigLevelChanged);
    connect(addRepoBtn, &QPushButton::clicked, this, &RepoListWindow::addRepo);
    connect(deleteRepoBtn, &QPushButton::clicked, this, &RepoListWindow::deleteRepo);
    connect(saveBtn, &QPushButton::clicked, this, &RepoListWindow::saveConfig);
}

bool RepoListWindow::parseKeyValue(const QString &line, QString &key, QString &value) {
    // 使用正则表达式更健壮地解析键值对
    static QRegularExpression keyValueRegex(R"(^\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*)$)");
    QRegularExpressionMatch match = keyValueRegex.match(line);
    
    if (match.hasMatch()) {
        key = match.captured(1).trimmed();
        value = match.captured(2).trimmed();
        return true;
    }
    return false;
}

void RepoListWindow::parseRepoLine(Repo &repo, const QString &line) {
    QString trimmed = line.trimmed();
    
    // 保留注释
    if (trimmed.startsWith('#')) {
        repo.origComments.append(line);
        repo.comments = repo.origComments;
        return;
    }
    
    // 跳过空行
    if (trimmed.isEmpty()) {
        return;
    }
    
    QString key, value;
    if (!parseKeyValue(line, key, value)) {
        qWarning() << "Failed to parse line in repo" << repo.name << ":" << line;
        return;
    }
    
    // 解析已知的键
    if (key == "Include") {
        repo.include = value;
        repo.origInclude = value;
    } else if (key == "Server") {
        repo.origServers.append(value);
        repo.servers = repo.origServers;
    } else if (key == "SigLevel") {
        repo.sigLevel = value;
        repo.origSigLevel = value;
    } else {
        // 保存未知的选项
        repo.extraOptions[key] = value;
        repo.origExtraOptions[key] = value;
        qDebug() << "Unknown repo option:" << key << "=" << value;
    }
}

void RepoListWindow::loadConfig() {
    qInfo() << "RepoListWindow: load config";
    QFile file("/etc/pacman.conf");
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "RepoListWindow: failed to open config" << file.errorString();
        QMessageBox::critical(this, tr("Error"), 
            tr("Failed to open configuration file: %1").arg(file.errorString()));
        return;
    }

    QTextStream in(&file);
    QStringList originalFileLines = in.readAll().split('\n');
    file.close();

    nonRepoLines.clear();
    origRepos.clear();
    repos.clear();

    Repo currentRepo;
    bool inRepoSection = false;
    int lineNumber = 0;
    QStringList parseErrors;

    // Lambda 保存当前仓库
    auto saveCurrentRepo = [&]() {
        if (inRepoSection && !currentRepo.name.isEmpty()) {
            // 同步工作副本
            currentRepo.servers = currentRepo.origServers;
            currentRepo.comments = currentRepo.origComments;
            currentRepo.extraOptions = currentRepo.origExtraOptions;
            origRepos.append(currentRepo);
            qDebug() << "Loaded repo:" << currentRepo.name 
                     << "with" << currentRepo.origServers.size() << "servers";
        }
    };

    // 解析每一行
    for (const QString &line : originalFileLines) {
        lineNumber++;
        QString trimmed = line.trimmed();

        // 检测段标记 [section]
        static QRegularExpression sectionRegex(R"(^\[([^\]]+)\]$)");
        QRegularExpressionMatch sectionMatch = sectionRegex.match(trimmed);
        
        if (sectionMatch.hasMatch()) {
            saveCurrentRepo(); // 保存上一个仓库

            QString sectionName = sectionMatch.captured(1).trimmed();
            
            if (sectionName == "options") {
                // options 段不是仓库
                inRepoSection = false;
                nonRepoLines.append(line);
            } else {
                // 开始新的仓库段
                inRepoSection = true;
                currentRepo = Repo();
                currentRepo.name = sectionName;
                currentRepo.origName = sectionName;
                qDebug() << "Found repo section:" << sectionName << "at line" << lineNumber;
            }
        } else if (inRepoSection) {
            // 在仓库段内，解析配置行
            parseRepoLine(currentRepo, line);
        } else {
            // 非仓库段的内容
            nonRepoLines.append(line);
        }
    }

    // 保存最后一个仓库
    saveCurrentRepo();

    // 初始化工作副本
    repos = origRepos;

    // 更新UI
    repoList->clear();
    for (const Repo &repo : repos) {
        QString displayName = repo.name;
        if (repo.servers.isEmpty() && repo.include.isEmpty()) {
            displayName += tr(" (empty)");
        }
        repoList->addItem(displayName);
    }
    
    qDebug() << "Loaded" << repos.size() << "repositories";
    updateWindowTitle();
}

bool RepoListWindow::hasChanges() const {
    if (repos.size() != origRepos.size()) return true;

    for (int i = 0; i < repos.size(); ++i) {
        const Repo &curr = repos[i];
        const Repo &orig = origRepos[i];

        if (curr.name != orig.origName ||
            curr.include != orig.origInclude ||
            curr.servers != orig.origServers ||
            curr.sigLevel != orig.origSigLevel ||
            curr.comments != orig.origComments ||
            curr.extraOptions != orig.origExtraOptions) {
            return true;
        }
    }
    return false;
}

bool RepoListWindow::backupConfigFile() {
    qInfo() << "RepoListWindow: backup config";
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    QString backupFile = QString("/etc/pacman.conf.bak_%1").arg(timestamp);

    QProcess process;
    process.start("pkexec", {"cp", "/etc/pacman.conf", backupFile});
    bool success = process.waitForFinished() && process.exitCode() == 0;
    
    if (success) {
        qDebug() << "Backup created:" << backupFile;
    } else {
        qWarning() << "RepoListWindow: backup failed" << backupFile;
    }
    
    return success;
}

bool RepoListWindow::writeConfigFile() {
    qInfo() << "RepoListWindow: write config";
    // 先写入临时文件
    QString tempFilePath = "/tmp/pacman.conf.tmp";
    QFile tempFile(tempFilePath);
    if (!tempFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qWarning() << "Failed to open temp file:" << tempFile.errorString();
        return false;
    }

    QTextStream out(&tempFile);
    
    // 写入非仓库段
    out << nonRepoLines.join('\n') << '\n';

    // 写入每个仓库
    for (const Repo &repo : repos) {
        // 仓库段标记
        out << "[" << repo.name << "]\n";
        
        // 写入注释（如果有）
        if (!repo.comments.isEmpty()) {
            for (const QString &comment : repo.comments) {
                out << comment << '\n';
            }
        }
        
        // 写入签名级别
        if (!repo.sigLevel.isEmpty()) {
            out << "SigLevel = " << repo.sigLevel << '\n';
        }
        
        // 写入 Include 路径
        if (!repo.include.isEmpty()) {
            out << "Include = " << repo.include << '\n';
        }
        
        // 写入额外选项
        for (auto it = repo.extraOptions.constBegin(); it != repo.extraOptions.constEnd(); ++it) {
            out << it.key() << " = " << it.value() << '\n';
        }

        // 写入服务器列表
        for (const QString &server : repo.servers) {
            out << "Server = " << server << '\n';
        }
        
        out << '\n'; // 段间分隔
    }

    tempFile.close();

    // 使用 pkexec 复制到系统位置
    QProcess process;
    process.start("pkexec", {"cp", tempFilePath, "/etc/pacman.conf"});
    if (!process.waitForFinished() || process.exitCode() != 0) {
        qWarning() << "Failed to copy config file:" << process.errorString();
        return false;
    }

    qDebug() << "Configuration saved successfully";
    return true;
}

void RepoListWindow::saveConfig() {
    qInfo() << "RepoListWindow: save config";
    if (!hasChanges()) {
        QMessageBox::information(this, tr("Note"), tr("No Change to Save"));
        return;
    }

    // 创建备份文件
    if (!backupConfigFile()) {
        QMessageBox::critical(this, tr("Error"), tr("Failed to create backup file"));
        return;
    }

    // 保存新配置
    if (!writeConfigFile()) {
        QMessageBox::critical(this, tr("Error"), tr("Failed to save configuration file"));
        return;
    }

    // 更新原始数据：同步所有 orig* 字段
    for (int i = 0; i < repos.size(); ++i) {
        repos[i].origName = repos[i].name;
        repos[i].origInclude = repos[i].include;
        repos[i].origServers = repos[i].servers;
        repos[i].origSigLevel = repos[i].sigLevel;
        repos[i].origComments = repos[i].comments;
        repos[i].origExtraOptions = repos[i].extraOptions;
    }
    origRepos = repos;
    
    updateWindowTitle(); // 更新标题
    QMessageBox::information(this, tr("Success"), 
        tr("Configuration has been updated. %1 repositories saved.").arg(repos.size()));
}

void RepoListWindow::onRepoSelected(int row) {
    if (row < 0 || row >= repos.size()) return;

    const Repo &repo = repos[row];
    repoNameEdit->setText(repo.name);
    includeEdit->setText(repo.include);
    serversEdit->setPlainText(repo.servers.join('\n'));

    int comboIndex = sigLevelCombo->findText(repo.sigLevel);
    sigLevelCombo->setCurrentIndex(comboIndex >= 0 ? comboIndex : 1);
}

void RepoListWindow::onRepoNameEdited(const QString &text) {
    int row = repoList->currentRow();
    if (row < 0 || row >= repos.size()) return;

    repos[row].name = text;
    repoList->item(row)->setText(text);
    updateWindowTitle();
}

void RepoListWindow::onIncludeEdited(const QString &text) {
    int row = repoList->currentRow();
    if (row >= 0) repos[row].include = text;
    updateWindowTitle();
}

void RepoListWindow::onServersEdited() {
    int row = repoList->currentRow();
    if (row >= 0) repos[row].servers = serversEdit->toPlainText().split('\n', Qt::SkipEmptyParts);
    updateWindowTitle();
}

void RepoListWindow::onSigLevelChanged(int index) {
    int row = repoList->currentRow();
    if (row >= 0) repos[row].sigLevel = sigLevelCombo->itemText(index);
    updateWindowTitle();
}

void RepoListWindow::addRepo() {
    qInfo() << "RepoListWindow: add repo";
    bool ok;
    QString name = QInputDialog::getText(this, tr("Add Repo"), tr("Enter the Repo name:"), QLineEdit::Normal, "", &ok);
    if (!ok || name.isEmpty()) return;

    if (name.contains(' ') || name.contains('[') || name.contains(']')) {
        qWarning() << "RepoListWindow: invalid repo name" << name;
        QMessageBox::warning(this, tr("Error"), tr("Repo name contains invalid chars"));
        return;
    }

    Repo newRepo;
    newRepo.name = name;
    newRepo.origName = name;
    repos.append(newRepo);
    repoList->addItem(name);
    repoList->setCurrentRow(repos.size() - 1);
    updateWindowTitle();
}

void RepoListWindow::deleteRepo() {
    qInfo() << "RepoListWindow: delete repo";
    int row = repoList->currentRow();
    if (row < 0 || row >= repos.size()) return;

    repos.removeAt(row);
    delete repoList->takeItem(row);
    updateWindowTitle();
}

void RepoListWindow::updateWindowTitle() {
    if (hasChanges()) {
        setWindowTitle(baseWindowTitle + " *");
    } else {
        setWindowTitle(baseWindowTitle);
    }
}
void RepoListWindow::closeEvent(QCloseEvent *event) {
    qInfo() << "RepoListWindow: close event";
    if (hasChanges()) {
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, tr("Unsaved Changes"),
                                       tr("You have unsaved changes. Do you want to save before closing?"),
                                       QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
        
        if (reply == QMessageBox::Save) {
            saveConfig();
            if (hasChanges()) {
                // 保存失败，不关闭
                event->ignore();
            } else {
                event->accept();
            }
        } else if (reply == QMessageBox::Discard) {
            event->accept();
        } else {
            event->ignore();
        }
    } else {
        event->accept();
    }
}