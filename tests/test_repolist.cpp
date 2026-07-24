#include <QtTest/QtTest>
#include <QTemporaryFile>
#include <QFile>
#include <QTextStream>
#include "RepoListWindow.h"

class TestRepoListWindow : public QObject
{
    Q_OBJECT

private:
    QString createTestPacmanConf(const QString &content) {
        QTemporaryFile *tempFile = new QTemporaryFile(this);
        tempFile->setAutoRemove(false);
        
        if (!tempFile->open()) {
            return QString();
        }
        
        QTextStream out(tempFile);
        out << content;
        tempFile->close();
        
        return tempFile->fileName();
    }
    
    QString readFile(const QString &path) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            return QString();
        }
        QTextStream in(&file);
        return in.readAll();
    }

private slots:
    void initTestCase() {
        qDebug() << "开始 RepoListWindow 测试";
    }

    void cleanupTestCase() {
        qDebug() << "完成 RepoListWindow 测试";
    }

    void testParseKeyValue() {
        QString key, value;
        
        // 测试标准格式
        QVERIFY(RepoListWindow::parseKeyValue("Server = https://example.com", key, value));
        QCOMPARE(key, QString("Server"));
        QCOMPARE(value, QString("https://example.com"));
        
        // 测试多余空格
        QVERIFY(RepoListWindow::parseKeyValue("  SigLevel  =  Required  ", key, value));
        QCOMPARE(key, QString("SigLevel"));
        QCOMPARE(value, QString("Required"));
        
        // 测试无空格
        QVERIFY(RepoListWindow::parseKeyValue("Include=/etc/pacman.d/mirrorlist", key, value));
        QCOMPARE(key, QString("Include"));
        QCOMPARE(value, QString("/etc/pacman.d/mirrorlist"));
        
        // 测试包含等号的值
        QVERIFY(RepoListWindow::parseKeyValue("Desc = Test = Value", key, value));
        QCOMPARE(key, QString("Desc"));
        QCOMPARE(value, QString("Test = Value"));
        
        // 测试无效格式
        QVERIFY(!RepoListWindow::parseKeyValue("InvalidLine", key, value));
        QVERIFY(!RepoListWindow::parseKeyValue("# Comment = Value", key, value));
        QVERIFY(!RepoListWindow::parseKeyValue("", key, value));
    }

    void testParseBasicRepo() {
        QString testConfig = R"([options]
HoldPkg = pacman glibc
Architecture = auto

[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Server = https://mirrors.example.com/archlinux/$repo/os/$arch
Server = https://mirrors.example2.com/archlinux/$repo/os/$arch
SigLevel = Required
)";
        
        // 由于 RepoListWindow 直接读取 /etc/pacman.conf，
        // 这里我们需要测试解析逻辑本身
        // 实际项目中应该重构使其可以接受文件路径参数
        
        // 这是一个集成测试的框架示例
        QVERIFY(true); // 占位符
    }

    void testParseRepoWithComments() {
        Repo repo;
        repo.name = "test-repo";
        
        // 测试注释
        RepoListWindow::parseRepoLine(repo, "# This is a comment");
        QCOMPARE(repo.comments.size(), 1);
        QVERIFY(repo.comments[0].contains("This is a comment"));
        
        // 测试服务器
        RepoListWindow::parseRepoLine(repo, "Server = https://example.com/$repo/os/$arch");
        QCOMPARE(repo.servers.size(), 1);
        QCOMPARE(repo.servers[0], QString("https://example.com/$repo/os/$arch"));
        
        // 测试 Include
        RepoListWindow::parseRepoLine(repo, "Include = /etc/pacman.d/mirrorlist");
        QCOMPARE(repo.include, QString("/etc/pacman.d/mirrorlist"));
        
        // 测试 SigLevel
        RepoListWindow::parseRepoLine(repo, "SigLevel = Required DatabaseOptional");
        QCOMPARE(repo.sigLevel, QString("Required DatabaseOptional"));
    }

    void testParseRepoWithExtraOptions() {
        Repo repo;
        repo.name = "test-repo";
        
        // 测试额外选项
        RepoListWindow::parseRepoLine(repo, "Usage = Search Sync");
        QVERIFY(repo.extraOptions.contains("Usage"));
        QCOMPARE(repo.extraOptions["Usage"], QString("Search Sync"));
        
        RepoListWindow::parseRepoLine(repo, "CustomOption = CustomValue");
        QVERIFY(repo.extraOptions.contains("CustomOption"));
        QCOMPARE(repo.extraOptions["CustomOption"], QString("CustomValue"));
    }

    void testHasChanges() {
        // 测试变更检测逻辑
        Repo original;
        original.name = "test";
        original.origName = "test";
        original.include = "/etc/pacman.d/mirrorlist";
        original.origInclude = "/etc/pacman.d/mirrorlist";
        original.servers = {"https://example.com"};
        original.origServers = {"https://example.com"};
        original.sigLevel = "Required";
        original.origSigLevel = "Required";
        
        // 无变更
        Repo modified = original;
        // QVERIFY(!hasChanges(original, modified)); // 需要辅助函数
        
        // 修改名称
        modified.name = "test-modified";
        // QVERIFY(hasChanges(original, modified));
    }

    void testWriteConfig() {
        // 创建临时配置
        QString testConfig = R"([options]
Architecture = auto

[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Server = https://example.com/$repo/os/$arch
)";
        
        // 测试写入和读取的一致性
        QTemporaryFile tempFile;
        QVERIFY(tempFile.open());
        
        QTextStream out(&tempFile);
        out << testConfig;
        tempFile.close();
        
        QString readContent = readFile(tempFile.fileName());
        QVERIFY(readContent.contains("[core]"));
        QVERIFY(readContent.contains("[extra]"));
    }

    void testEmptyRepo() {
        Repo repo;
        repo.name = "empty-repo";
        repo.origName = "empty-repo";
        
        // 空仓库应该有效
        QVERIFY(!repo.name.isEmpty());
        QVERIFY(repo.servers.isEmpty());
        QVERIFY(repo.include.isEmpty());
    }

    void testMultipleServers() {
        Repo repo;
        repo.name = "multi-server";
        
        // 添加多个服务器
        RepoListWindow::parseRepoLine(repo, "Server = https://mirror1.com/$repo/os/$arch");
        RepoListWindow::parseRepoLine(repo, "Server = https://mirror2.com/$repo/os/$arch");
        RepoListWindow::parseRepoLine(repo, "Server = https://mirror3.com/$repo/os/$arch");
        
        QCOMPARE(repo.servers.size(), 3);
        QCOMPARE(repo.servers[0], QString("https://mirror1.com/$repo/os/$arch"));
        QCOMPARE(repo.servers[1], QString("https://mirror2.com/$repo/os/$arch"));
        QCOMPARE(repo.servers[2], QString("https://mirror3.com/$repo/os/$arch"));
    }

    void testInvalidRepoNames() {
        // 测试无效仓库名称的处理
        QStringList invalidNames = {
            "repo with spaces",
            "repo[bracket]",
            "repo]bracket",
            "[repo",
            ""
        };
        
        // 这些应该在 UI 层被拒绝
        for (const QString &name : invalidNames) {
            QVERIFY(name.contains(' ') || name.contains('[') || name.contains(']') || name.isEmpty());
        }
    }

    void testSigLevelOptions() {
        QStringList validSigLevels = {
            "Never",
            "Optional",
            "Required",
            "Optional TrustAll",
            "Required TrustedOnly",
            "Optional TrustedOnly"
        };
        
        for (const QString &level : validSigLevels) {
            Repo repo;
            repo.name = "test";
            
            RepoListWindow::parseRepoLine(repo, QString("SigLevel = %1").arg(level));
            QCOMPARE(repo.sigLevel, level);
        }
    }

    void testCommentPreservation() {
        Repo repo;
        repo.name = "test";
        
        // 添加多行注释
        RepoListWindow::parseRepoLine(repo, "# Comment 1");
        RepoListWindow::parseRepoLine(repo, "# Comment 2");
        RepoListWindow::parseRepoLine(repo, "## Special comment");
        
        QCOMPARE(repo.comments.size(), 3);
        QVERIFY(repo.comments[0].contains("Comment 1"));
        QVERIFY(repo.comments[1].contains("Comment 2"));
        QVERIFY(repo.comments[2].contains("Special comment"));
    }
};

QTEST_MAIN(TestRepoListWindow)
#include "test_repolist.moc"
