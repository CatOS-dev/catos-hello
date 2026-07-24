#ifndef POSTINSTALLGUIDETAB_H
#define POSTINSTALLGUIDETAB_H

#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QPushButton>

class PostInstallGuideTab : public QWidget
{
    Q_OBJECT

public:
    explicit PostInstallGuideTab(QWidget *parent = nullptr);

private:
    QLabel *postInstallGuideLabel;
    QVBoxLayout *layout;
    QGridLayout *gridLayout;
    QPushButton *pacmanButton;
    // QPushButton *logButton;
    QPushButton *mirrorButton;
    QPushButton *collectLogsButton;
    QPushButton *vacuumJournalButton;
    QPushButton *clearTempButton;
    QPushButton *chooseButton;
    QPushButton *updateAURButton;
    QPushButton *packageCleanButton;
    QPushButton *updateButton;
    QPushButton *driverConfigButton;
    QPushButton *offlinePostInstallButton;

private slots:
    void onPacmanButtonClicked();
    void onDriverConfigButtonClicked();
    void onMirrorButtonClicked();
    void onUpdateButtonClicked();
    void onUpdateAURButtonClicked();
    void onOfflinePostInstallClicked();
    void onCollectLogsClicked();
    void onVacuumJournalClicked();
    void onClearTempClicked();
};

#endif // POSTINSTALLGUIDETAB_H
