#include "home/HomePage.h"
#include "ui/ActionList.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QScrollArea>
#include <QToolButton>
#include <QVBoxLayout>

HomePage::HomePage(const Environment &env, QWidget *parent) : QWidget(parent)
{
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    outer->addWidget(scroll);
    auto *content = new QWidget(scroll);
    scroll->setWidget(content);
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(28, 20, 34, 30);
    layout->setSpacing(6);

    Ui::addTitle(layout, content, tr("Welcome to CatOS"),
                 tr("%1  ·  %2  ·  %3").arg(env.osName, env.desktop,
                     env.live ? tr("Live session") : tr("Installed system")));

    if (env.live) {
        Ui::addSection(layout, content, tr("Start here"));
        auto *intro = new QLabel(tr("Install CatOS or use the recovery tools before installation."), content);
        intro->setWordWrap(true);
        intro->setForegroundRole(QPalette::PlaceholderText);
        layout->addWidget(intro);
        layout->addSpacing(8);

        auto *install = new QPushButton(tr("Install CatOS"), content);
        install->setObjectName(QStringLiteral("install"));
        install->setIcon(QIcon::fromTheme(QStringLiteral("system-software-install")));
        install->setIconSize(QSize(24, 24));
        install->setMinimumHeight(60);
        install->setMinimumWidth(260);
        install->setCursor(Qt::PointingHandCursor);
        install->setStyleSheet(QStringLiteral(
            "QPushButton { background: palette(highlight); color: palette(highlighted-text);"
            "border: 0; border-radius: 10px; padding: 10px 22px; font-weight: bold; }"
            "QPushButton:hover { border: 2px solid palette(highlighted-text); }"
            "QPushButton:focus { border: 2px solid palette(highlighted-text); }"));
        connect(install, &QPushButton::clicked, this, [this] { emit actionRequested(QStringLiteral("install")); });
        layout->addWidget(install, 0, Qt::AlignLeft);

        Ui::addSection(layout, content, tr("Installation options"));
        auto *advanced = Ui::addAction(layout, content, tr("Advanced installer"),
            tr("Choose the network installation configuration and additional packages."),
            QStringLiteral("preferences-system"));
        advanced->setObjectName(QStringLiteral("install-advanced"));
        connect(advanced, &QPushButton::clicked, this, [this] {
            emit actionRequested(QStringLiteral("install-advanced"));
        });

        Ui::addSection(layout, content, tr("Before installing"));
        auto *partition = Ui::addAction(layout, content, tr("Partition disks (GParted)"),
            tr("Inspect or prepare disk partitions before starting the installer."),
            QStringLiteral("drive-harddisk"));
        partition->setObjectName(QStringLiteral("partition"));
        connect(partition, &QPushButton::clicked, this, [this] {
            emit actionRequested(QStringLiteral("partition"));
        });
        auto *logs = Ui::addAction(layout, content, tr("Get installation logs"),
            tr("View Calamares logs if an installation failed."),
            QStringLiteral("text-x-log"));
        logs->setObjectName(QStringLiteral("install-log"));
        connect(logs, &QPushButton::clicked, this, [this] {
            emit actionRequested(QStringLiteral("install-log"));
        });
        layout->addStretch();
        return;
    }

    guide_ = new QWidget(content);
    auto *steps = new QVBoxLayout(guide_);
    steps->setContentsMargins(0, 0, 0, 0);
    steps->setSpacing(4);
    Ui::addSection(steps, guide_, tr("Getting started"));
    auto *explanation = new QLabel(tr("Choose what to do next. You can skip any step and return later."), guide_);
    explanation->setWordWrap(true);
    explanation->setForegroundRole(QPalette::PlaceholderText);
    steps->addWidget(explanation);
    progress_ = new QLabel(guide_);
    progress_->setForegroundRole(QPalette::PlaceholderText);
    steps->addWidget(progress_);
    addStep(steps, QStringLiteral("updates"), tr("Update CatOS"),
            tr("Check important news and update your system with CatOS updater."),
            QStringLiteral("update"), tr("Run CatOS updater"));
    addStep(steps, QStringLiteral("drivers"), tr("Check hardware drivers"),
            tr("Review available hardware profiles before making changes."),
            QStringLiteral("drivers"), tr("Review drivers"));
    addStep(steps, QStringLiteral("apps"), tr("Install your applications"),
            tr("Find repository, AUR and Flatpak applications."),
            QStringLiteral("software"), tr("Browse software"));
    addStep(steps, QStringLiteral("desktop"), tr("Personalize your desktop"),
            tr("Discover settings for your current desktop."),
            QStringLiteral("desktop"), tr("Configure desktop"));
    auto *dismiss = new QToolButton(guide_);
    dismiss->setText(tr("Hide getting-started guide"));
    dismiss->setAutoRaise(true);
    connect(dismiss, &QToolButton::clicked, this, [this] {
        onboarding_.setDismissed(true);
        refreshGuide();
    });
    steps->addWidget(dismiss, 0, Qt::AlignRight);
    layout->addWidget(guide_);

    resume_ = new QWidget(content);
    auto *resumeLayout = new QHBoxLayout(resume_);
    resumeLayout->setContentsMargins(0, 4, 0, 4);
    resumeLayout->addWidget(new QLabel(tr("Need help setting up CatOS?"), resume_), 1);
    auto *resumeButton = new QToolButton(resume_);
    resumeButton->setText(tr("Show getting-started guide"));
    resumeButton->setAutoRaise(true);
    connect(resumeButton, &QToolButton::clicked, this, [this] {
        onboarding_.reset();
        refreshGuide();
    });
    resumeLayout->addWidget(resumeButton);
    layout->addWidget(resume_);

    Ui::addSection(layout, content, tr("Explore CatOS"));
    for (const auto &item : {qMakePair(tr("Software manager"), QStringLiteral("software")),
                             qMakePair(tr("Desktop settings"), QStringLiteral("desktop")),
                             qMakePair(tr("System tools"), QStringLiteral("maintenance"))}) {
        auto *row = Ui::addAction(layout, content, item.first,
                                  item.second == QStringLiteral("software") ? tr("Install and manage applications.") :
                                  item.second == QStringLiteral("desktop") ? tr("Adjust your desktop environment.") :
                                  tr("Open maintenance and diagnostic tools."),
                                  item.second == QStringLiteral("software") ? QStringLiteral("applications-system") :
                                  item.second == QStringLiteral("desktop") ? QStringLiteral("preferences-desktop") :
                                  QStringLiteral("preferences-system"));
        connect(row, &QPushButton::clicked, this, [this, page = item.second] { emit navigateTo(page); });
    }
    layout->addStretch();
    refreshGuide();
}

void HomePage::addStep(QVBoxLayout *layout, const QString &id, const QString &title,
                       const QString &detail, const QString &action, const QString &label)
{
    auto *row = new QWidget(guide_);
    row->setObjectName(QStringLiteral("step_") + id);
    auto *line = new QHBoxLayout(row);
    line->setContentsMargins(0, 0, 0, 0);
    line->setSpacing(4);
    const QString icon = id == QStringLiteral("updates") ? QStringLiteral("system-software-update") :
                         id == QStringLiteral("drivers") ? QStringLiteral("computer") :
                         id == QStringLiteral("apps") ? QStringLiteral("applications-system") :
                         QStringLiteral("preferences-desktop");
    auto *open = new ActionRow(title, detail, icon, row);
    open->setToolTip(label);
    open->setObjectName(QStringLiteral("action_") + action);
    connect(open, &QPushButton::clicked, this, [this, action] { emit actionRequested(action); });
    line->addWidget(open, 1);

    auto *options = new QToolButton(row);
    options->setText(QStringLiteral("⋯"));
    options->setAccessibleName(tr("Step options"));
    options->setAutoRaise(true);
    options->setCursor(Qt::PointingHandCursor);
    options->setToolTip(tr("Step options"));
    auto *menu = new QMenu(options);
    auto *done = menu->addAction(tr("I completed this"));
    connect(done, &QAction::triggered, this, [this, id] {
        onboarding_.setMarkedDone(id, true);
        refreshGuide();
    });
    auto *skip = menu->addAction(tr("Later"));
    connect(skip, &QAction::triggered, this, [this, id] {
        onboarding_.setSkipped(id, true);
        refreshGuide();
    });
    connect(options, &QToolButton::clicked, this, [options, menu] {
        menu->popup(options->mapToGlobal(QPoint(0, options->height())));
    });
    line->addWidget(options);
    layout->addWidget(row);
    stepRows_.append(row);
}

void HomePage::refreshGuide()
{
    guide_->setVisible(!onboarding_.dismissed());
    resume_->setVisible(onboarding_.dismissed());
    const QStringList ids = {QStringLiteral("updates"), QStringLiteral("drivers"),
                             QStringLiteral("apps"), QStringLiteral("desktop")};
    int done = 0;
    int skipped = 0;
    for (int i = 0; i < stepRows_.size() && i < ids.size(); ++i) {
        const bool isDone = onboarding_.markedDone(ids[i]);
        const bool isSkipped = onboarding_.skipped(ids[i]);
        stepRows_[i]->setVisible(!isSkipped && !isDone);
        done += isDone;
        skipped += isSkipped;
    }
    progress_->setText(tr("%1 of %2 steps marked complete by you · %3 postponed")
                           .arg(done).arg(ids.size()).arg(skipped));
}
