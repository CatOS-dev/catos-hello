#include "home/HomePage.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

HomePage::HomePage(QWidget *parent) : QWidget(parent)
{
    auto *outer = new QVBoxLayout(this);
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    outer->addWidget(scroll);
    auto *content = new QWidget(scroll);
    scroll->setWidget(content);
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(18, 14, 22, 20);
    layout->setSpacing(18);

    auto *title = new QLabel(tr("Welcome to CatOS"), content);
    QFont font = title->font();
    font.setPointSize(font.pointSize() + 9);
    font.setBold(true);
    title->setFont(font);
    layout->addWidget(title);
    const auto env = Environment::detect();
    auto *summary = new QLabel(tr("%1  ·  %2  ·  %3")
        .arg(env.osName, env.desktop,
             env.live ? tr("Live session") : tr("Installed system")), content);
    summary->setWordWrap(true);
    layout->addWidget(summary);

    auto *links = new QHBoxLayout;
    for (const auto &entry : {qMakePair(tr("Software manager"), QStringLiteral("software")),
                             qMakePair(tr("Desktop settings"), QStringLiteral("desktop")),
                             qMakePair(tr("System tools"), QStringLiteral("maintenance"))}) {
        auto *button = new QPushButton(entry.first, content);
        connect(button, &QPushButton::clicked, this, [this, page = entry.second] { emit navigateTo(page); });
        links->addWidget(button);
    }
    layout->addLayout(links);

    guide_ = new QWidget(content);
    auto *steps = new QVBoxLayout(guide_);
    steps->setContentsMargins(0, 8, 0, 8);
    auto *heading = new QLabel(tr("Getting started"), guide_);
    QFont headingFont = heading->font();
    headingFont.setBold(true);
    heading->setFont(headingFont);
    steps->addWidget(heading);
    auto *explanation = new QLabel(tr("Choose what to do next. You can skip any step and return later."), guide_);
    explanation->setWordWrap(true);
    steps->addWidget(explanation);
    addStep(steps, QStringLiteral("updates"), tr("Update CatOS"),
            tr("Review software updates with Shelly."), QStringLiteral("shelly"), tr("Open Shelly"));
    addStep(steps, QStringLiteral("drivers"), tr("Check hardware drivers"),
            tr("Review available hardware profiles before making changes."), QStringLiteral("drivers"), tr("Review drivers"));
    addStep(steps, QStringLiteral("apps"), tr("Install your applications"),
            tr("Find repository, AUR and Flatpak applications."), QStringLiteral("software"), tr("Browse software"));
    addStep(steps, QStringLiteral("desktop"), tr("Personalize your desktop"),
            tr("Discover settings for your current desktop."), QStringLiteral("desktop"), tr("Configure desktop"));
    auto *dismiss = new QPushButton(tr("Hide getting-started guide"), guide_);
    connect(dismiss, &QPushButton::clicked, this, [this] {
        onboarding_.setDismissed(true);
        refreshGuide();
    });
    steps->addWidget(dismiss, 0, Qt::AlignLeft);
    layout->addWidget(guide_);

    resume_ = new QWidget(content);
    auto *resumeLayout = new QHBoxLayout(resume_);
    resumeLayout->setContentsMargins(0, 0, 0, 0);
    resumeLayout->addWidget(new QLabel(tr("Need help setting up CatOS?"), resume_));
    auto *resumeButton = new QPushButton(tr("Show getting-started guide"), resume_);
    connect(resumeButton, &QPushButton::clicked, this, [this] {
        onboarding_.reset();
        refreshGuide();
    });
    resumeLayout->addWidget(resumeButton);
    layout->addWidget(resume_);
    layout->addStretch();
    refreshGuide();
}

void HomePage::addStep(QVBoxLayout *layout, const QString &id, const QString &title,
                       const QString &detail, const QString &action, const QString &label)
{
    auto *row = new QFrame(guide_);
    row->setFrameShape(QFrame::StyledPanel);
    auto *line = new QHBoxLayout(row);
    auto *text = new QVBoxLayout;
    auto *heading = new QLabel(title, row);
    QFont font = heading->font();
    font.setBold(true);
    heading->setFont(font);
    text->addWidget(heading);
    auto *description = new QLabel(detail, row);
    description->setWordWrap(true);
    text->addWidget(description);
    line->addLayout(text, 1);
    auto *open = new QPushButton(label, row);
    connect(open, &QPushButton::clicked, this, [this, action] { emit actionRequested(action); });
    line->addWidget(open);
    auto *skip = new QPushButton(tr("Later"), row);
    connect(skip, &QPushButton::clicked, this, [this, row, id] {
        onboarding_.setSkipped(id, true);
        row->hide();
    });
    line->addWidget(skip);
    row->setVisible(!onboarding_.skipped(id));
    layout->addWidget(row);
}

void HomePage::refreshGuide()
{
    guide_->setVisible(!onboarding_.dismissed());
    resume_->setVisible(onboarding_.dismissed());
    // A reset must also reveal steps that were previously skipped.
    const auto rows = guide_->findChildren<QFrame *>(QString(), Qt::FindDirectChildrenOnly);
    const QStringList ids = {QStringLiteral("updates"), QStringLiteral("drivers"),
                             QStringLiteral("apps"), QStringLiteral("desktop")};
    for (int i = 0; i < rows.size() && i < ids.size(); ++i)
        rows[i]->setVisible(!onboarding_.skipped(ids[i]));
}
