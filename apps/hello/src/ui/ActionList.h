#pragma once

#include <QFrame>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPalette>
#include <QPushButton>
#include <QSizePolicy>
#include <QVBoxLayout>

// One focusable, keyboard-activated action with a descriptive label. The
// children draw the content; the QPushButton itself provides native semantics.
class ActionRow : public QPushButton {
public:
    explicit ActionRow(const QString &title, const QString &description,
                       const QString &iconName, QWidget *parent = nullptr,
                       const QString &marker = QStringLiteral("›"))
        : QPushButton(parent)
    {
        setAccessibleName(title);
        setAccessibleDescription(description);
        setFlat(true);
        setCursor(Qt::PointingHandCursor);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        setMinimumHeight(description.isEmpty() ? 54 : 66);
        setStyleSheet(QStringLiteral(
            "QPushButton { border: 0; border-radius: 9px; background: transparent; }"
            "QPushButton:hover { background: palette(alternate-base); }"
            "QPushButton:focus { border: 1px solid palette(highlight); }"));

        auto *line = new QHBoxLayout(this);
        line->setContentsMargins(10, 7, 10, 7);
        line->setSpacing(14);
        auto *icon = new QLabel(this);
        icon->setFixedSize(30, 30);
        icon->setAlignment(Qt::AlignCenter);
        auto theme = QIcon::fromTheme(iconName);
        if (theme.isNull()) theme = QIcon::fromTheme(QStringLiteral("applications-system"));
        if (!theme.isNull()) icon->setPixmap(theme.pixmap(24, 24));
        line->addWidget(icon);

        auto *texts = new QVBoxLayout;
        texts->setContentsMargins(0, 0, 0, 0);
        texts->setSpacing(3);
        auto *heading = new QLabel(title, this);
        auto font = heading->font();
        font.setBold(true);
        heading->setFont(font);
        texts->addWidget(heading);
        if (!description.isEmpty()) {
            auto *detail = new QLabel(description, this);
            detail->setWordWrap(true);
            detail->setForegroundRole(QPalette::PlaceholderText);
            texts->addWidget(detail);
        }
        line->addLayout(texts, 1);
        auto *chevron = new QLabel(marker, this);
        auto arrowFont = chevron->font();
        arrowFont.setPointSize(arrowFont.pointSize() + 8);
        chevron->setFont(arrowFont);
        chevron->setForegroundRole(QPalette::PlaceholderText);
        chevron->setFixedWidth(28);
        chevron->setAlignment(Qt::AlignCenter);
        line->addWidget(chevron);
    }
};

namespace Ui {
inline QLabel *addTitle(QVBoxLayout *layout, QWidget *parent,
                        const QString &title, const QString &subtitle = {})
{
    auto *heading = new QLabel(title, parent);
    auto font = heading->font();
    font.setPointSize(font.pointSize() + 9);
    font.setBold(true);
    heading->setFont(font);
    layout->addWidget(heading);
    if (!subtitle.isEmpty()) {
        auto *description = new QLabel(subtitle, parent);
        description->setWordWrap(true);
        description->setForegroundRole(QPalette::PlaceholderText);
        layout->addWidget(description);
    }
    return heading;
}

inline void addSection(QVBoxLayout *layout, QWidget *parent, const QString &name)
{
    layout->addSpacing(19);
    auto *heading = new QLabel(name, parent);
    auto font = heading->font();
    font.setBold(true);
    font.setPointSize(font.pointSize() + 2);
    heading->setFont(font);
    layout->addWidget(heading);
    auto *rule = new QFrame(parent);
    rule->setFrameShape(QFrame::HLine);
    rule->setFrameShadow(QFrame::Plain);
    layout->addWidget(rule);
}

inline ActionRow *addAction(QVBoxLayout *layout, QWidget *parent,
                            const QString &name, const QString &detail,
                            const QString &iconName)
{
    auto *action = new ActionRow(name, detail, iconName, parent);
    layout->addWidget(action);
    return action;
}
}
