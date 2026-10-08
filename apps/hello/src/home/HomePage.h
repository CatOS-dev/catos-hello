#pragma once

#include "home/Environment.h"
#include "home/Onboarding.h"
#include <QWidget>
#include <QVector>

class QVBoxLayout;
class HomePage : public QWidget {
    Q_OBJECT
public:
    explicit HomePage(const Environment &environment, QWidget *parent = nullptr);

signals:
    void navigateTo(const QString &page);
    void actionRequested(const QString &action);

private:
    QWidget *guide_ = nullptr;
    QWidget *resume_ = nullptr;
    class QLabel *progress_ = nullptr;
    OnboardingStore onboarding_;
    QVector<QWidget *> stepRows_;
    void addStep(QVBoxLayout *layout, const QString &id, const QString &title,
                 const QString &detail, const QString &action, const QString &label);
    void refreshGuide();
};
