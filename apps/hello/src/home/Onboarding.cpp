#include "home/Onboarding.h"

OnboardingStore::OnboardingStore(const QString &fileName)
{
    if (fileName.isEmpty()) settings_ = std::make_unique<QSettings>();
    else settings_ = std::make_unique<QSettings>(fileName, QSettings::IniFormat);
}

bool OnboardingStore::dismissed() const
{
    return settings_->value(QStringLiteral("onboarding/dismissed"), false).toBool();
}

void OnboardingStore::setDismissed(bool dismissed)
{
    settings_->setValue(QStringLiteral("onboarding/dismissed"), dismissed);
}

bool OnboardingStore::skipped(const QString &step) const
{
    return settings_->value(QStringLiteral("onboarding/skipped/") + step, false).toBool();
}

bool OnboardingStore::markedDone(const QString &step) const
{
    return settings_->value(QStringLiteral("onboarding/done/") + step, false).toBool();
}

void OnboardingStore::setMarkedDone(const QString &step, bool done)
{
    settings_->setValue(QStringLiteral("onboarding/done/") + step, done);
    if (done) setSkipped(step, false);
}

void OnboardingStore::setSkipped(const QString &step, bool skipped)
{
    settings_->setValue(QStringLiteral("onboarding/skipped/") + step, skipped);
    if (skipped) settings_->setValue(QStringLiteral("onboarding/done/") + step, false);
}

void OnboardingStore::reset()
{
    settings_->remove(QStringLiteral("onboarding"));
}
