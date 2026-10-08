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

void OnboardingStore::setSkipped(const QString &step, bool skipped)
{
    settings_->setValue(QStringLiteral("onboarding/skipped/") + step, skipped);
}

void OnboardingStore::reset()
{
    settings_->remove(QStringLiteral("onboarding"));
}
