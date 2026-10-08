#pragma once

#include <QSettings>
#include <QString>
#include <memory>

class OnboardingStore {
public:
    explicit OnboardingStore(const QString &fileName = {});
    bool dismissed() const;
    void setDismissed(bool dismissed);
    bool skipped(const QString &step) const;
    void setSkipped(const QString &step, bool skipped);
    void reset();

private:
    std::unique_ptr<QSettings> settings_;
};
