#pragma once
#include <QWidget>
class ToolRunner;
class QVBoxLayout;

class SoftwarePage : public QWidget {
    Q_OBJECT
public:
    explicit SoftwarePage(ToolRunner *tools, QWidget *parent = nullptr);
    void showDesktopSettings();
    QVBoxLayout *desktopLayout() const { return desktopLayout_; }

private:
    QVBoxLayout *desktopLayout_ = nullptr;
};
