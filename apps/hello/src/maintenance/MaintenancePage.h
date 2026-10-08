#pragma once
#include <QWidget>
class ToolRunner;
class QVBoxLayout;
class ActionRow;

class MaintenancePage : public QWidget {
    Q_OBJECT
public:
    explicit MaintenancePage(ToolRunner *tools, QWidget *parent = nullptr);
    void showDrivers();

private:
    ToolRunner *tools_;
    ActionRow *driversAnchor_ = nullptr;
    ActionRow *addCommand(QVBoxLayout *layout, const QString &label, const QString &detail,
                          const QString &icon, const QString &title,
                          const QString &command, bool confirm = false);
};
