#pragma once
#include <QWidget>
class ToolRunner;
class QVBoxLayout;

class MaintenancePage : public QWidget {
    Q_OBJECT
public:
    explicit MaintenancePage(ToolRunner *tools, QWidget *parent = nullptr);
    void showDrivers();

private:
    ToolRunner *tools_;
    void addCommand(QVBoxLayout *layout, const QString &label, const QString &title,
                    const QString &command, bool confirm = false);
};
