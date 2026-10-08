#pragma once
#include "desktop/Catdot.h"
#include <QWidget>

class QTreeWidget;
class QLabel;
class QPushButton;
class ToolRunner;

class DesktopPage : public QWidget {
    Q_OBJECT
public:
    explicit DesktopPage(ToolRunner *tools, QWidget *parent = nullptr);
    void refresh();

private:
    CatdotClient *catdot_;
    QTreeWidget *profiles_;
    QLabel *status_;
    QPushButton *refresh_;
    QPushButton *preview_;
    void previewSelected();
};
