#include "mainwindow.h"
#include "test.h"
#include <QApplication>
#include "globals.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();


    //open_cmd();

    return a.exec();

}
