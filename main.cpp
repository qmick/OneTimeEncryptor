#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow::Mode m = MainWindow::ALL;
    QStringList files;
    if (argc > 1)
    {
        QString arg = argv[1];
        if (arg == "enc")
            m = MainWindow::ENCRYPTION;
        else if (arg == "dec")
            m = MainWindow::DECRYPTION;
        else if (arg == "all")
            m = MainWindow::ALL;
        else
            return -1;

        if (argc > 2)
        {
            for (int i = 2; i < argc; i++)
                files.append(argv[i]);
        }
    }
    MainWindow w(m, files);
    w.show();

    return a.exec();
}
