#include "mainwindow.h"
#include <cstdio>
#include <QApplication>
#include <QTranslator>
#include <QLibraryInfo>
#include <QDebug>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QTranslator translator;
    if (translator.load("mainwindow_zh"))
    {
        qDebug() << "custom translator ok";
        a.installTranslator(&translator);
    }

    QTranslator qtTranslator;
    if (qtTranslator.load(QLocale::system(),
                "qt", "_",
                QLibraryInfo::location(QLibraryInfo::TranslationsPath)))
    {
        qDebug() << "qtTranslator ok";
        a.installTranslator(&qtTranslator);
    }

    QTranslator qtBaseTranslator;
    if (qtBaseTranslator.load("qtbase_" + QLocale::system().name(),
                QLibraryInfo::location(QLibraryInfo::TranslationsPath)))
    {
        qDebug() << "qtBaseTranslator ok";
        a.installTranslator(&qtBaseTranslator);
    }


    MainWindow::Mode m = MainWindow::ALL;
    QStringList files;

    //./OneTimeEncryptor [enc|dec|all] file1 file2...
    if (argc > 1)
    {
        QString arg = argv[1];
        if (arg == "enc")
            m = MainWindow::ENCRYPTION;
        else if (arg == "dec")
            m = MainWindow::DECRYPTION;
        else
        {
            printf("Usage: OneTimeEncryptor [enc|dec] file1 file2...");
            return -1;
        }

        //Get file(s)
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
