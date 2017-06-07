#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <openssl/err.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ERR_load_crypto_strings();
}

MainWindow::~MainWindow()
{
    delete ui;

    ERR_free_strings();
}
