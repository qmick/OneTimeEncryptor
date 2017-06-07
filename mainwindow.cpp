#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

MainWindow::~MainWindow()
{
    delete ui;

    ERR_free_strings();
}
