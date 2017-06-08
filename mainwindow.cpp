#include "encryptor.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "key_generator.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <QFileDialog>
#include <QInputDialog>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->action_Generate_Key, SIGNAL(triggered()), this, SLOT(generate_key_clicked()));
    connect(ui->action_Encrypt, SIGNAL(triggered()), this, SLOT(encrypt_clicked()));
    connect(ui->action_Decrypt, SIGNAL(triggered()), this, SLOT(decrypt_clicked()));

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

void MainWindow::generate_key_clicked()
{
    bool ok;
    QString text = QInputDialog::getText(this, tr("Input password"),
                                         tr("Password:"), QLineEdit::Password,
                                         QDir::home().dirName(), &ok);
    if (ok && !text.isEmpty())
    {
        SecureBuffer password = SecureBuffer(text.toStdString());
        auto key_pair = KeyGenerator::get_key_pair();
        shared_ptr<FILE> private_fp, public_fp;
        FILE *tmp;
        if (fopen_s(&tmp, "./private.pem", "wb") != 0)
        {
            //TODO
        }
    }
}

void MainWindow::encrypt_clicked()
{
    QFileDialog dialog(this);
    QStringList file_names;
    if (dialog.exec())
        file_names = dialog.selectedFiles();
}

void MainWindow::decrypt_clicked()
{
    QFileDialog dialog(this);
    QStringList file_names;
    if (dialog.exec())
        file_names = dialog.selectedFiles();
}
