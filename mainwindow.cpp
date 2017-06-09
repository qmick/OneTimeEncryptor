#include "encryptor.h"
#include "decryptor.h"
#include "crypt_thread.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "key_generator.h"
#include "crypto_exception.h"

#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QTime>
#include <QDebug>


MainWindow::MainWindow(const Mode &mode, const QStringList &files, QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle(tr("OneTimeEnc"));
    ui->progressBar->setMinimum(0);
    ui->progressBar->setMaximum(1000);

    public_path = "./public.pem";
    private_path = "./private.pem";

    connect(&timer, SIGNAL(timeout()), this, SLOT(update_time()));
    connect(ui->action_Generate_Key, SIGNAL(triggered()), this, SLOT(generate_key_clicked()));
    connect(ui->action_Encrypt, SIGNAL(triggered()), this, SLOT(encrypt_clicked()));
    connect(ui->action_Decrypt, SIGNAL(triggered()), this, SLOT(decrypt_clicked()));
    connect(ui->stop_button, SIGNAL(clicked()), this, SLOT(stop_job()));
    connect(ui->actionLoad_private_key, SIGNAL(triggered()), this, SLOT(load_privatekey()));
    connect(ui->actionLoad_public_key, SIGNAL(triggered()), this, SLOT(load_publickey()));

    switch (mode)
    {
    case ENCRYPTION:
        load_publickey();
        if (!files.isEmpty())
        {
            crypt_thread = std::make_shared<CryptThread>(encryptor, files);
            setup_thread();
            ui->stop_button->setEnabled(true);
        }
        break;

    case DECRYPTION:
        load_privatekey();
        if (!files.isEmpty())
        {
            crypt_thread = std::make_shared<CryptThread>(decryptor, files);
            setup_thread();
            ui->stop_button->setEnabled(true);
        }
        break;

    case ALL:
        load_publickey();
        load_privatekey();
        break;
    }
}

MainWindow::~MainWindow()
{
    delete ui;

}

void MainWindow::setup_thread()
{
    connect(crypt_thread.get(), SIGNAL(current_file(const QString&)), this, SLOT(current_file(const QString&)));
    connect(crypt_thread.get(), SIGNAL(file_failed(const QString&, const QString&)),
            this, SLOT(file_failed(const QString&, const QString&)));
    connect(crypt_thread.get(), SIGNAL(current_progress(int)), this, SLOT(current_progress(int)));
    connect(crypt_thread.get(), SIGNAL(job_finished()), this, SLOT(job_finished()));
    crypt_thread->start();
    timer.start(1000);
    time_record.setHMS(0, 0, 0);
    ui->time_label->setText(time_record.toString());
    count = 0;
}

void MainWindow::load_publickey()
{
    QFileInfo check_pubfile(public_path);
    if (check_pubfile.exists() && check_pubfile.isFile())
    {
        try
        {
            encryptor = std::make_shared<Encryptor>(public_path.toStdString());
            ui->public_label->setText(tr("Public key loaded"));
        }
        catch (const std::exception &e)
        {
            QMessageBox::warning(this, "Warning",
                                 QString("cannot open public pem file: ") + e.what(),
                                 QMessageBox::Abort);
        }
    }
}

void MainWindow::load_privatekey()
{
    QFileInfo check_prifile(private_path);
    if (check_prifile.exists() && check_prifile.isFile())
    {
        bool ok;
        QString text = QInputDialog::getText(this, tr("Input password"),
                                             tr("Password:"), QLineEdit::Password,
                                             QDir::home().dirName(), &ok);
        try
        {
            SecureBuffer password = SecureBuffer(text.toStdString());
            decryptor = std::make_shared<Decryptor>(private_path.toStdString(), password);
            ui->private_label->setText(tr("Private key loaded"));
        }
        catch (const std::exception &e)
        {
            QMessageBox::warning(this, "Warning",
                                 QString("cannot open private pem file: ") + e.what(),
                                 QMessageBox::Abort);
        }
    }
}

void MainWindow::update_time()
{
    time_record = time_record.addSecs(1);
    ui->time_label->setText(time_record.toString("hh:mm:ss"));
}


void MainWindow::generate_key_clicked()
{
    bool ok;
    QString text = QInputDialog::getText(this, tr("Input password"),
                                         tr("Password:"), QLineEdit::Password,
                                         QDir::home().dirName(), &ok);
    SecureBuffer password = SecureBuffer(text.toStdString());

    if (ok && !text.isEmpty())
    {
        FILE *private_fp = NULL, *public_fp = NULL;

        if (fopen_s(&private_fp, private_path.toStdString().c_str(), "w") != 0)
        {
            char buf[256];
            if (0 != strerror_s(buf, 256, errno))
                qDebug()<<"system error";
            QMessageBox::critical(this, tr("Error"),
                                  tr("Cannot open private key file: ") + buf, QMessageBox::Abort);
            return;
        }

        if (fopen_s(&public_fp, public_path.toStdString().c_str(), "w") != 0)
        {
            fclose(private_fp);

            char buf[256];
            if (0 != strerror_s(buf, 256, errno))
                qDebug()<<"system error";
            QMessageBox::critical(this, tr("Error"),
                                  tr("Cannot open public key file: ") + buf, QMessageBox::Abort);
            return;
        }

        try
        {
            auto key_pair = KeyGenerator::get_key_pair();
            KeyGenerator::save_key_pair(public_fp, private_fp, key_pair, password);

            fclose(private_fp);
            private_fp = NULL;
            fclose(public_fp);
            public_fp = NULL;

            encryptor = std::make_shared<Encryptor>(public_path.toStdString());
            decryptor = std::make_shared<Decryptor>(private_path.toStdString(), password);
        }
        catch (std::exception &e)
        {
            if (private_fp)
                fclose(private_fp);
            if (public_fp)
                fclose(public_fp);
            remove(public_path.toStdString().c_str());
            remove(private_path.toStdString().c_str());
            QMessageBox::critical(this, tr("Error"),
                                  tr("Cannot generate key: ") + e.what(),
                                  QMessageBox::Abort);
            return;
        }

        ui->private_label->setText(tr("Private key loaded"));
        ui->public_label->setText(tr("Public key loaded"));
    }
}


void MainWindow::encrypt_clicked()
{
    if (!encryptor)
    {
        QMessageBox::critical(this, tr("Error"),
                              tr("Public key not loaded, cannot use encryptor"),
                              QMessageBox::Abort);
        return;
    }

    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::ExistingFiles);
    if (dialog.exec())
    {
        crypt_thread = std::make_shared<CryptThread>(encryptor, dialog.selectedFiles());
        setup_thread();
        ui->stop_button->setEnabled(true);
    }
}

void MainWindow::decrypt_clicked()
{
    if (!decryptor)
    {
        QMessageBox::critical(this, tr("Error"),
                              tr("Private key not loaded, cannot use decryptor"),
                              QMessageBox::Abort);
        return;
    }

    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::ExistingFiles);
    if (dialog.exec())
    {
        crypt_thread = std::make_shared<CryptThread>(decryptor, dialog.selectedFiles());
        setup_thread();
        ui->stop_button->setEnabled(true);
    }
}

void MainWindow::current_file(const QString &s)
{
    ui->reason_label->setText(tr("Total file(s) processed: ") + QString::number(count));
    count++;
    ui->filename_label->setText(s);
}

void MainWindow::file_failed(const QString &file, const QString &reason)
{
    count++;
    ui->filename_label->setText(file);
    ui->reason_label->setText(reason);
}

void MainWindow::current_progress(int progress)
{
    ui->progressBar->setValue(progress);
}

void MainWindow::job_finished()
{
    timer.stop();
    time_record.setHMS(0, 0, 0);
    ui->progressBar->setValue(0);
    ui->stop_button->setEnabled(false);
    ui->reason_label->setText(tr("Total file(s) processed: ") + QString::number(count));

}

void MainWindow::stop_job()
{
    timer.stop();
    time_record.setHMS(0, 0, 0);
    crypt_thread->should_stop = true;
    crypt_thread->wait();
    ui->reason_label->setText(tr("Total file(s) processed: ") + QString::number(count));
}
