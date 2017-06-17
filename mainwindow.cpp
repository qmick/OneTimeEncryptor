#include "encryptor.h"
#include "decryptor.h"
#include "crypt_thread.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "key_generator.h"
#include "crypto_exception.h"
#include "progress_delegate.h"
#include "progress_tablemodel.h"

#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QTime>
#include <QDebug>


using std::make_unique;
using std::make_shared;

QString size_human(qint64 size)
{
    double num = size;
    QStringList list;
    list << "KB" << "MB" << "GB" << "TB";

    QStringListIterator i(list);
    QString unit("bytes");

    while(num >= 1024.0 && i.hasNext())
    {
        unit = i.next();
        num /= 1024.0;
    }
    return QString().setNum(num, 'f', 2)+" "+unit;
}

MainWindow::MainWindow(const Mode &mode, const QStringList &files, QWidget *parent)
    : QMainWindow(parent), ui(make_unique<Ui::MainWindow>()),
      progress_delegate(make_unique<ProgressDelegate>()),
      progress_model(make_unique<ProgressTableModel>())
{
    ui->setupUi(this);
    this->setWindowTitle(tr("OneTimeEncryptor"));

    public_label.setText(tr("Public key not loaded"));
    private_label.setText(tr("Private key not loaded"));
    ui->statusBar->addWidget(&public_label);
    ui->statusBar->addWidget(&private_label);

    ui->tableView->setModel(progress_model.get());
    ui->tableView->setItemDelegate(progress_delegate.get());
    emit progress_model->layoutChanged();

    public_path = "./public.pem";
    private_path = "./private.pem";
    auto_close = false;

    connect(&timer,                     SIGNAL(timeout()),   this, SLOT(update_time()));
    connect(ui->actionECC,              SIGNAL(triggered()), this, SLOT(generate_ecckey_clicked()));
    connect(ui->actionRSA,              SIGNAL(triggered()), this, SLOT(generate_rsakey_clicked()));
    connect(ui->action_Encrypt,         SIGNAL(triggered()), this, SLOT(encrypt_clicked()));
    connect(ui->action_Decrypt,         SIGNAL(triggered()), this, SLOT(decrypt_clicked()));
    connect(ui->stop_button,            SIGNAL(clicked()),   this, SLOT(stop_job()));
    connect(ui->actionLoad_private_key, SIGNAL(triggered()), this, SLOT(load_privatekey()));
    connect(ui->actionLoad_public_key,  SIGNAL(triggered()), this, SLOT(load_publickey()));
    connect(ui->actionE_xit,            SIGNAL(triggered()), this, SLOT(on_exit()));
    connect(ui->action_Reset_password,  SIGNAL(triggered()), this, SLOT(reset_password()));

    switch (mode)
    {
    //Open for encryption
    case ENCRYPTION:
        if (!load_publickey())
            return;

        //If command line args contains filenames, encrypt them automatically
        if (!files.isEmpty())
        {
            crypt_thread = std::make_unique<CryptThread>(encryptor, files);
            setup_progress(files);
            setup_thread();
            auto_close = true;
        }
        break;

    //Open for decryption
    case DECRYPTION:
        if (!load_privatekey())
            return;

        //If command line args contains filenames, decrypt them automatically
        if (!files.isEmpty())
        {
            crypt_thread = std::make_unique<CryptThread>(decryptor, files);
            setup_progress(files);
            setup_thread();
            auto_close = true;
        }
        break;

    //Open for both
    case ALL:
        load_publickey();
        load_privatekey();
        break;
    }
}

MainWindow::~MainWindow()
{
}

void MainWindow::setup_progress(const QStringList &files)
{
    //Clear previous data
    progress_model->mdata.clear();
    file_no.clear();

    //Add data to table model
    for (auto  i = 0; i < files.size(); i++)
    {
        QFileInfo f(files[i]);
        QStringList line({ files[i], tr("Pending"), size_human(0),
                           QString::number(0), QString()});
        progress_model->mdata.append(line);
        file_no[files[i]] = i;
    }

    emit progress_model->layoutChanged();
    ui->stop_button->setEnabled(true);
}

void MainWindow::setup_thread()
{
    connect(crypt_thread.get(), SIGNAL(current_file(const QString&, const qint64)),
            this, SLOT(current_file(const QString&, const qint64)));
    connect(crypt_thread.get(), SIGNAL(file_failed(const QString&, const QString&)),
            this, SLOT(file_failed(const QString&, const QString&)));
    connect(crypt_thread.get(), SIGNAL(current_progress(const QString &, int)),
            this, SLOT(current_progress(const QString &, int)));
    connect(crypt_thread.get(), SIGNAL(job_finished()), this, SLOT(job_finished()));
    connect(crypt_thread.get(), SIGNAL(current_finished(const QString &)),
            this, SLOT(current_finished(const QString &)));
    connect(crypt_thread.get(), SIGNAL(file_stopped(const QString &)),
            this, SLOT(file_stopped(const QString &)));

    //Disable other operation
    ui->actionLoad_private_key->setDisabled(true);
    ui->actionLoad_public_key->setDisabled(true);
    ui->action_Decrypt->setDisabled(true);
    ui->action_Encrypt->setDisabled(true);
    ui->actionECC->setDisabled(true);
    ui->actionRSA->setDisabled(true);

    //Setup timer
    timer.start(1000);
    time_record.setHMS(0, 0, 0);
    ui->time_label->setText(time_record.toString());

    //Initialize processed file(s) counter
    count = 0;

    crypt_thread->start();
}

void MainWindow::generate_keypair(MainWindow::KeyType type)
{
    bool ok;
    QString text = QInputDialog::getText(this, tr("Input password"),
                                         tr("Password:"), QLineEdit::Password,
                                         QDir::home().dirName(), &ok);
    SecureBuffer password = SecureBuffer(text.toStdString());

    if (ok && !text.isEmpty())
    {
        try
        {
            EVP_PKEY_ptr key_pair;
            switch (type)
            {
            case ECC:
                key_pair = KeyGenerator::get_key_pair();
                break;
            case RSA:
                key_pair = KeyGenerator::get_rsa_key_pair();
                break;
            }

            KeyGenerator::save_private_key(private_path.toStdString(), key_pair, password);
            KeyGenerator::save_public_key(public_path.toStdString(), key_pair);

            encryptor = std::make_unique<Encryptor>(public_path.toStdString());
            decryptor = std::make_unique<Decryptor>(private_path.toStdString(), password);
        }
        catch (std::exception &e)
        {
            //Remove generated files
            remove(public_path.toStdString().c_str());
            remove(private_path.toStdString().c_str());

            QMessageBox::critical(this, tr("Error"),
                                  tr("Cannot generate key: ") + e.what(),
                                  QMessageBox::Abort);
            return;
        }

        //Update UI
        private_label.setText(tr("Private key loaded"));
        public_label.setText(tr("Public key loaded"));
    }
}

bool MainWindow::load_publickey()
{
    QFileInfo check_pubfile(public_path);
    if (check_pubfile.exists() && check_pubfile.isFile())
    {
        try
        {
            encryptor = std::make_shared<Encryptor>(public_path.toStdString());
            public_label.setText(tr("Public key loaded"));
            return true;
        }
        catch (const std::exception &e)
        {
            QMessageBox::warning(this, "Warning",
                                 QString("cannot open public pem file: ") + e.what(),
                                 QMessageBox::Abort);
        }
    }

    return false;
}

bool MainWindow::load_privatekey()
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
            private_label.setText(tr("Private key loaded"));
            return true;
        }
        catch (const std::exception &e)
        {
            QMessageBox::warning(this, "Warning",
                                 QString("cannot open private pem file: ") + e.what(),
                                 QMessageBox::Abort);
        }
    }

    return false;
}

void MainWindow::reset_password()
{
    if (!decryptor)
    {
        QMessageBox::critical(this, tr("Error"),
                              tr("Cannot reset password: private key not loaded"),
                              QMessageBox::Abort);
        return;
    }

    bool ok;
    QString text = QInputDialog::getText(this, tr("Input password"),
                                         tr("Password:"), QLineEdit::Password,
                                         QDir::home().dirName(), &ok);
    SecureBuffer password = SecureBuffer(text.toStdString());
    auto private_key = decryptor->get_key();

    try
    {
        KeyGenerator::save_private_key(private_path.toStdString(), private_key, password);
    }
    catch (const std::exception &e)
    {
        QMessageBox::critical(this, tr("Error"),
                              tr("Cannot reset password: ") + e.what(),
                              QMessageBox::Abort);
    }
}

void MainWindow::update_time()
{
    time_record = time_record.addSecs(1);
    ui->time_label->setText(time_record.toString("hh:mm:ss"));
}

void MainWindow::generate_ecckey_clicked()
{
    generate_keypair(ECC);
}

void MainWindow::generate_rsakey_clicked()
{
    generate_keypair(RSA);
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
        auto files = dialog.selectedFiles();
        crypt_thread = std::make_unique<CryptThread>(encryptor, files);

        setup_progress(files);
        setup_thread();
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
        auto files = dialog.selectedFiles();

        crypt_thread = std::make_unique<CryptThread>(decryptor, files);

        setup_progress(files);
        setup_thread(); 
    }
}

void MainWindow::current_file(const QString &filename, const qint64 filesize)
{
    auto no = file_no[filename];
    count++;
    progress_model->mdata[no][ProgressTableModel::ROW_STATUS] = tr("Processing");
    progress_model->mdata[no][ProgressTableModel::ROW_SIZE] = ::size_human(filesize);
    emit progress_model->layoutChanged();
}

void MainWindow::file_failed(const QString &file, const QString &reason)
{
    auto no = file_no[file];
    count++;
    progress_model->mdata[no][ProgressTableModel::ROW_STATUS] = tr("Failed");
    progress_model->mdata[no][ProgressTableModel::ROW_REASON] = reason;
    emit progress_model->layoutChanged();
}

void MainWindow::file_stopped(const QString &file)
{
    auto no = file_no[file];

    timer.stop();
    time_record.setHMS(0, 0, 0);

    progress_model->mdata[no][ProgressTableModel::ROW_STATUS] = tr("Stopped");
    emit progress_model->layoutChanged();
}

void MainWindow::current_progress(const QString &file, int progress)
{
    auto no = file_no[file];
    progress_model->mdata[no][ProgressTableModel::ROW_PROGRESS] = QString::number(progress);
    emit progress_model->layoutChanged();
}

void MainWindow::current_finished(const QString &file)
{
    auto no = file_no[file];
    progress_model->mdata[no][ProgressTableModel::ROW_STATUS] = tr("Finished");
    progress_model->mdata[no][ProgressTableModel::ROW_PROGRESS] = QString::number(100);
    emit progress_model->layoutChanged();
}

void MainWindow::job_finished()
{
    timer.stop();
    time_record.setHMS(0, 0, 0);
    ui->stop_button->setEnabled(false);
    if (auto_close)
        this->close();

    ui->actionLoad_private_key->setDisabled(false);
    ui->actionLoad_public_key->setDisabled(false);
    ui->action_Decrypt->setDisabled(false);
    ui->action_Encrypt->setDisabled(false);
    ui->actionECC->setDisabled(false);
    ui->actionRSA->setDisabled(false);
}

void MainWindow::stop_job()
{
    crypt_thread->should_stop = true;
}

void MainWindow::on_exit()
{
    if (crypt_thread)
    {
        stop_job();
        crypt_thread->wait(1000);
    }
    this->close();
}
