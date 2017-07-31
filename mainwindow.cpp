#include "crypt_thread.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "progress_delegate.h"
#include "progress_tablemodel.h"
#include "asymmetric_cryptor.h"

#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QTime>
#include <QDebug>


using std::make_unique;
using std::make_shared;
using std::exception;
using std::string;


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

const QStringList MainWindow::kSupportedCipher = { "AES-128/CBC", "AES-256/CBC",
                                                   "AES-128/CTR", "AES-256/CTR",
                                                   "AES-128/GCM", "AES-256/GCM",
                                                   "AES-128/OCB", "AES-256/OCB" };


MainWindow::MainWindow(const Mode &mode, const QStringList &files, QWidget *parent)
    : QMainWindow(parent), ui(make_unique<Ui::MainWindow>()),
      progress_delegate(make_unique<ProgressDelegate>()),
      progress_model(make_unique<ProgressTableModel>())
{
    crypt_thread = make_unique<CryptThread>(files);
    cryptor = make_unique<AsymmetricCryptor>();
    crypt_thread->set_cryptor(cryptor);
    public_path = "./public.pem";
    private_path = "./private.pem";
    auto_close = false;

    //Setup UI
    ui->setupUi(this);
    this->setWindowTitle(tr("OneTimeEncryptor"));
    public_label.setText(tr("Public key not loaded"));
    private_label.setText(tr("Private key not loaded"));
    ui->statusBar->addWidget(&public_label);
    ui->statusBar->addWidget(&private_label);
    ui->tableView->setModel(progress_model.get());
    ui->tableView->setItemDelegate(progress_delegate.get());
    emit progress_model->layoutChanged();

    connect(&timer,                     SIGNAL(timeout()),   this, SLOT(update_time()));
    connect(ui->actionECC,              SIGNAL(triggered()), this, SLOT(generate_ecckey_clicked()));
    connect(ui->actionRSA,              SIGNAL(triggered()), this, SLOT(generate_rsakey_clicked()));
    connect(ui->action_Encrypt,         SIGNAL(triggered()), this, SLOT(encrypt_clicked()));
    connect(ui->action_Decrypt,         SIGNAL(triggered()), this, SLOT(decrypt_clicked()));
    connect(ui->stop_button,            SIGNAL(clicked()),   this, SLOT(stop_job()));
    connect(ui->actionLoad_private_key, SIGNAL(triggered()), this, SLOT(load_privatekey_clicked()));
    connect(ui->actionLoad_public_key,  SIGNAL(triggered()), this, SLOT(load_publickey_clicked()));
    connect(ui->actionE_xit,            SIGNAL(triggered()), this, SLOT(on_exit()));
    connect(ui->action_Reset_password,  SIGNAL(triggered()), this, SLOT(reset_password()));
    connect(ui->comboBox,               SIGNAL(currentTextChanged(QString)),
            this, SLOT(cipher_changed(const QString&)));

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

    ui->comboBox->addItems(kSupportedCipher);
    ui->actionRSA->setDisabled(true);

    switch (mode)
    {
    //Open for encryption
    case ENCRYPTION:
        //If command line args contains filenames, encrypt them automatically
        if (!files.isEmpty())
        {
            load_publickey_clicked();
            setup_progress(files);
            setup_thread();
            auto_close = true;
        }
        break;

    //Open for decryption
    case DECRYPTION:
        //If command line args contains filenames, decrypt them automatically
        if (!files.isEmpty())
        {
            load_privatekey_clicked();
            setup_progress(files);
            setup_thread();
            auto_close = true;
        }
        break;

    //Open for both
    case ALL:
        load_publickey_clicked();
        load_privatekey_clicked();
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

void MainWindow::generate_keypair(MainWindow::KeyType)
{
    bool ok;
    QString password = QInputDialog::getText(this, tr("Input password"),
                                         tr("Password:"), QLineEdit::Password,
                                         QDir::home().dirName(), &ok);

    if (ok && !password.isEmpty())
    {
        try
        {
            cryptor->gen_key();
            auto kp = cryptor->get_key(password.toStdString());

            if (!write_key(kp.public_key, public_path) ||
                !write_key(kp.private_key, private_path))
                return;
            cryptor->load_public_key(public_path.toStdString());
            cryptor->load_private_key(private_path.toStdString(), password.toStdString());
            public_label.setText(tr("Public key ready"));
            private_label.setText(tr("Private key ready"));
        }
        catch (exception &e)
        {
            //Remove generated files
            remove(public_path.toLocal8Bit().data());
            remove(private_path.toLocal8Bit().data());

            QMessageBox::critical(this, tr("Error"),
                                  tr("Cannot generate key: ") + e.what(),
                                  QMessageBox::Abort);
            return;
        }
    }
}

bool MainWindow::write_key(const string &pubkey, const QString &path)
{
    QFile public_file(path);
    if (public_file.exists())
    {
        auto result = QMessageBox::warning(this, tr("Warning"),
                                           tr("Going to cover old key, continue?"),
                                           QMessageBox::Yes | QMessageBox::No);
        if (result == QMessageBox::No)
            return false;
    }

    if (!public_file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(this, tr("Warning"), tr("Cannot write key"),
                             QMessageBox::Ok);
        return false;
    }

    if (public_file.write(pubkey.c_str()) != pubkey.size())
    {
        public_file.close();
        public_file.remove();
        return false;
    }
    return true;
}

void MainWindow::load_publickey_clicked()
{
    try
    {
        cryptor->load_public_key(string(public_path.toLocal8Bit().data()));
        public_label.setText(tr("Public key ready"));
    } catch (...)
    {
        public_label.setText(tr("Public key not loaded"));
    }
}

void MainWindow::load_privatekey_clicked()
{
    QFile file(private_path);
    if (!file.exists())
    {
        private_label.setText(tr("Private key not loaded"));
        return;
    }

    bool ok;
    QString password = QInputDialog::getText(this, tr("Input password"),
                                         tr("Password:"), QLineEdit::Password,
                                         QDir::home().dirName(), &ok);
    try
    {
        cryptor->load_private_key(string(private_path.toLocal8Bit().data()),
                                  password.toStdString());
        private_label.setText(tr("Private key ready"));
    } catch (...)
    {
        private_label.setText(tr("Private key not loaded"));
    }
}

void MainWindow::cipher_changed(const QString &cipher)
{
    crypt_thread->set_cipher(cipher);
}

void MainWindow::reset_password()
{
    if (!cryptor->has_prikey())
    {
        QMessageBox::critical(this, tr("Error"),
                              tr("Cannot reset password: private key not loaded"),
                              QMessageBox::Abort);
        return;
    }

    bool ok;
    QString password = QInputDialog::getText(this, tr("Input password"),
                                         tr("Password:"), QLineEdit::Password,
                                         QDir::home().dirName(), &ok);

    try
    {
        auto kp = cryptor->get_key(password.toStdString());
        write_key(kp.private_key, private_path);
    }
    catch (const exception &e)
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
    if (!cryptor->has_pubkey())
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
        crypt_thread->set_files(files);
        crypt_thread->set_mode(CryptThread::ENCRYPTION);
        setup_progress(files);
        setup_thread();
    }
}

void MainWindow::decrypt_clicked()
{
    if (!cryptor->has_prikey())
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
        crypt_thread->set_files(files);
        crypt_thread->set_mode(CryptThread::DECRYPTION);
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
//    ui->actionRSA->setDisabled(false);
}

void MainWindow::stop_job()
{
    crypt_thread->stop();
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
