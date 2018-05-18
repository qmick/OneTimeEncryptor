#include "encryptor.h"
#include "decryptor.h"
#include "crypt_thread.h"
#include "msg_cryptor.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "key_tool.h"
#include "crypto_exception.h"
#include "progress_delegate.h"
#include "progress_tablemodel.h"
#include "user_manager.h"

#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QTime>
#include <QDebug>
#include <QDialogButtonBox>


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

const QStringList MainWindow::kSupportedCipher = { "AES-128-CBC", "AES-128-CTR",
                                                   "AES-192-CBC", "AES-192-CTR",
                                                   "AES-256-CBC", "AES-256-CTR",
                                                   "ChaCha20" };


MainWindow::MainWindow(const Mode &mode, const QStringList &files, QWidget *parent)
    : QMainWindow(parent), ui(make_unique<Ui::MainWindow>()),
      progress_delegate(make_unique<ProgressDelegate>()),
      progress_model(make_unique<ProgressTableModel>())
{
    ui->setupUi(this);
    this->setWindowTitle(tr("OneTimeEncryptor"));

    public_label.setText("");
    private_label.setText(tr(""));
    ui->statusBar->addWidget(&public_label);
    ui->statusBar->addWidget(&private_label);

    ui->tableView->setModel(progress_model.get());
    ui->tableView->setItemDelegate(progress_delegate.get());
    emit progress_model->layoutChanged();

    user_manager = make_unique<UserManager>("./user.db");
    //public_path = "./public.pem";
    //private_path = "./private.pem";
    auto_close = false;

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
    connect(ui->action_encrypt_msg, SIGNAL(triggered()), this, SLOT(encrypt_msg_clicked()));
    connect(ui->action_decrypt_msg, SIGNAL(triggered()), this, SLOT(decrypt_msg_clicked()));
    connect(&encrypt_dialog, SIGNAL(encrypt(const QString &)), this, SLOT(encrypt_msg(const QString &)));
    connect(&encrypt_dialog, SIGNAL(decrypt(const QString &)), this, SLOT(decrypt_msg(const QString &)));
    connect(ui->action_Add, SIGNAL(triggered()), this, SLOT(add_user()));
    connect(ui->action_Switch, SIGNAL(triggered()), this, SLOT(switch_user()));
    connect(ui->action_Delete, SIGNAL(triggered()), this, SLOT(delete_user()));
    connect(ui->user_comboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(update_digest(int)));

    ui->comboBox->addItems(kSupportedCipher);

    QMap<QString, QString> user_digest = user_manager->get_user_digest();
    if (user_digest.size() != 0)
        user_manager->set_current_user(user_digest.begin().key());
    for (auto i = user_digest.constBegin(); i != user_digest.constEnd(); ++i)
        ui->user_comboBox->addItem(i.key(), i.value());


    switch (mode)
    {
    //Open for encryption
    case ENCRYPTION:
        if (!load_publickey_clicked())
            return;

        //If command line args contains filenames, encrypt them automatically
        if (!files.isEmpty())
        {
            crypt_thread = std::make_unique<CryptThread>(encryptor, files);
            setup_progress(files);
            setup_thread();
            auto_close = false;
        }
        break;

    //Open for decryption
    case DECRYPTION:
        if (!load_privatekey_clicked())
            return;

        //If command line args contains filenames, decrypt them automatically
        if (!files.isEmpty())
        {
            crypt_thread = std::make_unique<CryptThread>(decryptor, files);
            setup_progress(files);
            setup_thread();
            auto_close = false;
        }
        break;

    //Open for both
    case ALL:
        if (load_publickey_clicked())
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
    ui->action_Add->setDisabled(true);
    ui->action_Switch->setDisabled(true);

    //Setup timer
    timer.start(1000);
    time_record.setHMS(0, 0, 0);
    ui->time_label->setText(time_record.toString());

    //Initialize processed file(s) counter
    count = 0;

    crypt_thread->cipher = current_cipher;
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
                key_pair = KeyTool::get_key_pair();
                break;
            case RSA:
                key_pair = KeyTool::get_rsa_key_pair();
                break;
            }

            QString pubkey = QString::fromStdString(KeyTool::get_pubkey_pem(key_pair));
            QString private_key = QString::fromStdString(KeyTool::get_private_key_pem(key_pair, password));

            user_manager->set_key(pubkey, private_key);

            load_publickey(pubkey);
            load_privatekey(private_key, password);
        }
        catch (std::exception &e)
        {
            QMessageBox::critical(this, tr("Error"),
                                  tr("Cannot generate key: ") + e.what(),
                                  QMessageBox::Abort);
            return;
        }
    }
}


bool MainWindow::load_publickey_clicked()
{
    // No user
    if (ui->user_comboBox->count() == 0)
    {
        QMessageBox::critical(this, tr("Error"), tr("No user available"),
                              QMessageBox::Ok);
        public_label.setText("");
        return false;
    }
    return load_publickey(user_manager->get_pubkey());
}

bool MainWindow::load_privatekey_clicked()
{
    if (ui->user_comboBox->count() == 0)
    {
        QMessageBox::critical(this, tr("Error"), tr("No user available"),
                              QMessageBox::Ok);
        private_label.setText("");
        return false;
    }

    bool ok;

    QString text = QInputDialog::getText(this, tr("Input password"),
                                         tr("Password:"), QLineEdit::Password,
                                         QDir::home().dirName(), &ok);

    SecureBuffer password(text.toStdString());
    return load_privatekey(user_manager->get_private_key(), password);
}

void MainWindow::add_user()
{
    QDialog dialog(this);
    // Use a layout allowing to have a label next to each field
    QFormLayout form(&dialog);

    // Add some text above the fields
    form.addRow(new QLabel(tr("Please input:")));

    // Add the lineEdits with their respective labels
    QLineEdit username_edit(&dialog);
    form.addRow(tr("Username:"), &username_edit);
    QLineEdit password_edit(&dialog);
    password_edit.setEchoMode(QLineEdit::Password);
    form.addRow(tr("Password:"), &password_edit);
    QComboBox key_box(&dialog);
    key_box.addItems({"ECC", "RSA"});
    form.addRow(tr("Key type:"), &key_box);

    // Add some standard buttons (Cancel/Ok) at the bottom of the dialog
    QDialogButtonBox buttonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                               Qt::Horizontal, &dialog);
    form.addRow(&buttonBox);
    QObject::connect(&buttonBox, SIGNAL(accepted()), &dialog, SLOT(accept()));
    QObject::connect(&buttonBox, SIGNAL(rejected()), &dialog, SLOT(reject()));

    // Show the dialog as modal
    if (dialog.exec() == QDialog::Accepted)
    {
        User user;
        user.name = username_edit.text();
        EVP_PKEY_ptr key_pair = KeyTool::get_key_pair(key_box.currentText().toStdString());
        user.pubkey = QString::fromStdString(KeyTool::get_pubkey_pem(key_pair));
        SecureBuffer password(password_edit.text().toStdString());
        user.private_key = QString::fromStdString(KeyTool::get_private_key_pem(key_pair, password));
        std::vector<byte> digest = KeyTool::get_digest(user.pubkey.toStdString(), "SHA256");
        user.digest = QString::fromUtf8(QByteArray::fromRawData(reinterpret_cast<const char*>(digest.data()),
                                                                digest.size()).toHex());
        user_manager->add_user(user);
        ui->user_comboBox->addItem(user.name, user.digest);
        ui->user_comboBox->setCurrentText(user.name);
        switch_user();
    }
}

void MainWindow::switch_user()
{
    if (ui->user_comboBox->count() == 0)
    {
        QMessageBox::critical(this, tr("Error"), tr("No user available"),
                              QMessageBox::Ok);
        return;
    }

    user_manager->set_current_user(ui->user_comboBox->currentText());
    if (!load_publickey_clicked())
        return;
    if (!load_privatekey_clicked())
        return;
    QMessageBox::information(this, tr("Information"),
                             tr("Successfully switched to ") +
                             user_manager->get_current_user(),
                             QMessageBox::Ok);
}

void MainWindow::delete_user()
{
    QString username = user_manager->get_current_user();
    if (username.isEmpty())
        return;
    user_manager->get_private_key();

}

void MainWindow::cipher_changed(const QString &cipher)
{
    current_cipher = cipher;
}

void MainWindow::update_digest(int index)
{
    QString digest = ui->user_comboBox->itemData(index).toString();
    ui->digest_label->setText(digest.toUpper());
}

bool MainWindow::load_publickey(const QString &pubkey)
{
    try
    {
        encryptor = std::make_shared<Encryptor>(pubkey.toStdString());

        //Get public key type
        EVP_PKEY_ptr key = encryptor->get_key();
        switch (EVP_PKEY_id(key.get()))
        {
        case EVP_PKEY_RSA:
            public_label.setText(tr("RSA public key loaded"));
            break;

        case EVP_PKEY_EC:
        case NID_X25519:
            public_label.setText(tr("EC public key loaded"));
            break;

        default:
            encryptor = nullptr;
            QMessageBox::critical(this, "Error", tr("Unsupported Key type"), QMessageBox::Abort);
            return false;
        }
        if (!msg_cryptor)
            msg_cryptor = make_unique<MsgCryptor>();
        msg_cryptor->set_pubkey(key);
        return true;
    }
    catch (const std::exception &e)
    {
        QMessageBox::warning(this, "Warning",
                             tr("Cannot load public key: ") + e.what(),
                             QMessageBox::Abort);
        public_label.setText("");
    }

    return false;
}

bool MainWindow::load_privatekey(const QString &private_key, SecureBuffer &password)
{
    if (password.size() == 0)
    {
        private_label.setText("");
        return false;
    }

    try
    {
        decryptor = std::make_shared<Decryptor>(private_key.toStdString(), password);

        //Get private key type
        EVP_PKEY_ptr key = decryptor->get_key();
        switch (EVP_PKEY_id(key.get()))
        {
        case EVP_PKEY_RSA:
            private_label.setText(tr("RSA private key loaded"));
            break;

        case EVP_PKEY_EC:
        case NID_X25519:
            private_label.setText(tr("EC private key loaded"));
            break;

        default:
            decryptor = nullptr;
            QMessageBox::critical(this, "Error", tr("Unsupported Key type"), QMessageBox::Abort);
            return false;
        }
        if (!msg_cryptor)
            msg_cryptor = make_unique<MsgCryptor>();
        msg_cryptor->set_private_key(key);

        return true;
    }
    catch (const std::exception &e)
    {
        QMessageBox::warning(this, "Warning",
                             tr("cannot open private pem file: ") + e.what(),
                             QMessageBox::Abort);
        private_label.setText("");
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
    EVP_PKEY_ptr private_key = decryptor->get_key();

    try
    {
        std::string pem = KeyTool::get_private_key_pem(private_key, password);
        user_manager->set_private_key(QString::fromStdString(pem));
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

void MainWindow::encrypt_msg_clicked()
{
    encrypt_dialog.show();
}

void MainWindow::decrypt_msg_clicked()
{
    encrypt_dialog.show();
}

void MainWindow::encrypt_msg(const QString &msg)
{
    QByteArray qbytes = msg.toLocal8Bit();
    std::vector<byte> in(qbytes.begin(), qbytes.end());
    std::vector<byte> out;
    try
    {
        out = msg_cryptor->encrypt(in, current_cipher.toStdString());
    }
    catch (std::exception e)
    {
        QMessageBox::critical(this, "Error", e.what(), QMessageBox::Ok);
        return;
    }
    qbytes = QByteArray::fromRawData(reinterpret_cast<const char*>(out.data()), out.size());
    encrypt_dialog.set_text(qbytes.toBase64());
}

void MainWindow::decrypt_msg(const QString &cipher)
{
    QByteArray qbytes = QByteArray::fromBase64(cipher.toUtf8());
    std::vector<byte> in(qbytes.begin(), qbytes.end());
    std::vector<byte> out;
    try
    {
        out = msg_cryptor->decrypt(in);
    }
    catch (std::exception e)
    {
        QMessageBox::critical(this, "Error", e.what(), QMessageBox::Ok);
        return;
    }
    QString text = QString::fromLocal8Bit(reinterpret_cast<const char*>(out.data()), out.size());
    encrypt_dialog.set_text(text);
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
    ui->action_Add->setDisabled(false);
    ui->action_Switch->setDisabled(false);
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
