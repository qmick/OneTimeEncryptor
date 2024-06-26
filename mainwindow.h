#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QTime>
#include <QLabel>
#include <memory>
#include "secure_memory.h"
#include "encryption_dialog.h"

namespace Ui {
class MainWindow;
}

class Encryptor;
class Decryptor;
class CryptThread;
class MsgCryptor;
class ProgressDelegate;
class ProgressTableModel;
class UserManager;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    enum Mode { ENCRYPTION, DECRYPTION, ALL };
    enum KeyType { ECC, RSA };

    static const QStringList kSupportedCipher;
    /**
     * @brief MainWindow
     * @param mode Mode of opening, could be [ENCRYPTION|DECRYPTION|ALL]
     * @param files Files to be processed
     * @param parent
     */
    MainWindow(const Mode &mode, const QStringList &files, QWidget *parent = 0);

    ~MainWindow();

private:
    std::unique_ptr<Ui::MainWindow> ui;

    //Path to public and private key pem file
    QString public_path;
    QString private_path;

    std::shared_ptr<Encryptor> encryptor;
    std::shared_ptr<Decryptor> decryptor;
    std::unique_ptr<CryptThread> crypt_thread;
    std::unique_ptr<MsgCryptor> msg_cryptor;
    std::unique_ptr<UserManager> user_manager;
    QTimer timer;
    QTime time_record;
    int count;
    bool auto_close;

    //UI
    std::unique_ptr<ProgressDelegate> progress_delegate;
    std::unique_ptr<ProgressTableModel> progress_model;
    EncryptionDialog encrypt_dialog;
    QLabel public_label;
    QLabel private_label;

    //Find place of file progress by its name
    QHash<QString, int> file_no;

    //
    QString current_cipher;

    //
    bool auto_delete;

    void setup_progress(const QStringList &files);

    bool load_publickey(const QString &pubkey);
    bool load_privatekey(const QString &private_key, SecureBuffer &password);

    /**
     * @brief setup_thread Setup working thread for encryption or decryption
     */
    void setup_thread();

    void generate_keypair(KeyType type);

public slots:
    //load public and private key from pem file
    bool load_publickey_clicked();
    bool load_privatekey_clicked();

    void add_user();
    void switch_user();
    void delete_user();

    //
    void cipher_changed(const QString &cipher);

    //
    void update_digest(int index);

    //Auto delete file
    void auto_delete_checked(int state);

    //Reset password that used to encrypt private key
    void reset_password();

    //Update UI timer
    void update_time();

    //Generate private key and corresponding publick key and save them to pem file
    void generate_ecckey_clicked();
    void generate_rsakey_clicked();

    //Encrypt or decrypt file(s)
    void encrypt_clicked();
    void decrypt_clicked();

#ifdef Q_OS_WIN
    //
    void on_register_clicked();
    void on_unregister_clicked();
#endif

    //
    void encrypt_msg_clicked();
    void decrypt_msg_clicked();

    //
    void encrypt_msg(const QString &msg);
    void decrypt_msg(const QString &cipher);

    //Get filename that being processed currently
    void current_file(const QString &filename, const qint64 filesize);

    //Get file that fail to encrypt/decrypt and reason
    void file_failed(const QString &file, const QString &reason);

    //Encryption/Decryption is stopped manually
    void file_stopped(const QString &file);

    //Get asymmetric encryption/decryption progress
    void current_progress(const QString &file, int progress);

    //Current finished file
    void current_finished(const QString &file);

    //All file(s) are processed
    void job_finished();

    //Stop encryption/decryption job(s)
    void stop_job();

    //On exit
    void on_exit();
};

#endif // MAINWINDOW_H
