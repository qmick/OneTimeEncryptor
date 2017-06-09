#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QTime>
#include <memory>

namespace Ui {
class MainWindow;
}

class Encryptor;
class Decryptor;
class CryptThread;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    enum Mode { ENCRYPTION, DECRYPTION, ALL };

    /**
     * @brief MainWindow
     * @param mode Mode of opening, could be [ENCRYPTION|DECRYPTION|ALL]
     * @param files Files to be processed
     * @param parent
     */
    MainWindow(const Mode &mode, const QStringList &files, QWidget *parent = 0);

    ~MainWindow();

private:
    Ui::MainWindow *ui;

    //Path to public and private key pem file
    QString public_path;
    QString private_path;

    std::shared_ptr<Encryptor> encryptor;
    std::shared_ptr<Decryptor> decryptor;
    std::shared_ptr<CryptThread> crypt_thread;
    QTimer timer;
    QTime time_record;
    int count;

    /**
     * @brief setup_thread Setup working thread for encryption or decryption
     */
    void setup_thread();



public slots:
    //load public and private key from pem file
    void load_publickey();
    void load_privatekey();

    //Update UI timer
    void update_time();

    //Generate private key and corresponding publick key and save them to pem file
    void generate_key_clicked();

    //Encrypt or decrypt file(s)
    void encrypt_clicked();
    void decrypt_clicked();

    //Get filename that being processed currently
    void current_file(const QString &s);

    //Get file that fail to encrypt/decrypt and reason
    void file_failed(const QString &file, const QString &reason);

    //Get asymmetric encryption/decryption progress
    void current_progress(int progress);

    //All file(s) are processed
    void job_finished();

    //Stop encryption/decryption job(s)
    void stop_job();
};

#endif // MAINWINDOW_H
