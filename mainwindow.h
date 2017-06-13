#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QTime>
#include <QLabel>
#include <memory>

namespace Ui {
class MainWindow;
}

class Encryptor;
class Decryptor;
class CryptThread;
class ProgressDelegate;
class ProgressTableModel;

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
    bool auto_close;

    //UI
    ProgressDelegate *progress_delegate;
    ProgressTableModel *progress_model;
    QLabel *public_label;
    QLabel *private_label;

    //Find place of file progress by its name
    QHash<QString, int> file_no;

    void setup_progress(const QStringList &files);

    /**
     * @brief setup_thread Setup working thread for encryption or decryption
     */
    void setup_thread();



public slots:
    //load public and private key from pem file
    bool load_publickey();
    bool load_privatekey();

    //Update UI timer
    void update_time();

    //Generate private key and corresponding publick key and save them to pem file
    void generate_key_clicked();

    //Encrypt or decrypt file(s)
    void encrypt_clicked();
    void decrypt_clicked();

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
