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

    explicit MainWindow(const Mode &mode, const QStringList &files, QWidget *parent = 0);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QString public_path;
    QString private_path;
    std::shared_ptr<Encryptor> encryptor;
    std::shared_ptr<Decryptor> decryptor;
    std::shared_ptr<CryptThread> crypt_thread;
    void setup_thread();
    QTimer timer;
    QTime time_record;
    int count;


public slots:
    void load_publickey();
    void load_privatekey();
    void update_time();
    void generate_key_clicked();
    void encrypt_clicked();
    void decrypt_clicked();
    void current_file(const QString &s);
    void file_failed(const QString &file, const QString &reason);
    void current_progress(int progress);
    void job_finished();
    void stop_job();
};

#endif // MAINWINDOW_H
