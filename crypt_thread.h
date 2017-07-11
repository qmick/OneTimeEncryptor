#ifndef ENCRYPT_THREAD_H
#define ENCRYPT_THREAD_H


#include <QThread>
#include <QStringList>
#include <memory>

class AsymmetricCryptor;

class CryptThread : public QThread
{
    Q_OBJECT

public:
    enum MODE { ENCRYPTION, DECRYPTION };

    static const QString kCryptSign;

    CryptThread(const QStringList &file_names);
    ~CryptThread();
    void stop();
    void set_mode(const MODE mode);
    void set_cipher(const QString &cipher);
    void set_files(const QStringList &files);
    void set_cryptor(std::shared_ptr<AsymmetricCryptor> cryptor);

protected:
    void run();

signals:
    void current_file(const QString &filename, const qint64 filesize);
    void file_failed(const QString &file, const QString &reason);
    void file_stopped(const QString &file);
    void current_progress(const QString &file, int progress);
    void current_finished(const QString &s);
    void job_finished();

private:
    std::shared_ptr<AsymmetricCryptor> cryptor;
    QStringList file_names;
    bool should_stop;
    MODE mode;
    QString cipher;
};

#endif // ENCRYPT_THREAD_H
