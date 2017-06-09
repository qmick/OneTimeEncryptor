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
    CryptThread(std::shared_ptr<AsymmetricCryptor> cryptor,
                  const QStringList &file_names);
    ~CryptThread();
    bool should_stop;
protected:
    void run();

signals:
    void current_file(const QString &s);
    void file_failed(const QString &file, const QString &reason);
    void current_progress(int progress);
    void job_finished();

private:
    std::shared_ptr<AsymmetricCryptor> cryptor;
    QStringList file_names;
};

#endif // ENCRYPT_THREAD_H
