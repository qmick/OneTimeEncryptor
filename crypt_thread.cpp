#include "crypt_thread.h"
#include "encryptor.h"
#include "decryptor.h"
#include <QFileInfo>
#include <QDebug>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#ifdef _MSC_VER
#include <openssl/applink.c>
#endif

CryptThread::CryptThread(std::shared_ptr<AsymmetricCryptor> cryptor,
                             const QStringList &file_names)
    : cryptor(cryptor), file_names(file_names)
{
    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}

CryptThread::~CryptThread()
{
    ERR_free_strings();
}

void CryptThread::run() {
    int count = 0;

    should_stop = false;
    for (auto &i : file_names)
    {
        QFileInfo f(i);
        emit current_file(i, f.size());
        if (f.exists() && f.isFile() && f.size() > 0)
        {
            //Callback that used to recieve progress and send stop signal
            std::function<bool(int64_t)> cb = [&](int64_t bytes) {
                auto total = static_cast<double>(f.size());
                auto current  = static_cast<double>(bytes);
                auto progress = static_cast<int>(current / total * 100.0);
                emit current_progress(i, progress);
                return !should_stop;
            };

            try
            {
                //If stop manually
                if (cryptor->crypt_file(std::string(i.toLocal8Bit().data()), cb) < 0)
                {
                    emit file_stopped(i);
                    break;
                }
                count++;
                emit current_finished(i);
            }
            catch (std::exception &e)
            {
                emit file_failed(i, QString(e.what()));
            }  
        }
        else
            emit file_failed(i, tr("File not exists or size 0"));
    }
    emit job_finished();
}
