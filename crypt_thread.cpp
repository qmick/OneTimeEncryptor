#include "crypt_thread.h"
#include "encryptor.h"
#include "decryptor.h"
#include <QFileInfo>
#include <QDebug>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/applink.c>


using std::shared_ptr;

CryptThread::CryptThread(shared_ptr<AsymmetricCryptor> cryptor,
                             const QStringList &file_names)
    : cryptor(cryptor), file_names(file_names)
{
    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
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
        if (f.exists() && f.isFile() && f.size() > 0)
        {
            emit current_file(i);

            //Callback that used to recieve progress and send stop signal
            std::function<bool(long long)> cb = [&](long long bytes) {
                double total = static_cast<double>(f.size());
                double current  = static_cast<double>(bytes);
                emit current_progress(static_cast<int>(current / total * 1000.0));
                return !should_stop;
            };

            try
            {
                //If stop manually
                if (cryptor->crypt_file(i.toStdString(), cb) < 0)
                    break;
                count++;
            }
            catch (std::exception &e)
            {
                emit file_failed(i, QString(e.what()));
            }
        }
    }
    emit job_finished();
}
