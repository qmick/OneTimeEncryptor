#include "crypt_thread.h"
#include "asymmetric_cryptor.h"
#include <QFileInfo>
#include <QDebug>

using std::make_unique;
using std::function;
using std::shared_ptr;
using std::string;
using std::exception;

const QString CryptThread::kCryptSign = "[encrypted]";

CryptThread::CryptThread(const QStringList &file_names)
    : file_names(file_names)
{
}

CryptThread::~CryptThread()
{
}

void CryptThread::stop()
{
    should_stop = true;
}

void CryptThread::set_mode(const CryptThread::MODE mode)
{
    this->mode = mode;
}

void CryptThread::set_cipher(const QString &cipher)
{
    this->cipher = cipher;
}

void CryptThread::set_files(const QStringList &files)
{
    file_names = files;
}

void CryptThread::set_cryptor(shared_ptr<AsymmetricCryptor> cryptor)
{
    this->cryptor = cryptor;
}

void CryptThread::run()
{
    should_stop = false;
    for (auto &i : file_names)
    {
        QFileInfo f(i);
        emit current_file(i, f.size());
        if (f.exists() && f.isFile() && f.size() > 0)
        {
            //Callback that used to recieve progress and send stop signal
            function<bool(int64_t)> cb = [&](int64_t bytes) {
                auto total = static_cast<double>(f.size());
                auto current  = static_cast<double>(bytes);
                auto progress = static_cast<int>(current / total * 100.0);
                emit current_progress(i, progress);
                return !should_stop;
            };

            try
            {
                string src(i.toLocal8Bit().data());
                string dst;
                int64_t rs;

                if (mode == ENCRYPTION)
                {
                    dst = (i + kCryptSign).toLocal8Bit().data();
                    rs = cryptor->encrypt(src, dst, cb, cipher.toStdString());
                }
                else
                {
                    auto pos = i.indexOf(kCryptSign);
                    if (pos > 0)
                        dst = i.remove(pos, kCryptSign.size()).toLocal8Bit().data();
                    else
                        dst = (i + "[plain]").toLocal8Bit().data();
                    rs = cryptor->decrypt(src, dst, cb);
                }

                //If stop manually
                if (rs < 0)
                {
                    emit file_stopped(i);
                    break;
                }
                emit current_finished(i);
            }
            catch (exception &e)
            {
                emit file_failed(i, QString(e.what()));
            }  
        }
        else
            emit file_failed(i, tr("File not exists or size 0"));
    }
    emit job_finished();
}
