#include "crypt_thread.h"
#include "asymmetric_cryptor.h"
#include <QFileInfo>
#include <QDebug>

using std::make_unique;

const std::string CryptThread::kCryptSign = "[encrypted]";

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
                std::string src(i.toLocal8Bit().data());
                std::string dst(src + kCryptSign);
                int64_t rs;

                if (mode == ENCRYPTION)
                    rs = cryptor->encrypt(src, dst, cb, cipher.toStdString());
                else
                    rs = cryptor->decrypt(src, dst, cb);

                //If stop manually
                if (rs < 0)
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
