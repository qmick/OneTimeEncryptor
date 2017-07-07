#include "crypto_io.h"
#include "c_exception.h"


CryptoIO::CryptoIO(const std::string &filename, const char *mode)
    : filename(filename)
{
    open();
}

CryptoIO::~CryptoIO()
{
    close();
}

bool CryptoIO::open()
{
    fp = fopen(filename.c_str(), mode);
    if (!fp)
        throw CException("cannot open");
}

int CryptoIO::close()
{
    if (!fp)
        return 0;

    auto ret = fclose(fp);
    if (!ret)
        fp = NULL;
    return ret;
}

size_t CryptoIO::read(void *buffer, size_t size, size_t count)
{
    auto len = fread(buffer, size, count, fp);
    if (ferror(fp))
        throw CException("cannot read");
    return len;
}

size_t CryptoIO::must_read(void *buffer, size_t size, size_t count)
{
    auto len = fread(buffer, size, count, fp);
    if (count != len)
        throw CException("cannot read");

    return len;
}

size_t CryptoIO::write(const void *buffer, size_t size, size_t count)
{
    auto len = fwrite(buffer, size, count, fp);
    if (len != count)
        throw CException("cannot write");

    return len;
}

int CryptoIO::remove()
{
    close();
    return ::remove(filename.c_str());
}

bool CryptoIO::eof()
{
    return feof(fp) != 0;
}

FILE *CryptoIO::get()
{
    return fp;
}
