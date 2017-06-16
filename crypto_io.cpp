#include "crypto_io.h"
#include "c_exception.h"


CryptoIO::CryptoIO(const char *filename, const char *mode)
{
    fp = fopen(filename.c_str(), mode);
    if (!fp)
        throw CException("cannot open");
}

CryptoIO::~CryptoIO()
{
    close();
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
    auto len = fread(buffer, size, count);
    if (ferror(fp))
    {
        close();
        throw CException("cannot read");
    }
    return len;
}

size_t CryptoIO::must_read(void *buffer, size_t size, size_t count)
{
    auto len = fread(buffer, size, count);
    if (count != len)
    {
        close();
        throw CException("cannot read");
    }

    return len;
}

size_t CryptoIO::write(const void *buffer, size_t size, size_t count)
{
    auto len = fwrite(buffer, size, count);
    if (len != count)
    {
        close();
        throw CException("cannot write");
    }
}
