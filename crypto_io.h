#ifndef CRYPTO_IO_H
#define CRYPTO_IO_H

#include <cstdio>


class CryptoIO
{
public:
    explicit CryptoIO(const char *filename, const char *mode);
    ~CryptoIO();
    int close();
    size_t read(void *buffer, size_t size, size_t count);
    size_t must_read(void *buffer, size_t size, size_t count);
    size_t write(const void *buffer, size_t, size_t count);

private:
    FILE *fp;
};

#endif // CRYPTO_IO_H
