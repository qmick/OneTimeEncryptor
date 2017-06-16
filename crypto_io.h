#ifndef CRYPTO_IO_H
#define CRYPTO_IO_H

#include "secure_memory.h"
#include <string>
#include <cstdio>


class CryptoIO
{
public:
    explicit CryptoIO(const std::string &filename, const char *mode);
    ~CryptoIO();
    int close();
    size_t read(void *buffer, size_t size, size_t count);
    size_t must_read(void *buffer, size_t size, size_t count);
    size_t write(const void *buffer, size_t, size_t count);
    int remove();
    bool eof();
    FILE *get();

private:
    std::string filename;
    FILE *fp;
};

#endif // CRYPTO_IO_H
