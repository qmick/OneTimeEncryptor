#ifndef CRYPTOR_H
#define CRYPTOR_H

#include "secure_memory.h"
#include <cstdio>


class Cryptor
{
public:
    explicit Cryptor(SecureBuffer &secret);
    long encrypt_file(FILE *dst, FILE *src);
    long decrypt_file(FILE *dst, FILE *src);

private:
    SecureBuffer key;
    SecureBuffer iv;
};

#endif // CRYPTOR_H
