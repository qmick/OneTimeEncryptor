#ifndef CRYPTOR_H
#define CRYPTOR_H

#include "secure_memory.h"
#include <cstdio>


class Cryptor
{
public:
    Cryptor(shared_ptr<byte> secret, int secret_len);
    int file_encrypt(FILE *dst, FILE *src);
    int file_edecrypt(FILE *dst, FILE *src);

private:
    shared_ptr<byte> key;
    shared_ptr<byte> iv;
};

#endif // CRYPTOR_H
