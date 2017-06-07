#ifndef FILE_CRYPTOR_H
#define FILE_CRYPTOR_H

#include "secure_memory.h"
#include <QString>

class EVP_PKEY;

class Encryptor
{
public:
    explicit Encryptor(const secure_string &master_pubkey_str);

private:
    EVP_PKEY *master_key;
    size_t encrypt_file(const QString &filename);
};

#endif // FILE_CRYPTOR_H
