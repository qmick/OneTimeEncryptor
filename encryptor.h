#ifndef FILE_CRYPTOR_H
#define FILE_CRYPTOR_H

#include "secure_memory.h"


class Encryptor
{
public:
    explicit Encryptor(const secure_string &master_pubkey_str);
    long encrypt_file(const std::string &filename);

private:
    EVP_PKEY_free_ptr master_key;

};

#endif // FILE_CRYPTOR_H
