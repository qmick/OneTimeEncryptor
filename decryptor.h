#ifndef FILE_DECRYPTOR_H
#define FILE_DECRYPTOR_H

#include "secure_memory.h"
#include <string>

class Decryptor
{
public:
    explicit Decryptor(const std::string &master_prikey_pem);
    long decrypt_file(const std::string &filename);

private:
    EVP_PKEY_free_ptr master_key;
};

#endif // FILE_DECRYPTOR_H
