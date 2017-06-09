#ifndef FILE_CRYPTOR_H
#define FILE_CRYPTOR_H

#include "asymmetric_cryptor.h"
#include "secure_memory.h"

class Encryptor : public AsymmetricCryptor
{
public:
    explicit Encryptor(const std::string &master_pubkey_pem);
    ~Encryptor();
    long long crypt_file(const std::string &filename, std::function<bool(long long)> callback);

private:
    EVP_PKEY_free_ptr master_key;
};

#endif // FILE_CRYPTOR_H
