#ifndef FILE_DECRYPTOR_H
#define FILE_DECRYPTOR_H

#include "asymmetric_cryptor.h"
#include "secure_memory.h"

class Decryptor : public AsymmetricCryptor
{
public:
    Decryptor(const std::string &master_prikey_pem, SecureBuffer &password);
    ~Decryptor();
    long long crypt_file(const std::string &filename, std::function<bool(long long)> callback);

private:
    EVP_PKEY_free_ptr master_key;
};

#endif // FILE_DECRYPTOR_H
