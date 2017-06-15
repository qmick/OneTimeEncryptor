#ifndef RSA_ENCRYPTOR_H
#define RSA_ENCRYPTOR_H

#include "asymmetric_cryptor.h"

class RSAEncryptor : public AsymmetricCryptor
{
public:
    explicit RSAEncryptor(const std::string &master_pubkey_pem);

    // AsymmetricCryptor interface
    long long crypt_file(const std::string &filename, std::function<bool (long long)> callback) override;
    EVP_PKEY_ptr get_key() override;

private:
    //Master public key
    EVP_PKEY_ptr master_key;
};

#endif // RSA_ENCRYPTOR_H
