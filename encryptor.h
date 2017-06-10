#ifndef FILE_CRYPTOR_H
#define FILE_CRYPTOR_H

#include "asymmetric_cryptor.h"
#include "secure_memory.h"

class Encryptor : public AsymmetricCryptor
{
public:
    /**
     * @brief Encryptor construct
     * @param master_pubkey_pem Path to PEM file that contains master private key
     */
    explicit Encryptor(const std::string &master_pubkey_pem);

    ~Encryptor() override;

    /**
     * @brief Encrypt file using ECDH and AES
     * @param filename File(s) to be encrypted
     * @param Callback used to send progress and recieve stop signal
     * @return callback Encrypted data size, -1 if stop by callback
     */
    long long crypt_file(const std::string &filename, std::function<bool(long long)> callback) override;

private:
    //Master public key
    EVP_PKEY_free_ptr master_key;
};

#endif // FILE_CRYPTOR_H
