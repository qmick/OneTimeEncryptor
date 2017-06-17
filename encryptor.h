#ifndef FILE_CRYPTOR_H
#define FILE_CRYPTOR_H

#include "asymmetric_cryptor.h"


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
    int64_t crypt_file(const std::string &filename,
                       std::function<bool(int64_t)> callback,
                       const std::string &cipher_name) override;

    /**
     * @brief Get master public key
     * @return
     */
    EVP_PKEY_ptr get_key() override;

private:
    //Master public key
    EVP_PKEY_ptr master_key;

    int key_type;
};

#endif // FILE_CRYPTOR_H
