#ifndef FILE_DECRYPTOR_H
#define FILE_DECRYPTOR_H

#include "asymmetric_cryptor.h"


class Decryptor : public AsymmetricCryptor
{
public:
    /**
     * @brief Decryptor constructor
     * @param master_prikey_pem Path to PEM file that contains master private key
     * @param password Password used to encrypt private key
     */
    Decryptor(const std::string &master_prikey_pem, SecureBuffer &password);

    ~Decryptor() override;

    /**
     * @brief Decrypt file using ECDH and AES
     * @param filename File(s) to be decrypted
     * @param callback Callback used to send progress and recieve stop signal
     * @return Decrypted data size, -1 if stop by callback
     */
    int64_t crypt_file(const std::string &filename,
                       std::function<bool(int64_t)> callback,
                       const std::string &) override;

    /**
     * @brief Get master private key
     * @return
     */
    EVP_PKEY_ptr get_key() override;

private:
    //Master private key
    EVP_PKEY_ptr master_key;

    int key_type;
};

#endif // FILE_DECRYPTOR_H
