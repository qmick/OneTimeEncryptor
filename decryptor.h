#ifndef FILE_DECRYPTOR_H
#define FILE_DECRYPTOR_H

#include "asymmetric_cryptor.h"
#include "secure_memory.h"

class Decryptor : public AsymmetricCryptor
{
public:
    /**
     * @brief Decryptor constructor
     * @param master_prikey_pem Path to PEM file that contains master private key
     * @param password Password used to encrypt private key
     */
    Decryptor(const std::string &master_prikey_pem, SecureBuffer &password);

    ~Decryptor();

    /**
     * @brief Decrypt file using ECDH and AES
     * @param filename File(s) to be decrypted
     * @param callback Callback used to send progress and recieve stop signal
     * @return Decrypted data size, -1 if stop by callback
     */
    long long crypt_file(const std::string &filename, std::function<bool(long long)> callback);

private:
    //Master private key
    EVP_PKEY_free_ptr master_key;
};

#endif // FILE_DECRYPTOR_H
