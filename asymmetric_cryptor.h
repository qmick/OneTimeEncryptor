#ifndef ASYMMETRIC_CRYPTOR_H
#define ASYMMETRIC_CRYPTOR_H

#include "secure_memory.h"
#include <string>
#include <functional>
#include <cstdint>

class AsymmetricCryptor
{
public:
    const std::string kCryptSign = "[encrypted]";

    virtual ~AsymmetricCryptor();

    /**
     * @brief Function that encrypt/decrypt file(s)
     * @param filename File(s) to be processed
     * @param callback Callback that used to send progress and recieve stop signal
     * @return
     */
    virtual int64_t crypt_file(const std::string &filename,
                               std::function<bool(int64_t)> callback,
                               const std::string &cipher_name = "AES-256-CBC") = 0;

    /**
     * @brief Get private key or public key stored in PKEY structure
     * @return private key or public key
     */
    virtual EVP_PKEY_ptr get_key() = 0;
};


#endif // ASYMMETRIC_CRYPTOR_H
