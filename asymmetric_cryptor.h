#ifndef ASYMMETRIC_CRYPTOR_H
#define ASYMMETRIC_CRYPTOR_H

#include "secure_memory.h"
#include <string>
#include <functional>

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
    virtual long long crypt_file(const std::string &filename, std::function<bool(long long)> callback) = 0;

    /**
     * @brief Get private key or public key stored in PKEY structure
     * @return private key or public key
     */
    virtual EVP_PKEY_ptr get_key() = 0;
};


#endif // ASYMMETRIC_CRYPTOR_H
