#ifndef ASYMMETRIC_CRYPTOR_H
#define ASYMMETRIC_CRYPTOR_H

#include <string>
#include <functional>

class AsymmetricCryptor
{
public:
    virtual ~AsymmetricCryptor();

    /**
     * @brief crypt_file Function that encrypt/decrypt file(s)
     * @param filename File(s) to be processed
     * @param callback Callback that used to send progress and recieve stop signal
     * @return
     */
    virtual long long crypt_file(const std::string &filename, std::function<bool(long long)> callback) = 0;
};

#endif // ASYMMETRIC_CRYPTOR_H
