#ifndef ASYMMETRIC_CRYPTOR_H
#define ASYMMETRIC_CRYPTOR_H

#include <string>
#include <functional>

class AsymmetricCryptor
{
public:
    virtual ~AsymmetricCryptor();
    virtual long long crypt_file(const std::string &filename, std::function<bool(long long)> callback) = 0;
};

#endif // ASYMMETRIC_CRYPTOR_H
