#ifndef CRYPTO_EXCEPTION_H
#define CRYPTO_EXCEPTION_H

#include <exception>
#include <string>

class CryptoException : public virtual std::exception
{
public:
    static const int kMaxErrorStringLen = 256;
    CryptoException();
    virtual const char* what() const noexcept;

private:
    std::string what_str;
};

#endif // CRYPTO_EXCEPTION_H
