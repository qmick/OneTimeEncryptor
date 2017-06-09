#ifndef CRYPTO_EXCEPTION_H
#define CRYPTO_EXCEPTION_H

#include <exception>
#include <memory>

class CryptoException : public std::exception
{
public:
    static const int kMaxErrorStringLen = 256;
    explicit CryptoException();
    virtual const char* what() const noexcept;

private:
    std::shared_ptr<char> what_str;
};

#endif // CRYPTO_EXCEPTION_H
