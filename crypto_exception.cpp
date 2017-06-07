#include "crypto_exception.h"

#include <openssl/err.h>

CryptoException::CryptoException()
{
    what_str = std::make_shared<char>(kMaxErrorStringLen);
    auto e = ERR_get_error();
    if (e == 0)
        return;

    ERR_error_string(e, what_str.get());
}


const char* CryptoException::what() const noexcept
{
    return what_str.get();
}
