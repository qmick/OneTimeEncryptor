#include "crypto_exception.h"
#include <openssl/err.h>

CryptoException::CryptoException()
{
    what_str = std::shared_ptr<char>(new char[kMaxErrorStringLen], std::default_delete<char[]>());
    auto e = ERR_get_error();
    if (!e)
        return;

    ERR_error_string(e, what_str.get());
}


const char* CryptoException::what() const noexcept
{
    return what_str.get();
}
