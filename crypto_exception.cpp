#include "crypto_exception.h"
#include <openssl/err.h>
#include <memory>

CryptoException::CryptoException()
{
    auto buf = std::shared_ptr<char>(new char[kMaxErrorStringLen + 1], std::default_delete<char[]>());
    auto e = ERR_get_error();
    if (!e)
        return;

    ERR_error_string(e, buf.get());
    what_str = buf.get();
}


const char* CryptoException::what() const noexcept
{
    return what_str.c_str();
}
