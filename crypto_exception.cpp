#include "crypto_exception.h"
#include <openssl/err.h>
#include <memory>


using std::make_unique;

CryptoException::CryptoException()
{
    auto buf = make_unique<char[]>(kMaxErrorStringLen + 1);
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
