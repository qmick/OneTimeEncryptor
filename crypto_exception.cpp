#include "crypto_exception.h"
#include <openssl/err.h>
#include <memory>


using std::shared_ptr;
using std::default_delete;

CryptoException::CryptoException()
{
    auto buf = shared_ptr<char>(new char[kMaxErrorStringLen + 1], default_delete<char[]>());
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
