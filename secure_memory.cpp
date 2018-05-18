#include "secure_memory.h"
#include <openssl/crypto.h>
#include <cstring>

using std::string;

SecureBuffer::SecureBuffer()
    : n(0), buffer(nullptr)
{
}

SecureBuffer::SecureBuffer(size_t n)
    : n(n)
{
    if (n == 0)
        buffer = nullptr;
    else
        buffer = new byte[n];
}

SecureBuffer::SecureBuffer(const byte *other, size_t n)
    : n(n)
{
    buffer = new byte[n];
    memmove(buffer, other, n);
}

SecureBuffer::SecureBuffer(const string &str)
    : n(str.size() + 1)
{
    buffer = new byte[n];
    memmove(buffer, str.c_str(), n);
    buffer[n - 1] = '\0';
}

SecureBuffer::SecureBuffer(const SecureBuffer &other)
    : n(other.n), buffer(other.buffer)
{
    n = other.n;
    buffer = new byte[n];
    memmove(buffer, other.buffer, n);
}

SecureBuffer::~SecureBuffer()
{
    OPENSSL_cleanse(buffer, n);
    delete []buffer;
}

SecureBuffer &SecureBuffer::operator=(const SecureBuffer &other)
{
    n = other.n;
    buffer = new byte[n];
    memmove(buffer, other.buffer, n);
    return *this;
}

byte &SecureBuffer::operator[](size_t n)
{
    return buffer[n];
}

const byte &SecureBuffer::operator[](size_t n) const
{
    return buffer[n];
}

void SecureBuffer::resize(size_t new_size)
{
    if (new_size > n)
    {
        if (n != 0)
        {
            OPENSSL_cleanse(buffer, n);
            delete []buffer;
        }
        buffer = new byte[new_size];
    }
    else
    {
        OPENSSL_cleanse(buffer + new_size, n - new_size);
        n = new_size;
    }
}

byte* SecureBuffer::get()
{
    return buffer;
}

const byte *SecureBuffer::get() const
{
    return buffer;
}

size_t SecureBuffer::size() const
{
    return n;
}
