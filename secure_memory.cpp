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

SecureBuffer::SecureBuffer(SecureBuffer &&other) noexcept
    : n(other.n), buffer(other.buffer)
{
    other.n = 0;
    other.buffer = nullptr;
}

SecureBuffer::~SecureBuffer()
{
    OPENSSL_cleanse(buffer, n*sizeof(byte));
    delete []buffer;
}

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&other) noexcept
{
    n = other.n;
    buffer = other.buffer;
    other.n = 0;
    other.buffer = nullptr;

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
