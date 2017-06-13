#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <memory>
#include <string>
#include <openssl/evp.h>


typedef unsigned char byte;
using std::shared_ptr;

//Smart pointers for openssl structure
using EVP_CIPHER_CTX_ptr = shared_ptr<EVP_CIPHER_CTX>;
using EVP_PKEY_ptr = shared_ptr<EVP_PKEY>;
using EVP_PKEY_CTX_ptr = shared_ptr<EVP_PKEY_CTX>;


/**
 * @brief The SecureBuffer class is a buffer that used to place secret information
 *        and will be erased using OPENSSL_cleanse() before being free
 */
class SecureBuffer
{
public:
    SecureBuffer();
    explicit SecureBuffer(size_t n);
    SecureBuffer(const byte *other, size_t n);
    SecureBuffer(const std::string &str);
    SecureBuffer(SecureBuffer &&other) noexcept;
    ~SecureBuffer();
    SecureBuffer &operator=(const SecureBuffer &other) = delete;
    SecureBuffer &operator=(SecureBuffer &&other) noexcept;
    byte &operator[](size_t n);
    const byte &operator[](size_t n) const;

    //Get raw pointer to buffer zone
    byte* get();
    const byte* get() const;

    //Get buffer size
    size_t size() const;

private:
    size_t n;
    byte* buffer;
};


#endif // SECURE_MEMORY_H
