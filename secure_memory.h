#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <memory>
#include <string>
#include <openssl/evp.h>


typedef unsigned char byte;
using std::shared_ptr;
using std::unique_ptr;

//Smart pointers for openssl structure
using EVP_CIPHER_CTX_ptr = shared_ptr<EVP_CIPHER_CTX>;
using EVP_PKEY_ptr = shared_ptr<EVP_PKEY>;
using EVP_PKEY_CTX_ptr = shared_ptr<EVP_PKEY_CTX>;
using BIO_MEM_ptr = unique_ptr<BIO, decltype(&::BIO_free)>;
using EVP_MD_CTX_ptr = unique_ptr<EVP_MD_CTX, decltype (&::EVP_MD_CTX_free)>;

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
    SecureBuffer(const SecureBuffer &other);
    ~SecureBuffer();
    SecureBuffer &operator=(const SecureBuffer &other);
    byte &operator[](size_t n);
    const byte &operator[](size_t n) const;

    void resize(size_t new_size);

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
