#include "cryptor.h"
#include "crypto_exception.h"
#include <openssl/evp.h>



Cryptor::Cryptor(SecureBuffer &secret)
{
    key = SecureBuffer(EVP_MAX_KEY_LENGTH);
    iv = SecureBuffer(EVP_MAX_IV_LENGTH);
    if (0 == EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), NULL, secret.get(),
                            static_cast<int>(secret.size()), 1, key.get(), iv.get()))
        throw CryptoException();
}


long Cryptor::encrypt_file(FILE *dst, FILE *src)
{
    const auto kMaxInBufferSize = 1024 * 1024;
    const auto kMaxOutBufferSize = kMaxInBufferSize + 1024;
    auto in_buf = SecureBuffer(kMaxInBufferSize);
    auto out_buf = SecureBuffer(kMaxOutBufferSize);
    long cipher_len = 0;
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL, key.get(), iv.get()))
        throw CryptoException();

    while (!feof(src))
    {
        int block_len = 0;
        auto plain_len = fread(in_buf.get(), 1, kMaxInBufferSize, src);
        if (ferror(src))
            throw std::runtime_error("Cannot read from file");

        /* Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        EVP_EncryptUpdate(ctx.get(), out_buf.get(), &block_len, in_buf.get(), static_cast<int>(plain_len));
        fwrite(out_buf.get(), 1, static_cast<unsigned int>(block_len), dst);

        if (ferror(dst))
            throw std::runtime_error("Cannot write file");

        cipher_len += block_len;
    }

    return cipher_len;
}

long Cryptor::decrypt_file(FILE *dst, FILE *src)
{
    const auto kMaxInBufferSize = 1024 * 1024;
    const auto kMaxOutBufferSize = kMaxInBufferSize + 1024;
    auto in_buf = SecureBuffer(kMaxInBufferSize);
    auto out_buf = SecureBuffer(kMaxOutBufferSize);
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    long plain_len = 0;

    if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL, key.get(), iv.get()))
        throw CryptoException();

    while (!feof(src))
    {
        int block_len = 0;
        auto cipher_len = fread(in_buf.get(), 1, kMaxInBufferSize, src);
        if (1 != EVP_DecryptUpdate(ctx.get(), out_buf.get(), &block_len, in_buf.get(), static_cast<int>(cipher_len)))
            throw CryptoException();
        fwrite(out_buf.get(), 1, static_cast<size_t>(block_len), dst);

        if (ferror(dst))
            throw std::runtime_error("Cannot write file");
        plain_len += block_len;
    }

    return plain_len;
}
