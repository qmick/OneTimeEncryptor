#include "cryptor.h"
#include "crypto_exception.h"
#include <openssl/evp.h>

using std::make_shared;
using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;


Cryptor::Cryptor(shared_ptr<byte> secret, int secret_len)
{
    key = get_byte_shared(EVP_MAX_KEY_LENGTH);
    iv = get_byte_shared(EVP_MAX_IV_LENGTH);
    if (0 == EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), NULL, secret.get(), secret_len, 1, key.get(), iv.get()))
        throw CryptoException();
}


int Cryptor::file_encrypt(FILE *dst, FILE *src)
{
    const auto kMaxInBufferSize = 1024 * 1024;
    const auto kMaxOutBufferSize = kMaxInBufferSize + 1024;
    auto in_buf = get_byte_shared(kMaxInBufferSize);
    auto out_buf = get_byte_shared(kMaxOutBufferSize);
    int len = 0;
    int ciphertext_len = 0;
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL, key.get(), iv.get()))
        throw CryptoException();

    while (!feof(src))
    {
        int plaintext_len = static_cast<int>(fread(in_buf.get(), 1, kMaxInBufferSize, src));
        if (ferror(src))
            throw std::runtime_error("Cannot read from file");

        /* Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        EVP_EncryptUpdate(ctx.get(), out_buf.get(), &len, in_buf.get(), plaintext_len);
        fwrite(out_buf.get(), 1, static_cast<unsigned int>(len), dst);

        if (ferror(dst))
            throw std::runtime_error("%s cannot be write.\n");

        ciphertext_len += len;
    }

    return ciphertext_len;
}

int Cryptor::file_edecrypt(FILE *dst, FILE *src)
{

}
