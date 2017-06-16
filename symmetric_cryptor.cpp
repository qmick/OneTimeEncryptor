#include "symmetric_cryptor.h"
#include "crypto_io.h"
#include "crypto_exception.h"
#include "c_exception.h"
#include <openssl/evp.h>
#include <QDebug>

using std::function;
using std::runtime_error;

SymmetricCryptor::SymmetricCryptor()
    : symmetric_cipher(EVP_aes_256_cbc())
{
}

SymmetricCryptor::SymmetricCryptor(const EVP_CIPHER *cipher)
    : symmetric_cipher(cipher)
{
}

SymmetricCryptor::SymmetricCryptor(SecureBuffer &secret)
    : symmetric_cipher(EVP_aes_256_cbc())
{
    key = SecureBuffer(EVP_MAX_KEY_LENGTH);
    iv = SecureBuffer(EVP_MAX_IV_LENGTH);

    //Derive aes key from secret. EVP_ByteTokey() is used to derive key from password,
    //the security of using it on secret is not clear
    if (0 == EVP_BytesToKey(symmetric_cipher, EVP_sha256(), NULL, secret.get(),
                            static_cast<int>(secret.size()), 1, key.get(), iv.get()))
        throw CryptoException();
}

SymmetricCryptor::SymmetricCryptor(SecureBuffer &secret, const EVP_CIPHER *cipher)
    : symmetric_cipher(cipher)
{
    key = SecureBuffer(EVP_MAX_KEY_LENGTH);
    iv = SecureBuffer(EVP_MAX_IV_LENGTH);

    //Derive aes key from secret. EVP_ByteTokey() is used to derive key from password,
    //the security of using it on secret is not clear
    if (0 == EVP_BytesToKey(symmetric_cipher, EVP_sha256(), NULL, secret.get(),
                            static_cast<int>(secret.size()), 1, key.get(), iv.get()))
        throw CryptoException();
}


int64_t SymmetricCryptor::encrypt_file(CryptoIO &dst, CryptoIO &src, function<bool(int64_t)> callback)
{
    //Buffer to place read data
    auto in_buf = SecureBuffer(kMaxInBufferSize);

    //Buffer to place data to be written
    auto out_buf = SecureBuffer(kMaxOutBufferSize);

    //Total data length write
    int64_t cipher_len = 0;

    //Output data length of every EVP_EncryptUpdate() call
    auto block_len = 0;

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher */
    if (1 != EVP_EncryptInit_ex(ctx.get(), symmetric_cipher, NULL, key.get(), iv.get()))
        throw CryptoException();

    //Work until EOF
    while (!src.eof())
    {
        //Read kMaxInBufferSize data for src file
        auto plain_len = src.read(in_buf.get(), 1, kMaxInBufferSize);

        /* Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        if (1 != EVP_EncryptUpdate(ctx.get(), out_buf.get(), &block_len, in_buf.get(), static_cast<int>(plain_len)))
            throw CryptoException();

        //Write encrypted data to file
        dst.write(out_buf.get(), 1, static_cast<unsigned int>(block_len));
        cipher_len += block_len;

        //If asked to stop, then stop and return
        if (!callback(cipher_len))
            return -1;
    }

    //Finalize this encryption
    if (1 != EVP_EncryptFinal_ex(ctx.get(), out_buf.get(), &block_len))
        throw CryptoException();

    //Something still need to be written
    if (block_len > 0)
    {
        dst.write(out_buf.get(), 1, static_cast<unsigned int>(block_len));
        cipher_len += block_len;
    }

    if (!callback(cipher_len))
        return -1;

    return cipher_len;
}


//Almost the same as encryption
int64_t SymmetricCryptor::decrypt_file(CryptoIO &dst, CryptoIO &src, function<bool(int64_t)> callback)
{
    auto in_buf = SecureBuffer(kMaxInBufferSize);
    auto out_buf = SecureBuffer(kMaxOutBufferSize);
    auto block_len = 0;
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int64_t plain_len = 0;

    if (1 != EVP_DecryptInit_ex(ctx.get(), symmetric_cipher, NULL, key.get(), iv.get()))
        throw CryptoException();

    while (!src.eof())
    {
        auto cipher_len = src.read(in_buf.get(), 1, kMaxInBufferSize);
        if (1 != EVP_DecryptUpdate(ctx.get(), out_buf.get(), &block_len, in_buf.get(), static_cast<int>(cipher_len)))
            throw CryptoException();
        dst.write(out_buf.get(), 1, static_cast<size_t>(block_len));
        plain_len += block_len;
        if (!callback(plain_len))
            return -1;
    }

    if (1 != EVP_DecryptFinal_ex(ctx.get(), out_buf.get(), &block_len))
        throw CryptoException();
    if (block_len > 0)
    {
        dst.write(out_buf.get(), 1, static_cast<size_t>(block_len));
        plain_len += block_len;
    }
    if (!callback(plain_len))
        return -1;

    return plain_len;
}

int64_t SymmetricCryptor::seal_file(CryptoIO &dst, CryptoIO &src, EVP_PKEY_ptr pubk,
                                      std::function<bool (int64_t)> callback)
{
    //Buffer to place read data
    auto in_buf = SecureBuffer(kMaxInBufferSize);

    //Buffer to place data to be written
    auto out_buf = SecureBuffer(kMaxOutBufferSize);

    //Total data length write
    int64_t cipher_len = 0;

    //Data length of 1 update cycle
    int block_len = 0;

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    int32_t key_len = 0;
    key = SecureBuffer(static_cast<size_t>(EVP_PKEY_size(pubk.get())));
    iv = SecureBuffer(static_cast<size_t>(EVP_CIPHER_iv_length(EVP_aes_256_cbc())));

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    auto tmp_key = key.get();
    auto tmp_pubk = pubk.get();
    if (1 != EVP_SealInit(ctx.get(), symmetric_cipher, &tmp_key, &key_len, iv.get(), &tmp_pubk, 1))
        throw CryptoException();
    key.resize(static_cast<size_t>(key_len));

    dst.write(&key_len, sizeof(key_len), 1);
    dst.write(key.get(), 1, key.size());
    dst.write(iv.get(), 1, iv.size());

    //Work until EOF
    while (!src.eof())
    {
        //Read kMaxInBufferSize data for src file
        auto plain_len = src.read(in_buf.get(), 1, kMaxInBufferSize);

        /* Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        if (1 != EVP_SealUpdate(ctx.get(), out_buf.get(), &block_len, in_buf.get(), static_cast<int>(plain_len)))
            throw CryptoException();

        //Write encrypted data to file
        dst.write(out_buf.get(), 1, static_cast<unsigned int>(block_len));
        cipher_len += block_len;

        //If asked to stop, then stop and return
        if (!callback(cipher_len))
            return -1;
    }

    //Finalize this encryption
    if (1 != EVP_SealFinal(ctx.get(), out_buf.get(), &block_len))
        throw CryptoException();

    //Something still need to be written
    if (block_len > 0)
    {
        dst.write(out_buf.get(), 1, static_cast<unsigned int>(block_len));
        cipher_len += block_len;
    }

    if (!callback(cipher_len))
        return -1;

    return cipher_len;
}

int64_t SymmetricCryptor::open_file(CryptoIO &dst, CryptoIO &src, EVP_PKEY_ptr priv,
                                      std::function<bool (int64_t)> callback)
{
    auto in_buf = SecureBuffer(kMaxInBufferSize);
    auto out_buf = SecureBuffer(kMaxOutBufferSize);
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int64_t plain_len = 0;
    int block_len = 0;
    int32_t key_len = 0;
    size_t iv_len = static_cast<size_t>(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));

    key = SecureBuffer(static_cast<size_t>(EVP_PKEY_size(priv.get())));
    iv = SecureBuffer(iv_len);

    src.read(&key_len, sizeof(key_len), 1);
    key.resize(key_len);

    src.read(key.get(), 1, key_len);
    src.read(iv.get(), 1, iv_len);

    if (1 != EVP_OpenInit(ctx.get(), symmetric_cipher, key.get(),
                          static_cast<int>(key.size()), iv.get(), priv.get()))
        throw CryptoException();

    while (!src.eof())
    {
        auto cipher_len = src.read(in_buf.get(), 1, kMaxInBufferSize);
        if (1 != EVP_OpenUpdate(ctx.get(), out_buf.get(), &block_len, in_buf.get(), static_cast<int>(cipher_len)))
            throw CryptoException();
        dst.write(out_buf.get(), 1, static_cast<size_t>(block_len));
        plain_len += block_len;
        if (!callback(plain_len))
            return -1;
    }

    if (1 != EVP_OpenFinal(ctx.get(), out_buf.get(), &block_len))
        throw CryptoException();
    if (block_len > 0)
    {
        dst.write(out_buf.get(), 1, static_cast<size_t>(block_len));
        plain_len += block_len;
    }
    if (!callback(plain_len))
        return -1;

    return plain_len;
}

const EVP_CIPHER *SymmetricCryptor::get_cipher() const
{
    return symmetric_cipher;
}

