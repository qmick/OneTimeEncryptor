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
    iv = SecureBuffer(static_cast<size_t>(EVP_CIPHER_iv_length(symmetric_cipher)));
}

SymmetricCryptor::SymmetricCryptor(const EVP_CIPHER *cipher)
    : symmetric_cipher(cipher)
{
    iv = SecureBuffer(static_cast<size_t>(EVP_CIPHER_iv_length(symmetric_cipher)));
}

SymmetricCryptor::SymmetricCryptor(SecureBuffer &secret)
    : symmetric_cipher(EVP_aes_256_cbc())
{
    key = SecureBuffer(EVP_MAX_KEY_LENGTH);
    iv = SecureBuffer(static_cast<size_t>(EVP_CIPHER_iv_length(symmetric_cipher)));

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
    iv = SecureBuffer(static_cast<size_t>(EVP_CIPHER_iv_length(symmetric_cipher)));

    //Derive aes key from secret. EVP_ByteTokey() is used to derive key from password,
    //the security of using it on secret is not clear
    if (0 == EVP_BytesToKey(symmetric_cipher, EVP_sha256(), NULL, secret.get(),
                            static_cast<int>(secret.size()), 1, key.get(), iv.get()))
        throw CryptoException();
}


int64_t SymmetricCryptor::encrypt_file(CryptoIO &dst, CryptoIO &src, function<bool(int64_t)> callback)
{
    return cipher_file(dst, src, callback, ENCRYPTION);
}


//Almost the same as encryption
int64_t SymmetricCryptor::decrypt_file(CryptoIO &dst, CryptoIO &src, function<bool(int64_t)> callback)
{
    return cipher_file(dst, src, callback, DECRYPTION);
}

int64_t SymmetricCryptor::cipher_file(CryptoIO &dst, CryptoIO &src,
                                      std::function<bool (int64_t)> callback, int enc)
{
    //Buffer to place read data
    auto in_buf = SecureBuffer(kMaxInBufferSize);

    //Buffer to place data to be written
    auto out_buf = SecureBuffer(kMaxOutBufferSize);

    //Data length of every EVP_EncryptUpdate() call
    auto block_len = 0;

    //Total data length write
    int64_t dst_len = 0;

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher */
    if (1 != EVP_CipherInit_ex(ctx.get(), symmetric_cipher, NULL, key.get(), iv.get(), enc))
        throw CryptoException();

    //Work until EOF
    while (!src.eof())
    {
         //Read kMaxInBufferSize data from src file
        auto src_len = src.read(in_buf.get(), 1, kMaxInBufferSize);
        if (1 != EVP_CipherUpdate(ctx.get(), out_buf.get(),
                                   &block_len, in_buf.get(), static_cast<int>(src_len)))
            throw CryptoException();

        //Write encrypted/decrypted data to file and sum up its len
        dst.write(out_buf.get(), 1, static_cast<size_t>(block_len));
        dst_len += block_len;

        //If asked to stop, then stop and return
        if (!callback(dst_len))
            return -1;
    }

    //Finalize this encryption/decryption
    if (1 != EVP_CipherFinal_ex(ctx.get(), out_buf.get(), &block_len))
        throw CryptoException();

    //Something may still need to be written
    if (block_len > 0)
    {
        dst.write(out_buf.get(), 1, static_cast<size_t>(block_len));
        dst_len += block_len;
    }
    if (!callback(dst_len))
        return -1;

    return dst_len;
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

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher */
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

    key = SecureBuffer(static_cast<size_t>(EVP_PKEY_size(priv.get())));

    src.read(&key_len, sizeof(key_len), 1);
    key.resize(static_cast<size_t>(key_len));

    src.read(key.get(), 1, static_cast<size_t>(key_len));
    src.read(iv.get(), 1, iv.size());

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

