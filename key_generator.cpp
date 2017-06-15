#include "key_generator.h"
#include "crypto_exception.h"
#include "c_exception.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <cerrno>
#include <QDebug>


using std::runtime_error;
using std::string;

EVP_PKEY_ptr KeyGenerator::get_key_pair()
{
    EVP_PKEY_CTX_ptr pctx;

    /* Create the context for parameter generation */
    pctx = EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new_id(NID_X25519, NULL), ::EVP_PKEY_CTX_free);

    /* Generate the key */
    if (1 != EVP_PKEY_keygen_init(pctx.get()))
        throw CryptoException();
    EVP_PKEY *tmp = NULL;
    auto ret = EVP_PKEY_keygen(pctx.get(), &tmp);
    if (ret != 1)
        throw CryptoException();

    return EVP_PKEY_ptr(tmp, ::EVP_PKEY_free);
}

EVP_PKEY_ptr KeyGenerator::get_rsa_key_pair()
{
    EVP_PKEY_CTX_ptr ctx;
    EVP_PKEY_ptr pkey;
    auto ret = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ret)
        throw CryptoException();
    ctx = EVP_PKEY_CTX_ptr(ret, ::EVP_PKEY_CTX_free);

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
        throw CryptoException();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) <= 0)
        throw CryptoException();

    /* Generate key */
    EVP_PKEY *tmp = NULL;
    if (EVP_PKEY_keygen(ctx.get(), &tmp) != 1)
        throw CryptoException();
    return EVP_PKEY_ptr(tmp, ::EVP_PKEY_free);
}

SecureBuffer KeyGenerator::get_secret(const EVP_PKEY_ptr pkey,
                                      const EVP_PKEY_ptr peerkey)
{
    EVP_PKEY_CTX_ptr ctx;
    SecureBuffer secret;
    size_t secret_len;
    /* Create the context for the shared secret derivation */
    ctx = EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new(pkey.get(), NULL), ::EVP_PKEY_CTX_free);

    /* Initialise */
    if (1 != EVP_PKEY_derive_init(ctx.get()))
        throw CryptoException();

    /* Provide the peer public key */
    if (1 != EVP_PKEY_derive_set_peer(ctx.get(), peerkey.get()))
        throw CryptoException();

    /* Determine buffer length for shared secret */
    if (1 != EVP_PKEY_derive(ctx.get(), NULL, &secret_len))
        throw CryptoException();

    /* Create the buffer */
    secret = SecureBuffer(secret_len);

    /* Derive the shared secret */
    if (1 != (EVP_PKEY_derive(ctx.get(), secret.get(), &secret_len)))
        throw CryptoException();

    /* Never use a derived secret directly. Typically it is passed
    * through some hash function to produce a key */
    return secret;
}

bool KeyGenerator::save_private_key(const string &private_path, const EVP_PKEY_ptr private_key,
                                    SecureBuffer &password)
{
    FILE *private_fp = NULL;

    //Open file for writing pem private key
    private_fp = fopen(private_path.c_str(), "w");
    if (!private_fp)
        throw CException();

    if (!PEM_write_PrivateKey(private_fp, private_key.get(), EVP_aes_256_cbc(), password.get(),
                              static_cast<int>(password.size()), NULL, NULL))
    {
        fclose(private_fp);
        throw CryptoException();
    }
    fclose(private_fp);
    return true;
}

bool KeyGenerator::save_public_key(const string &public_path, const EVP_PKEY_ptr public_key)
{
    FILE *public_fp = NULL;

    //Open file for writing pem public key
    public_fp = fopen(public_path.c_str(), "w");
    if (!public_fp)
        throw CException();

    if (!PEM_write_PUBKEY(public_fp, public_key.get()))
    {
        fclose(public_fp);
        throw CryptoException();
    }
    fclose(public_fp);
    return true;
}
