#include "key_generator.h"
#include "crypto_exception.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>


EVP_PKEY_free_ptr KeyGenerator::get_key_pair()
{
    EVP_PKEY_free_ptr key_pair, params;
    EVP_PKEY_CTX_free_ptr pctx, kctx;

    /* Create the context for parameter generation */
    pctx = EVP_PKEY_CTX_free_ptr(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), ::EVP_PKEY_CTX_free);

    /* Initialise the parameter generation */
    if (1 != EVP_PKEY_paramgen_init(pctx.get()))
        throw CryptoException();

    /* We're going to use the ANSI X9.62 Prime 256v1 curve */
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1))
        throw CryptoException();

    /* Create the parameter object params */
    EVP_PKEY *params_p = NULL;
    EVP_PKEY_paramgen(pctx.get(), &params_p);
    params = EVP_PKEY_free_ptr(params_p, ::EVP_PKEY_free);

    /* Create the context for the key generation */
    kctx = EVP_PKEY_CTX_free_ptr(EVP_PKEY_CTX_new(params.get(), NULL), ::EVP_PKEY_CTX_free);

    /* Generate the key */
    EVP_PKEY *key_pair_p = NULL;
    if (1 != EVP_PKEY_keygen_init(kctx.get()))
        throw CryptoException();
    auto ret = EVP_PKEY_keygen(kctx.get(), &key_pair_p);
    key_pair = EVP_PKEY_free_ptr(key_pair_p, ::EVP_PKEY_free);
    if (ret != 1)
        throw CryptoException();

    return key_pair;
}

SecureBuffer KeyGenerator::get_secret(const EVP_PKEY_free_ptr pkey,
                                      const EVP_PKEY_free_ptr peerkey)
{
    EVP_PKEY_CTX_free_ptr ctx;
    SecureBuffer secret;
    size_t secret_len;
    /* Create the context for the shared secret derivation */
    ctx = EVP_PKEY_CTX_free_ptr(EVP_PKEY_CTX_new(pkey.get(), NULL), ::EVP_PKEY_CTX_free);

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

bool KeyGenerator::save_key_pair(FILE *dst_public, FILE *dst_private,
                                 const EVP_PKEY_free_ptr key_pair, SecureBuffer &password)
{
    if (!PEM_write_PrivateKey(dst_private, key_pair.get(), EVP_aes_128_cbc(), password.get(),
                              static_cast<int>(password.size()), NULL, NULL))
        throw CryptoException();

    if (!PEM_write_PUBKEY(dst_public, key_pair.get()))
        throw CryptoException();

    return true;
}

