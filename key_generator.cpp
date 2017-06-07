#include "key_generator.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>

key_generator::key_generator()
{

}


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


EVP_PKEY *key_generator::get_key_pair()
{
    EVP_PKEY_CTX *pctx, *kctx;
    EVP_PKEY *pkey = NULL, *params = NULL;

    /* Create the context for parameter generation */
    if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) handleErrors();

    /* Initialise the parameter generation */
    if (1 != EVP_PKEY_paramgen_init(pctx)) handleErrors();

    /* We're going to use the ANSI X9.62 Prime 256v1 curve */
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X25519)) handleErrors();

    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &params)) handleErrors();

    /* Create the context for the key generation */
    if (NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) handleErrors();

    /* Generate the key */
    if (1 != EVP_PKEY_keygen_init(kctx)) handleErrors();
    if (1 != EVP_PKEY_keygen(kctx, &pkey)) handleErrors();

    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);

    return pkey;
}

byte *key_generator::get_secret(EVP_PKEY *pkey, EVP_PKEY *peerkey, size_t *secret_len)
{
    EVP_PKEY_CTX *ctx;
    unsigned char *secret;

    /* Create the context for the shared secret derivation */
    if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))
        handleErrors();

    /* Initialise */
    if (1 != EVP_PKEY_derive_init(ctx))
        handleErrors();

    /* Provide the peer public key */
    if (1 != EVP_PKEY_derive_set_peer(ctx, peerkey))
        handleErrors();

    /* Determine buffer length for shared secret */
    if (1 != EVP_PKEY_derive(ctx, NULL, secret_len))
        handleErrors();

    /* Create the buffer */
    if (NULL == (secret = (unsigned char *)OPENSSL_malloc(*secret_len)))
        handleErrors();

    /* Derive the shared secret */
    if (1 != (EVP_PKEY_derive(ctx, secret, secret_len)))
        handleErrors();

    EVP_PKEY_CTX_free(ctx);

    /* Never use a derived secret directly. Typically it is passed
    * through some hash function to produce a key */
    return secret;
}
