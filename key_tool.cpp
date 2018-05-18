#include "key_tool.h"
#include "crypto_exception.h"
#include "c_exception.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <cerrno>
#include <QDebug>


using std::runtime_error;
using std::string;
using std::vector;

EVP_PKEY_ptr KeyTool::get_key_pair(const string &type)
{
    if (type == "ECC")
        return get_key_pair();
    else if (type == "RSA")
        return get_rsa_key_pair();
    else
        throw runtime_error("Unsupported key type");
}

EVP_PKEY_ptr KeyTool::get_key_pair()
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

EVP_PKEY_ptr KeyTool::get_rsa_key_pair()
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

SecureBuffer KeyTool::get_secret(const EVP_PKEY_ptr &pkey,
                                      const EVP_PKEY_ptr &peerkey)
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

string KeyTool::get_private_key_pem(const EVP_PKEY_ptr &private_key,
                                    SecureBuffer &password)
{
    BIO_MEM_ptr bio(BIO_new(BIO_s_mem()), ::BIO_free);

    if (!PEM_write_bio_PrivateKey(bio.get(), private_key.get(), EVP_aes_256_cbc(), password.get(),
                              static_cast<int>(password.size()), NULL, NULL))
        throw CryptoException();
    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(bio.get(), &mem);
    if (!mem || !mem->data || !mem->length)
        throw CryptoException();
    return string(mem->data, mem->length);
}

string KeyTool::get_pubkey_pem(const EVP_PKEY_ptr &public_key)
{
    BIO_MEM_ptr bio(BIO_new(BIO_s_mem()), ::BIO_free);


    if (!PEM_write_bio_PUBKEY(bio.get(), public_key.get()))
        throw CryptoException();

    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(bio.get(), &mem);
    if (!mem || !mem->data || !mem->length)
        throw CryptoException();
    return string(mem->data, mem->length);
}

EVP_PKEY_ptr KeyTool::get_pubkey(const std::string &pem)
{
    BIO_MEM_ptr bio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_write(bio.get(), pubkey_pem.c_str(), pubkey_pem.size());

    auto ret = PEM_read_bio_PUBKEY(bio.get(), NULL, 0, 0);

    if (!ret)
        throw CryptoException();
    return EVP_PKEY_ptr(ret, ::EVP_PKEY_free);
}

EVP_PKEY_ptr KeyTool::get_private_key(const std::string &pem, const SecureBuffer &password)
{
    BIO_MEM_ptr bio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_write(bio.get(), pem.data(), pem.size());
    EVP_PKEY *ret = PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, password.get());

    if (!ret)
        throw CryptoException();

    retur EVP_PKEY_ptr(ret, ::EVP_PKEY_free);;
}

vector<byte> KeyTool::get_digest(const std::string &content, const std::string &type)
{
    EVP_MD_CTX_ptr mdctx(EVP_MD_CTX_new(), ::EVP_MD_CTX_free);
    const EVP_MD *md = EVP_get_digestbyname(type.c_str());
    if (!md)
        throw runtime_error("No such digest algorithm");
    EVP_DigestInit_ex(mdctx.get(), md, NULL);
    EVP_DigestUpdate(mdctx.get(), content.c_str(), content.size());
    unsigned int md_len;
    vector<byte> md_value(EVP_MAX_MD_SIZE);
    EVP_DigestFinal_ex(mdctx.get(), &md_value[0], &md_len);
    md_value.resize(md_len);
    return md_value;
}
