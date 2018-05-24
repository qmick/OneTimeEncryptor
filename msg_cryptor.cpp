#include "msg_cryptor.h"
#include "crypto_exception.h"
#include <exception>
#include <openssl/evp.h>
#include <cstring>

MsgCryptor::MsgCryptor()
{
}

void MsgCryptor::set_pubkey(EVP_PKEY_ptr &key)
{
    pubkey = key;
    key_type = EVP_PKEY_id(pubkey.get());
}

void MsgCryptor::set_private_key(EVP_PKEY_ptr &key)
{
    private_key = key;
    key_type = EVP_PKEY_id(private_key.get());
}

std::vector<byte> MsgCryptor::encrypt(const std::vector<byte> &in, const std::string &cipher_name)
{
    if (!pubkey)
        throw std::runtime_error("public key not set");
    if (in.size() < 1)
        return std::vector<byte>();
    auto cipher = EVP_get_cipherbyname(cipher_name.c_str());

    if (!cipher)
        throw std::runtime_error("not a valid cipher name");
    int32_t cipher_nid = EVP_CIPHER_nid(cipher);

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    if (key_type == EVP_PKEY_RSA)
    {
        SecureBuffer key = SecureBuffer(static_cast<size_t>(EVP_PKEY_size(pubkey.get())));
        SecureBuffer iv = SecureBuffer(static_cast<size_t>(EVP_CIPHER_iv_length(cipher)));
        int key_len;
        auto tmp_key = key.get();
        auto tmp_pubkey = pubkey.get();
        if (1 != EVP_SealInit(ctx.get(), cipher, &tmp_key, &key_len, iv.get(), &tmp_pubkey, 1))
            throw CryptoException();
        key.resize(static_cast<size_t>(key_len));

        const size_t block_size = EVP_CIPHER_block_size(cipher);
        std::vector<byte> out(sizeof(int32_t) + key.size() + iv.size() + in.size() + block_size - 1 + block_size);
        size_t ptr = 0;

        // Write cipher type id
        memcpy(&out[ptr], &cipher_nid, sizeof(int32_t));
        ptr += sizeof(int32_t);

        // Write key and iv
        memcpy(&out[ptr], key.get(), key.size());
        ptr += key.size();
        memcpy(&out[ptr], iv.get(), iv.size());
        ptr += iv.size();

        // Write cipher text
        int out_len;
        if (1 != EVP_SealUpdate(ctx.get(), &out[ptr], &out_len, &in[0], in.size()))
            throw CryptoException();
        ptr += out_len;

        // Write final block cipher
        int final_len;
        if (1 != EVP_SealFinal(ctx.get(), &out[ptr], &final_len))
            throw CryptoException();
        ptr += final_len;
        out.resize(ptr);
        return out;
    }
    else //if (key_type == EVP_PKEY_EC || key_type == NID_X25519)
    {
        throw std::invalid_argument("key type not supported");
    }
}

std::vector<byte> MsgCryptor::decrypt(const std::vector<byte> &in)
{
    if (!private_key)
        throw std::runtime_error("private key not set");
    if (in.size() < sizeof(int32_t))
        throw std::runtime_error("Not cipher message");
    size_t ptr = 0;

    // Read cipher type
    int32_t cipher_nid;
    memcpy(&cipher_nid, &in[ptr], sizeof(int32_t));
    ptr += sizeof(int32_t);

    auto cipher = EVP_get_cipherbynid(cipher_nid);
    if (!cipher)
        throw CryptoException();

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    if (key_type == EVP_PKEY_RSA)
    {
        // Read encrypted key
        SecureBuffer key = SecureBuffer(static_cast<size_t>(EVP_PKEY_size(private_key.get())));
        memcpy(key.get(), &in[ptr], key.size());
        ptr += key.size();

        // Read iv
        SecureBuffer iv = SecureBuffer(static_cast<size_t>(EVP_CIPHER_iv_length(cipher)));
        memcpy(iv.get(), &in[ptr], iv.size());
        ptr += iv.size();

        if (1 != EVP_OpenInit(ctx.get(), cipher, key.get(), key.size(), iv.get(), private_key.get()))
            throw CryptoException();

        std::vector<byte> out(in.size());

        // Write cipher text
        int out_len;
        if (1 != EVP_OpenUpdate(ctx.get(), &out[0], &out_len, &in[ptr], in.size() - ptr))
            throw CryptoException();

        // Write final block cipher
        int final_len;
        if (1 != EVP_OpenFinal(ctx.get(), &out[out_len], &final_len))
            throw CryptoException();
        out.resize(out_len + final_len);
        return out;
    }
    else //if (key_type == EVP_PKEY_EC || key_type == NID_X25519)
    {
        throw std::invalid_argument("key type not supported");
    }
}
