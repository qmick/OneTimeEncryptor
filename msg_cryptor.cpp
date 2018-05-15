#include "msg_cryptor.h"
#include "crypto_exception.h"

MsgCryptor::MsgCryptor()
{

}

void MsgCryptor::set_pubkey(const EVP_PKEY_ptr key)
{
    pubkey = key;
}

const EVP_PKEY_ptr MsgCryptor::get_pubkey() const
{
    return pubkey;
}

void MsgCryptor::set_private_key(const EVP_PKEY_ptr key)
{
    private_key = key;
}

const EVP_PEKY_ptr MsgCryptor::get_private_key() const
{
    return private_key;
}

std::vector<byte> MsgCryptor::encrypt(const std::vector<byte> &in, const std::string &cipher_name)
{
    if (in.size() < 1)
        return std::vector<byte>();
    auto cipher = EVP_get_cipherbyname(cipher_name.c_str());

    if (!cipher)
        throw runtime_error("not a valid cipher name");
    int32_t cipher_nid = EVP_CIPHER_nid(cipher);

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    if (key_type == EVP_PKEY_RSA)
    {
        SecureBuffer key = SecureBuffer(static_cast<size_t>(EVP_PKEY_size(pubkey.get())));
        SecureBuffer iv = SecureBuffer(static_cast<size_t>(EVP_CIPHER_iv_length(cipher)));
        int key_len;
        if (1 != EVP_SealInit(ctx.get(), cipher, &key.get(), &key_len, iv.get(), &pubkey.get(), 1))
            throw CryptoException();
        key.resize(static_cast<size_t>(key_len));

        const int block_size = evp_cipher_block_size(cipher);
        std::vector<byte> out(sizeof(int32_t) + key.size() + iv.size() + in.size() + block_size - 1 + block_size);
        int ptr = 0;

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
        if (1 != EVP_SealUpdate(ctx.get(), &out[ptr], &out_len, &in[0], static_cast<int>(in.size())))
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
        throw CryptoException();
    }
}

std::vector<byte> MsgCryptor::decrypt(const std::vector<byte> &in, const std::string &cipher_name)
{

}
