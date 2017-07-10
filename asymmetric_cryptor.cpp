#ifdef _MSC_VER
 #pragma warning(disable:4250)
#endif

#include "asymmetric_cryptor.h"
#include "crypto_io.h"
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/pk_keys.h>
#include <botan/auto_rng.h>
#include <botan/x509_key.h>
#include <botan/curve25519.h>
#include <botan/cipher_mode.h>
#include <botan/symkey.h>
#include <botan/aead.h>
#include <botan/data_src.h>
#include <vector>
#include <stdexcept>
#include <QtEndian>

using std::string;
using std::unique_ptr;
using std::logic_error;
using std::vector;

struct CryptoHeader
{
    static void write(const Botan::Public_Key *pubkey, const string &cipher_name, CryptoIO &out)
    {
        // Write session public key length
        auto session_public = Botan::X509::PEM_encode(*pubkey);
        uint32_t public_size = qToBigEndian(static_cast<uint32_t>(session_public.size() + 1));
        out.write(&public_size, sizeof(public_size), 1);

        // Write session public key
        out.write(session_public.c_str(), sizeof(char), session_public.size() + 1);

        // Write cipher name length
        uint8_t name_size = static_cast<uint8_t>(cipher_name.size() + 1);
        out.write(&name_size, sizeof(name_size), 1);

        // Write cipher name
        out.write(cipher_name.c_str(), sizeof(char), name_size);
    }

    static CryptoHeader read(CryptoIO &in)
    {
        CryptoHeader header;

        // Read public key size
        uint32_t pubkey_size;
        in.must_read(&pubkey_size, 4, 1);
        pubkey_size = qFromBigEndian(pubkey_size);

        // Read public key
        vector<char> buf(pubkey_size);
        in.must_read(buf.data(), sizeof(char), pubkey_size);
        Botan::DataSource_Memory ds(string(buf.data()));
        header.session_public = unique_ptr<Botan::Public_Key>(Botan::X509::load_key(ds));

        // Read cipher name length
        uint8_t name_size;
        in.must_read(&name_size, sizeof(name_size), 1);
        buf.resize(name_size);

        // Read cipher name
        in.read(buf.data(), sizeof(char), buf.size());
        header.cipher_name = string(buf.data());

        return header;
    }

    unique_ptr<Botan::Public_Key> session_public;
    string cipher_name;
};


AsymmetricCryptor::AsymmetricCryptor()
{
    kdf = unique_ptr<Botan::KDF>(Botan::get_kdf("KDF2(SHA-256)"));
}

AsymmetricCryptor::~AsymmetricCryptor()
{

}

std::string AsymmetricCryptor::key_type() const
{
    if (public_key)
        return public_key->algo_name();
    if (private_key)
        return private_key->algo_name();
    return "";
}

void AsymmetricCryptor::load_public_key(const std::string &pubkey_file)
{
    public_key = unique_ptr<Botan::Public_Key>(Botan::X509::load_key(pubkey_file));
}

void AsymmetricCryptor::load_private_key(const std::string &prikey_file,
                                         const std::string &passphrase)
{
    Botan::AutoSeeded_RNG rng;
    private_key = unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(prikey_file, rng, passphrase));
}

int64_t AsymmetricCryptor::encrypt(const std::string &src, const std::string &dst,
                                   std::function<bool (int64_t)> callback,
                                   const std::string &cipher_name)
{
    if (!public_key)
        throw logic_error("public key not loaded");

    if (public_key->algo_name() == "Curve25519")
    {
        Botan::AutoSeeded_RNG rng;
        auto master_key = dynamic_cast<Botan::Curve25519_PublicKey*>(public_key.get());
        Botan::Curve25519_PrivateKey session_key(rng);
        Botan::PK_Key_Agreement ecdh(session_key, rng, "Raw");
        auto secret = ecdh.derive_key(32, master_key->public_value());

        auto enc = unique_ptr<Botan::Cipher_Mode>(Botan::get_cipher_mode(cipher_name, Botan::ENCRYPTION));
        auto key = kdf->derive_key(enc->key_spec().maximum_keylength(), secret.bits_of(), "key");
        auto  iv = kdf->derive_key(enc->default_nonce_length(), secret.bits_of(), "iv");
        enc->set_key(key);
        enc->start(iv);

        size_t buf_size = enc->update_granularity() == 1 ? 1 << 16 : enc->update_granularity() << 12;
        Botan::secure_vector<uint8_t> buf(buf_size);
        Botan::secure_vector<uint8_t> final_block(enc->minimum_final_size());

        CryptoIO in(src, "rb");
        CryptoIO out(dst, "wb");

        int64_t total_len = 0;

        try
        {
            // Write header
            auto session_public = dynamic_cast<Botan::Public_Key*>(&session_key);
            CryptoHeader::write(session_public, cipher_name, out);

            while (!in.eof())
            {
                in.read(buf.data(), sizeof(uint8_t), buf.size());
                enc->update(buf);
                total_len += out.write(buf.data(), sizeof(uint8_t), buf.size());
                if (!callback(total_len))
                {
                    out.remove();
                    return -1;
                }
            }

            enc->finish(final_block);
            out.write(final_block.data(), sizeof(uint8_t), final_block.size());
        }
        catch (...)
        {
            out.remove();
            throw;
        }

        return total_len;
    }
    else
        throw logic_error("unsupported public key type");
}

int64_t AsymmetricCryptor::decrypt(const std::string &src, const std::string &dst,
                                   std::function<bool (int64_t)> callback)
{
    if (!private_key)
        throw logic_error("public key not loaded");

    if (private_key->algo_name() == "Curve25519")
    {
        Botan::AutoSeeded_RNG rng;
        auto master_key = dynamic_cast<Botan::Curve25519_PrivateKey*>(private_key.get());

        CryptoIO in(src, "rb");
        CryptoIO out(dst, "wb");

        auto header = CryptoHeader::read(in);

        auto session_key = dynamic_cast<Botan::Curve25519_PrivateKey*>(header.session_public.get());
        Botan::PK_Key_Agreement ecdh(*master_key, rng, "Raw");
        auto secret = ecdh.derive_key(32, session_key->public_value());

        auto dec = unique_ptr<Botan::Cipher_Mode>(Botan::get_cipher_mode(header.cipher_name, Botan::DECRYPTION));
        auto key = kdf->derive_key(dec->key_spec().maximum_keylength(), secret.bits_of(), "key");
        auto  iv = kdf->derive_key(dec->default_nonce_length(), secret.bits_of(), "iv");
        dec->set_key(key);
        dec->start(iv);

        size_t buf_size = dec->update_granularity() == 1 ? 1 << 16 : dec->update_granularity() << 12;
        Botan::secure_vector<uint8_t> buf(buf_size);
        Botan::secure_vector<uint8_t> final_block(dec->minimum_final_size());
        int64_t total_len = 0;

        try
        {
            while (!in.eof())
            {
                in.read(buf.data(), sizeof(uint8_t), buf.size());
                dec->update(buf);
                total_len += out.write(buf.data(), sizeof(uint8_t), buf.size());
                if (!callback(total_len))
                {
                    out.remove();
                    return -1;
                }
            }

            dec->finish(final_block);
            out.write(final_block.data(), sizeof(uint8_t), final_block.size());
        }
        catch (...)
        {
            out.remove();
            throw;
        }
        return total_len;
    }
    else
        throw logic_error("unsupported public key type");
}
