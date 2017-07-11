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
#include <botan/pipe.h>
#include <botan/cipher_filter.h>
#include <botan/data_snk.h>
#include <botan/data_src.h>
#include <botan/lookup.h>
#include <botan/secmem.h>
#include <vector>
#include <stdexcept>
#include <QtEndian>
#include <QDebug>

using std::string;
using std::unique_ptr;
using std::logic_error;
using std::runtime_error;
using std::vector;
using std::make_unique;
using std::function;

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
        in.must_read(&pubkey_size, sizeof(uint32_t), 1);
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

int64_t cipher_file(const Botan::SymmetricKey &secret, const Botan::KDF *kdf,
                    CryptoIO &src, CryptoIO &dst, function<bool (int64_t)> callback,
                    const string &cipher_name, Botan::Cipher_Dir direction)
{
    auto mode = Botan::get_cipher_mode(cipher_name, direction);
    auto cipher_filter = new Botan::Cipher_Mode_Filter(mode);

    auto key = kdf->derive_key(mode->key_spec().maximum_keylength(), secret.bits_of(), "key");
    cipher_filter->set_key(key);

    if (mode->default_nonce_length() > 0)
    {
        auto iv = kdf->derive_key(mode->default_nonce_length(), secret.bits_of(), "iv");
        cipher_filter->set_iv(iv);
    }

    Botan::secure_vector<uint8_t> buffer(1 << 16);
    Botan::Pipe pipe(cipher_filter);
    pipe.start_msg();

    int64_t total_len = 0;

    while (!src.eof())
    {
        auto len = src.read(buffer.data(), sizeof(uint8_t), buffer.size());
        pipe.write(buffer.data(), len);
        if (src.eof())
        {
            pipe.end_msg();
        }
        while (pipe.remaining() > 0)
        {
            const size_t buffered = pipe.read(buffer.data(), buffer.size());
            total_len += dst.write(buffer.data(), sizeof(uint8_t), buffered);
            if (!callback(total_len))
            {
                dst.remove();
                return -1;
            }
        }
    }

    return total_len;
}

AsymmetricCryptor::AsymmetricCryptor()
{
    kdf = unique_ptr<Botan::KDF>(Botan::get_kdf("KDF2(SHA-256)"));
}

AsymmetricCryptor::~AsymmetricCryptor()
{

}

void AsymmetricCryptor::gen_key()
{
    Botan::AutoSeeded_RNG rng;
    auto key = make_unique<Botan::Curve25519_PrivateKey>(rng);
    public_key  = make_unique<Botan::Curve25519_PublicKey>(key->public_value());
    private_key = move(key);
}

KeyPair AsymmetricCryptor::get_key(const std::string &passphrase)
{
    KeyPair key_pair;
    Botan::AutoSeeded_RNG rng;

    if (public_key)
    {
        key_pair.type = public_key->algo_name();
        key_pair.public_key = Botan::X509::PEM_encode(*public_key.get());
    }
    if (private_key)
    {
        key_pair.type = public_key->algo_name();
        key_pair.private_key = Botan::PKCS8::PEM_encode(*private_key.get(), rng, passphrase);
    }

    return key_pair;
}

std::string AsymmetricCryptor::key_type() const
{
    if (public_key)
        return public_key->algo_name();
    if (private_key)
        return private_key->algo_name();
    return "";
}

bool AsymmetricCryptor::has_pubkey() const
{
    return public_key != nullptr;
}

bool AsymmetricCryptor::has_prikey() const
{
    return private_key != nullptr;
}

void AsymmetricCryptor::load_public_key(const std::string &pubkey_file)
{
    public_key = unique_ptr<Botan::Public_Key>(Botan::X509::load_key(pubkey_file));
}

void AsymmetricCryptor::load_private_key(const std::string &prikey_file,
                                         const std::string &passphrase)
{
    Botan::AutoSeeded_RNG rng;
    auto ptr = Botan::PKCS8::load_key(prikey_file, rng, passphrase);
    private_key = unique_ptr<Botan::Private_Key>(ptr);
}

int64_t AsymmetricCryptor::encrypt(const std::string &src, const std::string &dst,
                                   std::function<bool (int64_t)> callback,
                                   const std::string &cipher_name) const
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

        CryptoIO in(src, "rb");
        CryptoIO out(dst, "wb");

        try
        {
            // Write header
            auto session_public = dynamic_cast<Botan::Public_Key*>(&session_key);
            CryptoHeader::write(session_public, cipher_name, out);

            return cipher_file(secret, kdf.get(), in, out, callback, cipher_name, Botan::ENCRYPTION);
        }
        catch (...)
        {
            out.remove();
            throw;
        }

    }
    else
        throw logic_error("unsupported public key type");
}

int64_t AsymmetricCryptor::decrypt(const std::string &src, const std::string &dst,
                                   std::function<bool (int64_t)> callback) const
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
        auto session_key = dynamic_cast<Botan::Curve25519_PublicKey*>(header.session_public.get());
        if (!session_key)
            throw runtime_error("invalid session public key");
        Botan::PK_Key_Agreement ecdh(*master_key, rng, "Raw");
        auto secret = ecdh.derive_key(32, session_key->public_value());

        try
        {
            return cipher_file(secret, kdf.get(), in, out, callback, header.cipher_name, Botan::DECRYPTION);
        }
        catch (...)
        {
            out.remove();
            throw;
        }
    }
    else
        throw logic_error("unsupported public key type");
}


