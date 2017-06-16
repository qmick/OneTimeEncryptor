#include "encryptor.h"
#include "symmetric_cryptor.h"
#include "key_generator.h"
#include "crypto_exception.h"
#include "c_exception.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <QDebug>


using std::string;
using std::runtime_error;
using std::exception;
using std::function;
using std::unique_ptr;
using std::make_unique;

Encryptor::Encryptor(const string &master_pubkey_pem)
{
    //Open pem file that contains master private ec key
    CryptoIO in(master_pubkey_pem, "r");

    //Read master private key from file
    auto ret = PEM_read_PUBKEY(in.get(), NULL, NULL, NULL);

    master_key = EVP_PKEY_ptr(ret, ::EVP_PKEY_free);
}

Encryptor::~Encryptor()
{

}


int64_t Encryptor::crypt_file(const string &filename, function<bool(int64_t)> callback)
{
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    string cipher_filename = filename + kCryptSign;
    int64_t ciphertext_len = 0;
    unique_ptr<SymmetricCryptor> cryptor;

    //Open source file for reading
    CryptoIO src(filename, "rb");

    //Open dst file for writing
    CryptoIO dst(cipher_filename, "wb");

    auto key_type = EVP_PKEY_id(master_key.get());
    if (key_type == EVP_PKEY_RSA)
    {
        cryptor = make_unique<SymmetricCryptor>();

        try
        {
            ciphertext_len = cryptor->seal_file(dst, src, master_key, callback);
        }
        catch (exception &)
        {
            dst.remove();
            throw;
        }
    }
    else if (key_type == EVP_PKEY_EC || key_type == NID_X25519)
    {
        //ECDH
        auto key_pair = KeyGenerator::get_key_pair();
        auto secret = KeyGenerator::get_secret(key_pair, master_key);
        cryptor = make_unique<SymmetricCryptor>(secret);

        //Write session publick key to file header
        if (!PEM_write_PUBKEY(dst.get(), key_pair.get()))
        {
            dst.remove();
            throw CryptoException();
        }

        try
        {
            ciphertext_len = cryptor->encrypt_file(dst, src, callback);
        }
        catch (exception &)
        {
            dst.remove();
            throw;
        }
    }
    else
    {
        dst.remove();
        throw runtime_error("not valid key type");
    }

    //Stop manually, remove incomplete encrypted file
    if (ciphertext_len < 0)
        dst.remove();

    return ciphertext_len;
}

EVP_PKEY_ptr Encryptor::get_key()
{
    return master_key;
}


