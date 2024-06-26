#include "encryptor.h"
#include "symmetric_cryptor.h"
#include "key_tool.h"
#include "crypto_exception.h"
#include "c_exception.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <QDebug>


using std::string;
using std::runtime_error;
using std::exception;
using std::function;
using std::unique_ptr;
using std::make_unique;

Encryptor::Encryptor(const string &pubkey_pem)
{
    master_key = KeyTool::get_pubkey(pubkey_pem);
    key_type = EVP_PKEY_id(master_key.get());
}

Encryptor::~Encryptor()
{

}


int64_t Encryptor::crypt_file(const string &filename,
                              function<bool(int64_t)> callback,
                              const std::string &cipher_name)
{
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    string cipher_filename = filename + kCryptSign;
    int64_t ciphertext_len = 0;
    int32_t file_key_type = key_type;
    int32_t cipher_nid;
    auto cipher = EVP_get_cipherbyname(cipher_name.c_str());

    if (!cipher)
        throw runtime_error("not a valid cipher name");
    cipher_nid = EVP_CIPHER_nid(cipher);

    unique_ptr<SymmetricCryptor> cryptor;

    //Open source file for reading
    CryptoIO src(filename, "rb");

    //Open dst file for writing
    CryptoIO dst(cipher_filename, "wb");

    dst.write(&file_key_type, sizeof(file_key_type), 1);
    dst.write(&cipher_nid, sizeof(cipher_nid), 1);

    if (key_type == EVP_PKEY_RSA)
    {
        cryptor = make_unique<SymmetricCryptor>(cipher);

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
        auto key_pair = KeyTool::get_key_pair();
        auto secret = KeyTool::get_secret(key_pair, master_key);
        cryptor = make_unique<SymmetricCryptor>(secret, cipher);

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


