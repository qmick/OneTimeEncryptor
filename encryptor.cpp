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

using std::string;
using std::runtime_error;
using std::exception;
using std::function;

Encryptor::Encryptor(const string &master_pubkey_pem)
{
    FILE *pubkey_fp;

    //Open pem file that contains master private ec key
    pubkey_fp = fopen(master_pubkey_pem.c_str(), "r");
    if (!pubkey_fp)
        throw CException("cannot open private key file: ");

    //Read master private key from file
    auto ret = PEM_read_PUBKEY(pubkey_fp, NULL, NULL, NULL);
    fclose(pubkey_fp);
    if (ret == NULL)
        throw CryptoException();

    master_key = EVP_PKEY_ptr(ret, ::EVP_PKEY_free);
}

Encryptor::~Encryptor()
{

}


long long Encryptor::crypt_file(const string &filename, function<bool(long long)> callback)
{
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    FILE *plain_fp = NULL, *cipher_fp = NULL;
    string cipher_filename = filename + kCryptSign;
    long long ciphertext_len = 0;

    //ECDH
    auto key_pair = KeyGenerator::get_key_pair();
    auto secret = KeyGenerator::get_secret(key_pair, master_key);
    SymmetricCryptor cryptor(secret);

    //Open source file for reading
    plain_fp = fopen(filename.c_str(), "rb");
    if (!plain_fp)
        throw CException("cannot open: ");

    //Open dst file for writing
    cipher_fp = fopen(cipher_filename.c_str(), "wb");
    if (!cipher_fp)
    {
        fclose(plain_fp);
        throw CException("cannot open: ");
    }

    //Write session publick key to file header
    if (!PEM_write_PUBKEY(cipher_fp, key_pair.get()))
    {
        fclose(plain_fp);
        fclose(cipher_fp);
        remove(cipher_filename.c_str());
        throw CryptoException();
    }

    try
    {
        ciphertext_len = cryptor.encrypt_file(cipher_fp, plain_fp, callback);
    }
    catch (exception &e)
    {
        fclose(plain_fp);
        fclose(cipher_fp);
        remove(cipher_filename.c_str());
        throw e;
    }

    fclose(plain_fp);
    fclose(cipher_fp);

    //Stop manually, remove incomplete encrypted file
    if (ciphertext_len < 0)
        remove(cipher_filename.c_str());

    return ciphertext_len;
}

EVP_PKEY_ptr Encryptor::get_key()
{
    return master_key;
}


