#include "encryptor.h"
#include "symmetric_cryptor.h"
#include "key_generator.h"
#include "crypto_exception.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

using std::string;
using std::shared_ptr;
using std::runtime_error;
static const string crypt_sign = "[encrypted]";

Encryptor::Encryptor(const string &master_pubkey_pem)
{
    shared_ptr<FILE> pubkey_fp;

    //Open pem file that contains master private ec key
    FILE *tmp;
    if (fopen_s(&tmp, master_pubkey_pem.c_str(), "r") != 0)
        throw runtime_error("cannot open private key file");
    pubkey_fp = shared_ptr<FILE>(tmp, ::fclose);

    //Read master private key from file
    auto ret = PEM_read_PUBKEY(pubkey_fp.get(), NULL, NULL, NULL);
    if (ret == NULL)
        throw CryptoException();
    master_key = EVP_PKEY_ptr(ret, ::EVP_PKEY_free);
}

Encryptor::~Encryptor()
{

}


long long Encryptor::crypt_file(const string &filename, std::function<bool(long long)> callback)
{
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    FILE *plain_fp = NULL, *cipher_fp = NULL;
    string cipher_filename = filename + crypt_sign;
    long long ciphertext_len = 0;

    //ECDH
    auto key_pair = KeyGenerator::get_key_pair();
    auto secret = KeyGenerator::get_secret(key_pair, master_key);
    SymmetricCryptor cryptor(secret);

    //Open source file for reading
    if (fopen_s(&plain_fp, filename.c_str(), "rb") != 0)
        throw runtime_error(filename + ": cannot be opened.\n");

    //If dst file exist, remove it
    remove(cipher_filename.c_str());

    //Open dst file for writing
    if (fopen_s(&cipher_fp, cipher_filename.c_str(), "ab") != 0)
    {
        fclose(plain_fp);
        throw runtime_error(cipher_filename + "%s cannot be opened");
    }

    //Write session publick key to file header
    if (!PEM_write_PUBKEY(cipher_fp, key_pair.get()))
    {
        fclose(plain_fp);
        fclose(cipher_fp);
        remove(cipher_filename.c_str());
        throw runtime_error(cipher_filename + ": error writing pubkey");
    }

    try
    {
        ciphertext_len = cryptor.encrypt_file(cipher_fp, plain_fp, callback);

        //Stop manually, remove incomplete encrypted file
        if (ciphertext_len < 0)
        {
            fclose(cipher_fp);
            cipher_fp = NULL;
            remove(cipher_filename.c_str());
        }
    }
    catch (std::exception &e)
    {
        fclose(plain_fp);
        fclose(cipher_fp);
        remove(cipher_filename.c_str());
        throw e;
    }

    fclose(plain_fp);
    if (cipher_fp)
        fclose(cipher_fp);

    return ciphertext_len;
}

EVP_PKEY_ptr Encryptor::get_key()
{
    return master_key;
}


