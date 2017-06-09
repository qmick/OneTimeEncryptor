#include "decryptor.h"
#include "crypto_exception.h"
#include "key_generator.h"
#include "symmetric_cryptor.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cerrno>


using std::runtime_error;
static const std::string crypt_sign = "[encrypted]";

Decryptor::Decryptor(const std::string &master_prikey_pem, SecureBuffer &password)
{
    shared_ptr<FILE> prikey_fp;

    //Open pem file that contains master private ec key
    FILE *tmp;
    if (fopen_s(&tmp, master_prikey_pem.c_str(), "r") != 0)
        throw runtime_error("cannot open private key file");
    prikey_fp = shared_ptr<FILE>(tmp, ::fclose);

    //Read master private key from file
    auto ret = PEM_read_PrivateKey(prikey_fp.get(), NULL, NULL, password.get());
    if (ret == NULL)
        throw CryptoException();
    master_key = EVP_PKEY_free_ptr(ret, ::EVP_PKEY_free);
}

Decryptor::~Decryptor()
{

}

long long Decryptor::crypt_file(const std::string &filename, std::function<bool(long long)> callback)
{
    std::string plain_filename = filename.substr(0, filename.length() - crypt_sign.length());
    EVP_PKEY_free_ptr pub_key;
    SecureBuffer secret;
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    FILE *cipher_fp = NULL, *plain_fp = NULL;
    long long plaintext_len = 0;

    if (fopen_s(&cipher_fp, filename.c_str(), "r") != 0)
        throw runtime_error(filename + ": cannot open");

    if (remove(plain_filename.c_str()) != 0)
    {
        if (errno != ENOENT)
        {
            fclose(cipher_fp);
            throw runtime_error(plain_filename + ": cannot remove");
        }
    }

    if (fopen_s(&plain_fp, plain_filename.c_str(), "ab") != 0)
    {
        fclose(cipher_fp);
        throw runtime_error(plain_filename + ": cannot open");
    }

    auto ret = PEM_read_PUBKEY(cipher_fp, NULL, NULL, NULL);
    if (ret == NULL)
    {
        fclose(cipher_fp);
        fclose(plain_fp);
        throw CryptoException();
    }

    pub_key = EVP_PKEY_free_ptr(ret, ::EVP_PKEY_free);
    secret = KeyGenerator::get_secret(master_key, pub_key);
    SymmetricCryptor cryptor(secret);

    try
    {
        plaintext_len = cryptor.decrypt_file(plain_fp, cipher_fp, callback);
        if (plaintext_len < 0)
        {
            fclose(plain_fp);
            plain_fp = NULL;
            remove(plain_filename.c_str());
        }
    }
    catch (std::exception &e)
    {
        fclose(plain_fp);
        fclose(cipher_fp);
        remove(plain_filename.c_str());
        throw e;
    }

    fclose(cipher_fp);
    if (plain_fp)
        fclose(plain_fp);

    return plaintext_len;
}
