#include "decryptor.h"
#include "crypto_exception.h"
#include "key_generator.h"
#include "symmetric_cryptor.h"
#include "c_exception.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cerrno>


using std::runtime_error;
using std::string;
using std::function;
using std::exception;

Decryptor::Decryptor(const string &master_prikey_pem, SecureBuffer &password)
{
    FILE *prikey_fp;

    //Open pem file that contains master private ec key
    prikey_fp = fopen(master_prikey_pem.c_str(), "r");
    if (!prikey_fp)
        throw CException("cannot open private key file");

    //Read master private key from file
    auto ret = PEM_read_PrivateKey(prikey_fp, NULL, NULL, password.get());
    fclose(prikey_fp);
    if (ret == NULL)
        throw CryptoException();

    master_key = EVP_PKEY_ptr(ret, ::EVP_PKEY_free);
}

Decryptor::~Decryptor()
{

}

long long Decryptor::crypt_file(const string &filename, function<bool(long long)> callback)
{
    //Decrypted file name
    string plain_filename = filename.substr(0, filename.length() - kCryptSign.length());

    //Session public key
    EVP_PKEY_ptr pub_key;

    //Secret from ECDH
    SecureBuffer secret;

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    FILE *cipher_fp = NULL, *plain_fp = NULL;

    //Decrypted data size
    long long plaintext_len = 0;

    //Open encrypted file
    cipher_fp = fopen(filename.c_str(), "rb");
    if (!cipher_fp)
        throw CException("cannot open: ");

    //Open decrypted file for writting(append)
    plain_fp = fopen(plain_filename.c_str(), "wb");
    if (!plain_fp)
    {
        fclose(cipher_fp);
        throw CException("cannot open: ");
    }

    //Read session public key from header of encrypted file
    auto ret = PEM_read_PUBKEY(cipher_fp, NULL, NULL, NULL);
    if (ret == NULL)
    {
        fclose(cipher_fp);
        fclose(plain_fp);
        throw CryptoException();
    }
    pub_key = EVP_PKEY_ptr(ret, ::EVP_PKEY_free);

    //ECDH
    secret = KeyGenerator::get_secret(master_key, pub_key);

    //Initialize AES256 decryptor
    SymmetricCryptor cryptor(secret);

    try
    {
        plaintext_len = cryptor.decrypt_file(plain_fp, cipher_fp, callback);
    }
    catch (exception &e)
    {
        fclose(plain_fp);
        fclose(cipher_fp);
        remove(plain_filename.c_str());
        throw e;
    }

    fclose(plain_fp);
    fclose(cipher_fp);

    //Stop manually, remove incomplete decrypted file
    if (plaintext_len < 0)
        remove(plain_filename.c_str());

    return plaintext_len;
}

EVP_PKEY_ptr Decryptor::get_key()
{
    return master_key;
}
