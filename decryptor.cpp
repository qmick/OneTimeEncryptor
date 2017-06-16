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
using std::unique_ptr;
using std::make_unique;

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

int64_t Decryptor::crypt_file(const string &filename, function<bool(int64_t)> callback)
{
    //Decrypted file name
    string plain_filename = filename.substr(0, filename.length() - kCryptSign.length());

    //Session public key
    EVP_PKEY_ptr pub_key;

    //Secret from ECDH
    SecureBuffer secret;

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    FILE *cipher_fp = NULL, *plain_fp = NULL;

    unique_ptr<SymmetricCryptor> cryptor;
    //Decrypted data size
    int64_t plaintext_len = 0;

    //Open encrypted file
    cipher_fp = fopen(filename.c_str(), "rb");
    if (!cipher_fp)
        throw CException("cannot open");

    //Open decrypted file for writting(append)
    plain_fp = fopen(plain_filename.c_str(), "wb");
    if (!plain_fp)
    {
        fclose(cipher_fp);
        throw CException("cannot open");
    }

    auto key_type = EVP_PKEY_id(master_key.get());
    if (key_type == EVP_PKEY_RSA)
    {
        cryptor = make_unique<SymmetricCryptor>();

        try
        {
            plaintext_len = cryptor->open_file(plain_fp, cipher_fp, master_key, callback);
        }
        catch (exception &)
        {
            fclose(plain_fp);
            fclose(cipher_fp);
            remove(plain_filename.c_str());
            throw;
        }
    }
    else if (key_type == EVP_PKEY_EC || key_type == NID_X25519)
    {
        //Read session public key from header of encrypted file
        auto ret = PEM_read_PUBKEY(cipher_fp, NULL, NULL, NULL);
        if (!ret)
        {
            fclose(cipher_fp);
            fclose(plain_fp);
            throw CryptoException();
        }
        pub_key = EVP_PKEY_ptr(ret, ::EVP_PKEY_free);

        //ECDH
        secret = KeyGenerator::get_secret(master_key, pub_key);

        //Initialize AES256 decryptor
        cryptor = make_unique<SymmetricCryptor>(secret);

        try
        {
            plaintext_len = cryptor->decrypt_file(plain_fp, cipher_fp, callback);
        }
        catch (exception &)
        {
            fclose(plain_fp);
            fclose(cipher_fp);
            remove(plain_filename.c_str());
            throw;
        }
    }
    else
    {
        fclose(plain_fp);
        fclose(cipher_fp);
        remove(plain_filename.c_str());
        throw runtime_error("not valid key type");
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
