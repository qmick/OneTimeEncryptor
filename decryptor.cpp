#include "decryptor.h"
#include "crypto_exception.h"
#include "crypto_io.h"
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
    //Open pem file that contains master private ec key
    CryptoIO in(master_prikey_pem, "r");

    //Read master private key from file
    auto ret = PEM_read_PrivateKey(in.get(), NULL, NULL, password.get());
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

    unique_ptr<SymmetricCryptor> cryptor;

    //Decrypted data size
    int64_t plaintext_len = 0;

    //Open encrypted file
    CryptoIO src(filename, "rb");

    //Open decrypted file for writting(append)
    CryptoIO dst(plain_filename, "wb");

    auto key_type = EVP_PKEY_id(master_key.get());
    if (key_type == EVP_PKEY_RSA)
    {
        cryptor = make_unique<SymmetricCryptor>();

        try
        {
            plaintext_len = cryptor->open_file(dst, src, master_key, callback);
        }
        catch (exception &)
        {
            dst.remove();
            throw;
        }
    }
    else if (key_type == EVP_PKEY_EC || key_type == NID_X25519)
    {
        //Read session public key from header of encrypted file
        auto ret = PEM_read_PUBKEY(src.get(), NULL, NULL, NULL);
        if (!ret)
            throw CryptoException();
        pub_key = EVP_PKEY_ptr(ret, ::EVP_PKEY_free);

        //ECDH
        secret = KeyGenerator::get_secret(master_key, pub_key);

        //Initialize AES256 decryptor
        cryptor = make_unique<SymmetricCryptor>(secret);

        try
        {
            plaintext_len = cryptor->decrypt_file(dst, src, callback);
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

    //Stop manually, remove incomplete decrypted file
    if (plaintext_len < 0)
    {
        dst.remove();
    }

    return plaintext_len;
}

EVP_PKEY_ptr Decryptor::get_key()
{
    return master_key;
}
