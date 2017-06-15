#include "rsa_encryptor.h"
#include "key_generator.h"
#include "crypto_exception.h"
#include "c_exception.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <string>
#include <cstdio>

using std::string;

RSAEncryptor::RSAEncryptor(const string &master_pubkey_pem)
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


long long RSAEncryptor::crypt_file(const std::string &filename, std::function<bool (long long)> callback)
{
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    FILE *plain_fp = NULL, *cipher_fp = NULL;
    string cipher_filename = filename + kCryptSign;
    long long ciphertext_len = 0;

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


}

EVP_PKEY_ptr RSAEncryptor::get_key()
{
}
