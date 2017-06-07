#include "decryptor.h"
#include "crypto_exception.h"
#include "key_generator.h"
#include "cryptor.h"
#include <openssl/evp.h>
#include <openssl/pem.h>

using std::runtime_error;
static const std::string crypt_sign = "[encrypted]";

Decryptor::Decryptor(const std::string &master_prikey_pem)
{
    shared_ptr<FILE> prikey_fp;

    //Open pem file that contains master private ec key
    FILE *tmp;
    if (fopen_s(&tmp, master_prikey_pem.c_str(), "r") != 0)
        throw CryptoException();
    prikey_fp = shared_ptr<FILE>(tmp, ::fclose);

    //Read master private key from file
    auto ret = PEM_read_PrivateKey(prikey_fp.get(), NULL, NULL, NULL);
    if (ret == NULL)
        throw CryptoException();
    master_key = EVP_PKEY_free_ptr(ret, ::EVP_PKEY_free);
}

long Decryptor::decrypt_file(const std::string &filename)
{
    std::string decrypted_filename = filename.substr(0, filename.length() - crypt_sign.length());
    EVP_PKEY_free_ptr pub_key;
    size_t secret_len;
    SecureBuffer secret;
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    shared_ptr<FILE> cipher_fp, decrypted_fp;

    FILE *tmp;
    if (fopen_s(&tmp, filename.c_str(), "r") != 0)
        throw runtime_error(filename + ": cannot open");
    cipher_fp = shared_ptr<FILE>(tmp, ::fclose);

    if (remove(decrypted_filename.c_str()) != 0)
        throw runtime_error(decrypted_filename + ": cannot remove");

    if (fopen_s(&tmp, decrypted_filename.c_str(), "ab") != 0)
        throw runtime_error(decrypted_filename + ": cannot open");
    decrypted_fp = shared_ptr<FILE>(tmp, ::fclose);

    auto ret = PEM_read_PUBKEY(cipher_fp.get(), NULL, NULL, NULL);
    if (ret == NULL)
        throw CryptoException();
    pub_key = EVP_PKEY_free_ptr(ret, ::EVP_PKEY_free);
    secret = KeyGenerator::get_secret(master_key, pub_key);
    Cryptor cryptor(secret);

    //Print for debugging
    for (int i = 0; i < secret_len; i++)
        printf("0x%x ", secret[i]);
    printf("\n\n");


    return cryptor.decrypt_file(decrypted_fp.get(), cipher_fp.get());

}
