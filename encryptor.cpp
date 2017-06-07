#include "encryptor.h"
#include "cryptor.h"
#include "key_generator.h"
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

Encryptor::Encryptor(const secure_string &master_pubkey_str)
{
    BIO *bufio;
    bufio = BIO_new_mem_buf(static_cast<const void*>(master_pubkey_str.c_str()),
                            static_cast<int>(master_pubkey_str.size()));
    master_key = EVP_PKEY_free_ptr(PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL), ::EVP_PKEY_free);
    BIO_set_close(bufio, BIO_CLOSE);
    BIO_free(bufio);
}


long Encryptor::encrypt_file(const string &filename)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    shared_ptr<FILE> rfp = nullptr, wfp = nullptr;
    string encrypted_filename = filename + crypt_sign;
    long ciphertext_len = 0;

    //ECDH
    auto key_pair = KeyGenerator::get_key_pair();
    auto secret = KeyGenerator::get_secret(key_pair, master_key);
    Cryptor cryptor(secret);

    //Print for debugging
    for (int i = 0; i < secret.size(); i++)
        printf("0x%x ", secret[i]);
    printf("\n\n");

    //Open source file for reading
    FILE *tmp;
    if (fopen_s(&tmp, filename.c_str(), "rb") != 0)
        throw runtime_error(filename + ": cannot be opened.\n");
    rfp = shared_ptr<FILE>(tmp, ::fclose);

    //If dst file exist, remove it
    remove(encrypted_filename.c_str());

    //Open dst file for writing
    if (fopen_s(&tmp, encrypted_filename.c_str(), "ab") != 0)
        throw runtime_error(encrypted_filename + "%s cannot be opened");
    wfp = shared_ptr<FILE>(tmp, ::fclose);

    if (!PEM_write_PUBKEY(wfp.get(), key_pair.get()))
    {
        remove(encrypted_filename.c_str());
        throw runtime_error(encrypted_filename + ": error writing pubkey");
    }

    ciphertext_len = cryptor.encrypt_file(wfp.get(), rfp.get());

    return ciphertext_len;
}


