#include "encryptor.h"
#include "key_generator.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>


static const QString crypt_sign = "[encrypted]";

Encryptor::Encryptor(const QString &master_pubkey_str)
{
    BIO *bufio;
    bufio = BIO_new_mem_buf((void*)master_pubkey_str.toStdString().c_str(), master_pubkey_str.size());
    master_key = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
    BIO_set_close(bufio, BIO_CLOSE);
    BIO_free(bufio);
}


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}





size_t Encryptor::encrypt_file(const QString &filename)
{
    const size_t kMaxInBufferSize = 1024 * 1024;
    const size_t kMaxOutBufferSize = kMaxInBufferSize + 1024;
    size_t secret_len;
    byte key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    EVP_PKEY *key_pair;
    EVP_CIPHER_CTX *ctx;
    byte *secret;
    FILE *rfp = nullptr, *wfp = nullptr;
    byte *in_buf = nullptr, *out_buf = nullptr;
    QString encrypted_filename = filename + crypt_sign;
    int ciphertext_len = 0;
    int len;

    //ECDH
    key_pair = key_generator::get_key_pair();
    secret = key_generator::get_secret(key_pair, this->master_key, &secret_len);

    //Print for debugging
    for (int i = 0; i < secret_len; i++)
        printf("0x%x ", secret[i]);
    printf("\n\n");

    if (0 == EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), NULL, secret, secret_len, 1, key, iv))
        handleErrors();

    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    in_buf = (byte *)OPENSSL_malloc(kMaxInBufferSize);
    out_buf = (byte *)OPENSSL_malloc(kMaxOutBufferSize);

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    rfp = fopen(filename.c_str(), "rb");
    if (!rfp)
    {
        printf("%s cannot be opened.\n", filename.c_str());
        goto CLEAN;
    }
    remove(encrypted_filename.c_str());
    wfp = fopen(encrypted_filename.c_str(), "ab");
    if (!wfp)
    {
        printf("%s cannot be opened.\n", encrypted_filename.c_str());
        goto CLEAN;
    }

    if (!PEM_write_PUBKEY(wfp, key_pair))
    {
        printf("Error writing pubkey to %s\n.", encrypted_filename.c_str());
        ERR_print_errors_fp(stderr);
        if (0 != remove(encrypted_filename.c_str()))
            printf("Remove %s failed.\n", encrypted_filename.c_str());

        goto CLEAN;
    }

    while (!feof(rfp))
    {
        auto plaintext_len = fread(in_buf, 1, kMaxInBufferSize, rfp);
        if (ferror(rfp))
        {
            printf("%s cannot be read.\n", filename.c_str());
            goto CLEAN;
        }

        /* Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */

        EVP_EncryptUpdate(ctx, out_buf, &len, in_buf, plaintext_len);
        fwrite(out_buf, 1, len, wfp);
        if (ferror(wfp))
        {
            printf("%s cannot be write.\n", encrypted_filename.c_str());
            ciphertext_len = 0;
            remove(encrypted_filename.c_str());
            goto CLEAN;
        }
        ciphertext_len += len;
    }

    /* Finalise the encryption. Further ciphertext bytes may be written at
    * this stage.
    */
    EVP_EncryptFinal_ex(ctx, out_buf, &len);
    fwrite(out_buf, 1, len, wfp);
    if (ferror(wfp))
    {
        printf("%s cannot be write.\n", encrypted_filename.c_str());
        ciphertext_len = 0;
        remove(encrypted_filename.c_str());
        goto CLEAN;
    }
    ciphertext_len += len;

CLEAN:
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(key_pair);
    OPENSSL_free(in_buf);
    OPENSSL_free(out_buf);
    OPENSSL_free(secret);
    ERR_free_strings();
    if (rfp != nullptr)
        fclose(rfp);
    if (wfp != nullptr)
        fclose(wfp);
    return ciphertext_len;
}


