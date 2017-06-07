#include "decryptor.h"
#include <openssl/evp.h>
Decryptor::Decryptor()
{

}


size_t Decryptor::decrypt_file(const QString &filename)
{
    const size_t kMaxInBufferSize = 1024 * 1024;
    const size_t kMaxOutBufferSize = kMaxInBufferSize + 1024;
    std::string decrypted_filename = filename.substr(0, filename.length() - crypt_sign.length());
    std::string pri_key_filename = "D:/ecckey/ec_master_pri.pem";
    EVP_PKEY *pri_key = nullptr, *pub_key = nullptr;
    size_t secret_len;
    byte *secret;
    EVP_CIPHER_CTX *ctx;
    byte key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    byte *in_buf, *out_buf;
    int len;
    FILE *pri_file, *cipher_file, *decrypted_file;
    size_t plaintext_len = 0;

    pri_file = fopen(pri_key_filename.c_str(), "r");
    if (!pri_file)
    {
        printf("Cannot open %s\n", pri_key_filename.c_str());
        return 0;
    }
    cipher_file = fopen(filename.c_str(), "r");
    if (!cipher_file)
    {
        printf("Cannot open %s\n", filename.c_str());
        return 0;
    }
    if (0 != remove(decrypted_filename.c_str()))
    {
        printf("Remove %s failed.\n", decrypted_filename.c_str());
    }
    decrypted_file = fopen(decrypted_filename.c_str(), "ab");
    if (!decrypted_file)
    {
        printf("Cannot open %s\n", decrypted_filename.c_str());
        return 0;
    }

    PEM_read_PrivateKey(pri_file, &pri_key, NULL, NULL);
    PEM_read_PUBKEY(cipher_file, &pub_key, NULL, NULL);
    secret = get_secret(pri_key, pub_key, &secret_len);
    for (int i = 0; i < secret_len; i++)
        printf("0x%x ", secret[i]);
    printf("\n\n");

    if (0 == EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), NULL, secret, secret_len, 1, key, iv))
        handleErrors();

    ctx = EVP_CIPHER_CTX_new();
    in_buf = (byte *)OPENSSL_malloc(kMaxInBufferSize);
    out_buf = (byte *)OPENSSL_malloc(kMaxOutBufferSize);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    while (!feof(cipher_file))
    {
        int in_len = fread(in_buf, 1, kMaxInBufferSize, cipher_file);
        if (1 != EVP_DecryptUpdate(ctx, out_buf, &len, in_buf, in_len))
            handleErrors();
        fwrite(out_buf, 1, len, decrypted_file);
    }

    if (1 != EVP_DecryptFinal_ex(ctx, out_buf, &len))
        handleErrors();
    fwrite(out_buf, 1, len, decrypted_file);

    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(pri_key);
    EVP_PKEY_free(pub_key);
    OPENSSL_free(in_buf);
    OPENSSL_free(out_buf);
    OPENSSL_free(secret);
    if (pri_file)
        fclose(pri_file);
    if (cipher_file)
        fclose(cipher_file);
    if (decrypted_file)
        fclose(decrypted_file);
    return 0;

}
