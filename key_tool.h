#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include "secure_memory.h"
#include <string>
#include <vector>

class KeyTool
{
public:
    static EVP_PKEY_ptr get_key_pair(const std::string &type);
    /**
     * @brief Generate private and public key
     * @return Key pair
     */
    static EVP_PKEY_ptr get_key_pair();

    static EVP_PKEY_ptr get_rsa_key_pair();

    /**
     * @brief Get secret using ECDH
     * @param pkey master private key or session private
     * @param peerkey session public or master public key
     * @return secret
     */
    static SecureBuffer get_secret(const EVP_PKEY_ptr &pkey,
                                   const EVP_PKEY_ptr &peerkey);

    /**
     * @brief Save private to given path, encrypt it using given password
     * @param private_path Complete path, including file name, to save private key
     * @param private_key OpenSSL structure that stored private key
     * @param password Password used to encrypt private key, using aes_256_cbc algorithm
     * @return
     */
    static std::string get_private_key_pem(const EVP_PKEY_ptr &private_key,
                                 SecureBuffer &password);

    /**
     * @brief Save public to given path
     * @param public_path Complete path, including file name, to save public key
     * @param public_key OpenSSL structure that stored public key
     * @return
     */
    static std::string get_pubkey_pem(const EVP_PKEY_ptr &public_key);

    static EVP_PKEY_ptr get_pubkey(const std::string &pem);

    static EVP_PKEY_ptr get_private_key(const std::string &pem, const SecureBuffer &password);

    static std::vector<byte> get_digest(const std::string &content, const std::string &type);
};

#endif // KEY_GENERATOR_H
