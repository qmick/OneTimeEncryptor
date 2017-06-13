#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include "secure_memory.h"
#include <string>

class KeyGenerator
{
public:
    /**
     * @brief Generate private and public key
     * @return Key pair
     */
    static EVP_PKEY_ptr get_key_pair();

    /**
     * @brief Get secret using ECDH
     * @param pkey master private key or session private
     * @param peerkey session public or master public key
     * @return secret
     */
    static SecureBuffer get_secret(const EVP_PKEY_ptr pkey,
                                   const EVP_PKEY_ptr peerkey);

    /**
     * @brief Save private to given path, encrypt it using given password
     * @param private_path Complete path, including file name, to save private key
     * @param private_key OpenSSL structure that stored private key
     * @param password Password used to encrypt private key, using aes_256_cbc algorithm
     * @return
     */
    static bool save_private_key(const std::string &private_path, const EVP_PKEY_ptr private_key,
                                 SecureBuffer &password);

    /**
     * @brief Save public to given path
     * @param public_path Complete path, including file name, to save public key
     * @param public_key OpenSSL structure that stored public key
     * @return
     */
    static bool save_public_key(const std::string &public_path, const EVP_PKEY_ptr public_key);
};

#endif // KEY_GENERATOR_H
