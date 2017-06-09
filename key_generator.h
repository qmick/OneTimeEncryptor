#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include "secure_memory.h"


class KeyGenerator
{
public:
    /**
     * @brief Generate private and public key
     * @return Key pair
     */
    static EVP_PKEY_free_ptr get_key_pair();

    /**
     * @brief Get secret using ECDH
     * @param pkey master private key or session private
     * @param peerkey session public or master public key
     * @return secret
     */
    static SecureBuffer get_secret(const EVP_PKEY_free_ptr pkey,
                                   const EVP_PKEY_free_ptr peerkey);

    /**
     * @brief Save given key pair to PEM files, private key are encrypted using given password
     * @param dst_public File pointer to public key PEM file
     * @param dst_private File pointer to private key PEM file
     * @param key_pair Key pair given
     * @param password Password used to encrypt private key PEM file
     * @return true if save success, otherwise throw exception
     */
    static bool save_key_pair(FILE *dst_public, FILE *dst_private,
                              const EVP_PKEY_free_ptr key_pair, SecureBuffer &password);
};

#endif // KEY_GENERATOR_H
