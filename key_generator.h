#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include "secure_memory.h"


class KeyGenerator
{
public:
    static EVP_PKEY_free_ptr get_key_pair();
    static SecureBuffer get_secret(const EVP_PKEY_free_ptr pkey, const EVP_PKEY_free_ptr peerkey);
    static bool save_key_pair(FILE *dst_public, FILE *dst_private, const EVP_PKEY_free_ptr key_pair, SecureBuffer &password);
};

#endif // KEY_GENERATOR_H
