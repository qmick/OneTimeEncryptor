#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include "secure_memory.h"


class KeyGenerator
{
public:
    static EVP_PKEY_free_ptr get_key_pair();
    static SecureBuffer get_secret(const EVP_PKEY_free_ptr &pkey, const EVP_PKEY_free_ptr &peerkey);
};

#endif // KEY_GENERATOR_H
