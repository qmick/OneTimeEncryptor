#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include "secure_memory.h"

class EVP_PKEY;

class key_generator
{
public:
    key_generator();
    static shared_ptr<EVP_PKEY> get_key_pair();
    static shared_ptr<byte> get_secret(shared_ptr<EVP_PKEY> pkey, shared_ptr<EVP_PKEY> peerkey, shared_ptr<size_t> secret_len);
};

#endif // KEY_GENERATOR_H
