#ifndef MSG_RYPTOR_H
#define MSG_RYPTOR_H

#include "secure_memory.h"
#include <vector>

class MsgCryptor
{
public:
    MsgCryptor();

    void set_pubkey(const EVP_PKEY_ptr key);
    const EVP_PKEY_ptr get_pubkey() const;
    void set_private_key(const EVP_PKEY_ptr key);
    const EVP_PEKY_ptr get_private_key() const;
    std::vector<byte> encrypt(const std::vector<byte> &in, const std::string &cipher_name);
    std::vector<byte> decrypt(const std::vector<byte> &in, const std::string &cipher_name);

public:
    EVP_PKEY_ptr pubkey;
    EVP_PKEY_ptr private_key;
    int key_type;
};

#endif // MSG_RYPTOR_H
